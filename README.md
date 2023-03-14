# Guardian

[dev.to-article]("https://dev.to/elioenaiferrari/rotation-keys-in-golang-506c")

The idea here is to rotate the ed25519 keys for the signatures of our tokens. In this way we achieve greater security and unpredictability with asymmetric encryption.

First, let's assemble our containers.

```docker
// Dockerfile
FROM golang:1.20-alpine

WORKDIR /app
COPY go.* .
RUN go mod tidy
COPY . .
RUN go build -buildvcs=false -ldflags '-s -w' -o ./bin ./cmd/guardian

EXPOSE 4000

CMD [ "./bin/guardian" ]
```

```yaml
// docker-compose.yml
version: '3'

networks:
  guardian:
    driver: bridge

services:
  cache:
    image: redis:7.0-alpine
    hostname: cache.guardian.local
    restart: always
    ports:
      - '6379:6379'
    networks:
      - guardian
  app:
    platform: linux/amd64
    build: .
    hostname: app.guardian.local
    depends_on:
      - cache
    networks:
      - guardian
    ports:
      - 4000:4000
```

The key server module will be responsible for setting the last key id, generating the tokens with the last generated key, and rotating the keys in the given interval.
The `kid` is the identifier of the key in question. Every time we generate a token we will use the last key stored in redis. Our `ks.Start()` worker in the main file will rotate keys every `5 minutes`.

```go
// internal/key-server/key-server.go
package keyserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"time"

	"github.com/golang-jwt/jwt"
	gonanoid "github.com/matoous/go-nanoid/v2"
	"github.com/redis/go-redis/v9"
)

type KeyServer struct {
	cache *redis.Client
}

func New(cache *redis.Client) *KeyServer {
	return &KeyServer{
		cache: cache,
	}
}

func (ks *KeyServer) NewSignedToken(ctx context.Context, data map[string]interface{}) (string, jwt.Claims, error) {
	lastKID, err := ks.GetLastKID(ctx)
	if err != nil {
		return "", nil, err
	}

	lastKey, err := ks.GetKeyByKID(ctx, lastKID)
	if err != nil {
		return "", nil, err
	}

	claims := jwt.MapClaims{
		"exp": time.Now().Add(15 * time.Minute).Unix(),
		"iss": "guardian",
		"kid": lastKID,
		"dat": data,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signedToken, err := token.SignedString(lastKey)

	return signedToken, claims, err
}

func (ks *KeyServer) DecodeSignedToken(ctx context.Context, signedToken string) (*jwt.Token, jwt.Claims, error) {
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(signedToken, &claims, func(t *jwt.Token) (interface{}, error) {
		claims, ok := t.Claims.(*jwt.MapClaims)
		if !ok {
			return nil, errors.New("invalid token")
		}

		key, err := ks.GetKeyByKID(ctx, (*claims)["kid"].(string))
		if err != nil {
			return nil, err
		}

		return key.Public(), nil
	})

	if err != nil {
		return nil, nil, err
	}

	return token, claims, nil
}

func (ks *KeyServer) SetLastKID(ctx context.Context, kid string) error {
	return ks.cache.Set(ctx, "last-kid", kid, time.Minute*15).Err()
}

func (ks *KeyServer) SetLastKey(ctx context.Context, kid string, pvk ed25519.PrivateKey) error {
	b, err := x509.MarshalPKCS8PrivateKey(pvk)
	if err != nil {
		return err
	}

	if err := ks.cache.Set(ctx, kid, b, time.Minute*15).Err(); err != nil {
		return err
	}

	return nil
}

func (ks *KeyServer) GetKeyByKID(ctx context.Context, kid string) (ed25519.PrivateKey, error) {
	key, err := ks.cache.Get(ctx, kid).Result()
	if err != nil {
		return nil, err
	}

	pvk, err := x509.ParsePKCS8PrivateKey([]byte(key))
	if err != nil {
		return nil, err
	}

	return pvk.(ed25519.PrivateKey), nil
}

func (ks *KeyServer) GetLastKID(ctx context.Context) (string, error) {
	lastKID, err := ks.cache.Get(ctx, "last-kid").Result()
	if err != nil {
		return "", err
	}

	return lastKID, nil
}

func (ks *KeyServer) Rotate(ctx context.Context) error {
	kid, err := gonanoid.New(8)
	if err != nil {
		return err
	}

	_, pvk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	if err := ks.SetLastKID(ctx, kid); err != nil {
		return err
	}

	if err := ks.SetLastKey(ctx, kid, pvk); err != nil {
		return err
	}

	return nil
}

func (ks *KeyServer) Start(ctx context.Context) error {
	ks.Rotate(ctx)

	for range time.Tick(time.Minute * 5) {
		ks.Rotate(ctx)
	}

	return nil
}
```

The `POST /api/v1/tokens` route will generate a token with the `claims defined in the body` sent (JSON). And the `GET /api/v1/tokens` route will only act as a validator for us to test our tokens.
The token is encrypted with a `private ed2559 key` and decrypted with the `public key of that same key`.

```go
// cmd/guardian/main.go
package main

import (
	"context"
	"log"
	"net/http"

	keyserver "github.com/ElioenaiFerrari/guardian/internal/key-server"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/redis/go-redis/v9"
)

func main() {
	cache := redis.NewClient(&redis.Options{
		Addr:     "cache.guardian.local:6379",
		DB:       0,
		Password: "",
	})
	ks := keyserver.New(cache)
	ctx := context.Background()

	go ks.Start(ctx)

	app := fiber.New()
	app.Use(logger.New())
	app.Use(recover.New())
	app.Use(cors.New())

	v1 := app.Group("/api/v1")
	v1.Post("/tokens", func(c *fiber.Ctx) error {
		var data map[string]interface{}

		if err := c.BodyParser(&data); err != nil {
			return fiber.NewError(http.StatusBadRequest, err.Error())
		}

		token, claims, err := ks.NewSignedToken(ctx, data)
		if err != nil {
			return fiber.NewError(http.StatusInternalServerError, err.Error())
		}

		return c.Status(http.StatusCreated).JSON(fiber.Map{
			"token":  token,
			"claims": claims,
		})
	})

	v1.Get("/tokens", func(c *fiber.Ctx) error {
		signedToken := c.Get("Authorization")
		if signedToken == "" {
			return fiber.NewError(http.StatusUnauthorized, "unauthorized")
		}

		token, claims, err := ks.DecodeSignedToken(ctx, signedToken)
		if err != nil {
			return fiber.NewError(http.StatusUnauthorized, err.Error())
		}

		return c.Status(http.StatusCreated).JSON(fiber.Map{
			"token":  token,
			"claims": claims,
		})
	})

	log.Fatal(app.Listen(":4000"))
}
```

Let's start our server.

```bash
docker-compose up --build
```

## Examples:

- POST request

```sh
curl --location 'http://localhost:4000/api/v1/tokens' \
--header 'Content-Type: application/json' \
--data '{
    "sub": "123123123"
}'
```

- POST response

```json
{
  "claims": {
    "dat": {
      "sub": "123123123"
    },
    "exp": 1678807427,
    "iss": "guardian",
    "kid": "rwqgN9dI"
  },
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJkYXQiOnsic3ViIjoiMTIzMTIzMTIzIn0sImV4cCI6MTY3ODgwNzQyNywiaXNzIjoiZ3VhcmRpYW4iLCJraWQiOiJyd3FnTjlkSSJ9.8yUZ-0XSZk5UMITSUZLX2SXIs5MIIXCID4X4IBxWy_N9WHXCBk0v6o0urB5r7Sr8vz7T_Z_2JVsNU4j681PMAw"
}
```

- GET request

```sh
curl --location 'http://localhost:4000/api/v1/tokens' \
--header 'Authorization: eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJkYXQiOnsic3ViIjoiMTIzMTIzMTIzIn0sImV4cCI6MTY3ODgwNzQyNywiaXNzIjoiZ3VhcmRpYW4iLCJraWQiOiJyd3FnTjlkSSJ9.8yUZ-0XSZk5UMITSUZLX2SXIs5MIIXCID4X4IBxWy_N9WHXCBk0v6o0urB5r7Sr8vz7T_Z_2JVsNU4j681PMAw'
```

- GET response

```json
{
  "claims": {
    "dat": {
      "sub": "123123123"
    },
    "exp": 1678807427,
    "iss": "guardian",
    "kid": "rwqgN9dI"
  },
  "token": {
    "Raw": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJkYXQiOnsic3ViIjoiMTIzMTIzMTIzIn0sImV4cCI6MTY3ODgwNzQyNywiaXNzIjoiZ3VhcmRpYW4iLCJraWQiOiJyd3FnTjlkSSJ9.8yUZ-0XSZk5UMITSUZLX2SXIs5MIIXCID4X4IBxWy_N9WHXCBk0v6o0urB5r7Sr8vz7T_Z_2JVsNU4j681PMAw",
    "Method": {},
    "Header": {
      "alg": "EdDSA",
      "typ": "JWT"
    },
    "Claims": {
      "dat": {
        "sub": "123123123"
      },
      "exp": 1678807427,
      "iss": "guardian",
      "kid": "rwqgN9dI"
    },
    "Signature": "8yUZ-0XSZk5UMITSUZLX2SXIs5MIIXCID4X4IBxWy_N9WHXCBk0v6o0urB5r7Sr8vz7T_Z_2JVsNU4j681PMAw",
    "Valid": true
  }
}
```
