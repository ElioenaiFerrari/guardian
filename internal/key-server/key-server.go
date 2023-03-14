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
