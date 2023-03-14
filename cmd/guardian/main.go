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
