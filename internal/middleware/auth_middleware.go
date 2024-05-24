package middleware

import (
	"fmt"
	"smart_electricity_tracker_backend/internal/config"
	"smart_electricity_tracker_backend/internal/helpers"
	"smart_electricity_tracker_backend/internal/models"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
)

type AuthMiddlewareService struct {
	cfg *config.Config
}

func NewAuthMiddleware(cfg *config.Config) *AuthMiddlewareService {
	return &AuthMiddlewareService{cfg: cfg}
}

func (s *AuthMiddlewareService) Authenticate() fiber.Handler {
	return func(c *fiber.Ctx) error {
		tokenString := c.Get("Authorization")
		if tokenString == "" {
			return helpers.ErrorResponse(c, fiber.StatusUnauthorized, "Unauthorized")
		}

		token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(s.cfg.JWTSecret), nil
		})
		if err != nil {
			return helpers.ErrorResponse(c, fiber.StatusUnauthorized, "Unauthorized")
		}

		claims, ok := token.Claims.(*jwt.StandardClaims)
		if !ok || !token.Valid {
			return helpers.ErrorResponse(c, fiber.StatusUnauthorized, "Unauthorized")
		}

		if claims.ExpiresAt < time.Now().Unix() {
			return helpers.ErrorResponse(c, fiber.StatusUnauthorized, "Token expired")
		}

		c.Locals("user_id", claims.Subject)
		c.Locals("role", claims.Issuer)

		return c.Next()
	}
}

func (s *AuthMiddlewareService) Permission(roleApprover []models.Role) fiber.Handler {
	return func(c *fiber.Ctx) error {
		role := c.Locals("role").(string)

		for _, roleApp := range roleApprover {
			if role == fmt.Sprint(roleApp) {
				return c.Next()
			}
		}

		return helpers.ErrorResponse(c, fiber.StatusForbidden, "Forbidden")
	}
}
