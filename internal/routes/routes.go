package routes

import (
	"log"
	"smart_electricity_tracker_backend/internal/config"
	"smart_electricity_tracker_backend/internal/handlers"
	"smart_electricity_tracker_backend/internal/middleware"
	"smart_electricity_tracker_backend/internal/repositories"
	"smart_electricity_tracker_backend/internal/services"

	"github.com/gofiber/fiber/v2"
	socketio "github.com/googollee/go-socket.io"
	"gorm.io/gorm"
)

func Setup(app *fiber.App, cfg *config.Config, db *gorm.DB) {
	server := socketio.NewServer(nil)
	authMiddleware := middleware.NewAuthMiddleware(cfg)
	// powerMeterService, err := services.NewPowerMeterService(cfg, server,usageRepo)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// go powerMeterService.ReadAndStorePowerData()

	// dependencies
	userRepo := repositories.NewUserRepository(db)
	refreshTokenRepo := repositories.NewRefreshTokenRepository(db)

	userService := services.NewUserService(userRepo, refreshTokenRepo, cfg.JWTSecret, cfg.JWTExpiration, cfg.RefreshTokenExpiration)

	userHandler := handlers.NewUserHandler(userService)

	server.OnConnect("/", func(s socketio.Conn) error {
		s.SetContext("")
		log.Println("connected:", s.ID())
		return nil
	})

	server.OnError("/", func(s socketio.Conn, e error) {
		log.Println("meet error:", e)
	})

	server.OnDisconnect("/", func(s socketio.Conn, reason string) {
		log.Println("closed", reason)
	})
	go server.Serve()
	defer server.Close()

	api := app.Group("/api")
	// Authentication
	api.Post("/login", userHandler.Login)
	api.Post("/logout", userHandler.Logout)
	api.Post("/refresh-Token", userHandler.RefreshToken)
	api.Get("/check-token", authMiddleware.Authenticate())
	// api.Post("/register", userHandler.Register)

	// // Electricity Bill
	// data := api.Group("/data", authMiddleware.Authenticate(), authMiddleware.Permission([]models.Role{models.USER, models.ADMIN}))
	// data.Get("/power-meter", userHandler.GetPowerMeter)
	// data.Get("/electricity-bill", userHandler.GetElectricityBill)

	// // Admin
	// admin := api.Group("/admin", authMiddleware.Authenticate(), authMiddleware.Permission([]models.Role{models.ADMIN}))
	// admin.Get("/users", userHandler.GetUsers)
	// admin.Get("/users/:id", userHandler.GetUser)
	// admin.Post("/users", userHandler.Register)
	// admin.Put("/users/:id", userHandler.UpdateUser)
	// admin.Delete("/users/:id", userHandler.DeleteUser)

	// admin.Get("/user_device", userHandler.GetUserDevices)
	// admin.Get("/user_device/:id", userHandler.GetUserDevice)
	// admin.Post("/user_device", userHandler.CreateUserDevice)
	// admin.Put("/user_device/:id", userHandler.UpdateUserDevice)
	// admin.Delete("/user_device/:id", userHandler.DeleteUserDevice)

	// admin.Get("/electricity-cost", userHandler.GetElectricityCost)
	// admin.Get("/electricity-cost/:id", userHandler.GetElectricityCost)
	// admin.Put("/electricity-cost/:id", userHandler.UpdateElectricityCost)
}
