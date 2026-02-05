package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/internal/api"
	"github.com/ortelius/pdvd-backend/v12/internal/kafka"
)

func main() {
	// Initialize database connection
	db := database.InitializeDatabase()

	// Handle graceful shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Start Kafka processor
	go kafka.RunEventProcessor(ctx, db)

	// Start Fiber server with API routes
	app := api.NewFiberApp(db)
	port := os.Getenv("MS_PORT")
	if port == "" {
		port = "3000"
	}

	go func() {
		log.Printf("Starting server on port %s", port)
		if err := app.Listen(":" + port); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for termination signal
	<-ctx.Done()
	log.Println("Shutting down pdvd-backend...")
	app.Shutdown()
}
