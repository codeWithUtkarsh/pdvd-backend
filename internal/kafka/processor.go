package kafka

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	"github.com/ortelius/pdvd-backend/v12/database"
	release "github.com/ortelius/pdvd-backend/v12/events/modules/releases"
	"github.com/ortelius/pdvd-backend/v12/internal/services"
	"github.com/segmentio/kafka-go"
)

// RunEventProcessor starts the Kafka consumer for release events.
// Kafka messages contain the SBOM CID (and optional metadata)
func RunEventProcessor(ctx context.Context, db database.DBConnection) {
	// Parse Kafka brokers from environment variable
	brokersEnv := os.Getenv("KAFKA_BROKERS")
	var brokers []string
	if brokersEnv != "" {
		brokers = strings.Split(brokersEnv, ",")
	} else {
		brokers = []string{"localhost:9092"}
	}

	// Create Kafka reader
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  brokers,
		GroupID:  "pdvd-backend-worker",
		Topic:    "release-events",
		MaxBytes: 10e6, // 10MB per message
	})
	defer func() {
		if err := reader.Close(); err != nil {
			log.Printf("Error closing Kafka reader: %v", err)
		}
	}()

	// Initialize ReleaseService
	service := &services.ReleaseServiceWrapper{DB: db}

	// Initialize SBOM fetcher
	fetcher := &services.CIDFetcher{} // implements release.SBOMFetcher

	log.Println("Kafka Event Processor started. Listening for release events...")

	for {
		select {
		case <-ctx.Done():
			log.Println("Kafka Event Processor shutting down...")
			return
		default:
			// Read message
			msg, err := reader.ReadMessage(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("Kafka read error: %v. Retrying in 1s...", err)
				time.Sleep(time.Second)
				continue
			}

			// Pass the raw message to the release handler along with fetcher and service
			if err := release.HandleReleaseSBOMCreatedWithService(ctx, msg.Value, fetcher, service); err != nil {
				log.Printf("Handler error for message key=%s: %v", string(msg.Key), err)
			} else {
				log.Printf("Successfully processed message key=%s offset=%d", string(msg.Key), msg.Offset)
			}
		}
	}
}
