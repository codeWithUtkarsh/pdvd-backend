// Package restapi provides the main router and initialization for REST API endpoints.
package restapi

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/admin"
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/releases"
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/sync"
)

// SetupRoutes configures all REST API routes
func SetupRoutes(app *fiber.App, db database.DBConnection) {
	// API group
	api := app.Group("/api/v1")

	// Release endpoints
	api.Post("/releases", releases.PostReleaseWithSBOM(db))

	// Sync endpoints
	api.Post("/sync", sync.PostSyncWithEndpoint(db))

	// Admin endpoints
	adminGroup := api.Group("/admin")
	adminGroup.Post("/backfill-mttr", admin.PostBackfillMTTR(db))
	adminGroup.Get("/backfill-status", admin.GetBackfillStatus())
}
