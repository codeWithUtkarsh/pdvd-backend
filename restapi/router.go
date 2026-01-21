// Package restapi provides the main router and initialization for REST API endpoints.
package restapi

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors" // Import CORS middleware
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/auth"
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/github" // Import GitHub module
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/releases"
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/sync"
)

// SetupRoutes configures all REST API routes
func SetupRoutes(app *fiber.App, db database.DBConnection) {
	// ========================================================================
	// MIDDLEWARE
	// ========================================================================
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000,http://localhost:4000,http://127.0.0.1:3000,http://127.0.0.1:4000",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization, X-Requested-With",
		AllowCredentials: true,
		AllowMethods:     "GET, POST, HEAD, PUT, DELETE, PATCH, OPTIONS",
	}))

	go func() {
		if err := auth.BootstrapAdmin(db); err != nil {
			log.Printf("WARNING: Failed to bootstrap admin: %v", err)
		}
	}()

	go func() {
		if err := auth.EnsureDefaultRoles(db); err != nil {
			log.Printf("WARNING: Failed to ensure default roles: %v", err)
		}
	}()

	emailConfig := auth.LoadEmailConfig()
	go autoApplyRBACOnStartup(db, emailConfig)
	go startInvitationCleanup(db)

	api := app.Group("/api/v1")

	// Public Routes
	api.Post("/signup", auth.Signup(db, emailConfig))

	// Auth Routes
	authGroup := api.Group("/auth")
	authGroup.Post("/login", auth.Login(db))
	authGroup.Post("/logout", auth.Logout())
	authGroup.Get("/me", auth.OptionalAuth(db), auth.Me(db))
	authGroup.Post("/forgot-password", auth.ForgotPassword(db))
	authGroup.Post("/change-password", auth.RequireAuth(db), auth.ChangePassword(db))
	authGroup.Post("/refresh", auth.RefreshToken(db))

	// GitHub Auth Routes
	authGroup.Get("/github/login", auth.GitHubLogin)
	authGroup.Get("/github/callback", auth.GitHubCallback(db))

	// GitHub Integration Routes
	githubGroup := api.Group("/github", auth.RequireAuth(db))
	githubGroup.Get("/repos", github.ListRepos(db))
	githubGroup.Post("/onboard", github.OnboardRepos(db))

	// Invitation Routes
	invitationGroup := api.Group("/invitation")
	invitationGroup.Get("/:token", auth.GetInvitationHandler(db))
	invitationGroup.Post("/:token/accept", auth.AcceptInvitationHandler(db))
	invitationGroup.Post("/:token/resend", auth.ResendInvitationHandler(db, emailConfig))

	// User Management (Admin)
	userGroup := api.Group("/users", auth.RequireAuth(db), auth.RequireRole("admin"))
	userGroup.Get("/", auth.ListUsers(db))
	userGroup.Post("/", auth.CreateUser(db))
	userGroup.Get("/:username", auth.GetUser(db))
	userGroup.Put("/:username", auth.UpdateUser(db))
	userGroup.Delete("/:username", auth.DeleteUser(db))

	// RBAC Management (Admin)
	rbac := api.Group("/rbac", auth.RequireAuth(db), auth.RequireRole("admin"))
	rbac.Post("/apply/content", auth.ApplyRBACFromBody(db, emailConfig))
	rbac.Post("/apply/upload", auth.ApplyRBACFromUpload(db, emailConfig))
	rbac.Post("/apply", auth.ApplyRBACFromFile(db, emailConfig))
	rbac.Post("/validate", auth.HandleRBACValidate(db))
	rbac.Get("/config", auth.GetRBACConfig(db))
	rbac.Get("/invitations", auth.ListPendingInvitationsHandler(db))

	// Release & Sync
	api.Post("/releases", auth.OptionalAuth(db), releases.PostReleaseWithSBOM(db))
	api.Post("/sync", auth.OptionalAuth(db), sync.PostSyncWithEndpoint(db))

	log.Println("API routes initialized successfully")
}

func startInvitationCleanup(db database.DBConnection) {
	runCleanup(db)
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		runCleanup(db)
	}
}

func runCleanup(db database.DBConnection) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	count, err := auth.CleanupExpiredInvitations(ctx, db)
	if err != nil {
		fmt.Printf("⚠️  Background Task: Failed to cleanup expired invitations: %v\n", err)
		return
	}
	if count > 0 {
		fmt.Printf("🧹 Background Task: Cleaned up %d expired invitations\n", count)
	}
}

func autoApplyRBACOnStartup(db database.DBConnection, emailConfig *auth.EmailConfig) {
	configPath := os.Getenv("RBAC_CONFIG_PATH")
	if configPath == "" {
		configPath = "/etc/pdvd/rbac.yaml"
	}
	if _, err := os.Stat(configPath); err == nil {
		fmt.Println("🔄 Auto-applying RBAC configuration from:", configPath)
		config, err := auth.LoadPeriobolosConfig(configPath)
		if err != nil {
			fmt.Printf("⚠️  Failed to load RBAC config: %v\n", err)
			return
		}
		result, err := auth.ApplyRBAC(db, config, emailConfig)
		if err != nil {
			fmt.Printf("⚠️  RBAC apply failed: %v\n", err)
			return
		}
		fmt.Printf("✅ RBAC apply complete: %d created, %d updated, %d removed, %d invited\n",
			len(result.Created), len(result.Updated), len(result.Removed), len(result.Invited))
	}
}
