package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/ortelius/pdvd-backend/v12/database"
)

// GitHubLogin initiates the GitHub App Installation flow
func GitHubLogin(c *fiber.Ctx) error {
	appName := os.Getenv("GITHUB_APP_NAME")
	if appName == "" {
		return c.Status(fiber.StatusInternalServerError).SendString("GITHUB_APP_NAME not configured")
	}

	installURL := fmt.Sprintf("https://github.com/apps/%s/installations/new", appName)
	return c.Redirect(installURL)
}

// GitHubCallback handles the callback from GitHub
func GitHubCallback(db database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		code := c.Query("code")
		installationID := c.Query("installation_id") // Captured from App Install flow

		if code == "" {
			return c.Status(fiber.StatusBadRequest).SendString("Missing code. Ensure the App requests OAuth during installation.")
		}

		clientID := os.Getenv("GITHUB_CLIENT_ID")
		clientSecret := os.Getenv("GITHUB_CLIENT_SECRET")

		reqBody, _ := json.Marshal(map[string]string{
			"client_id":     clientID,
			"client_secret": clientSecret,
			"code":          code,
		})

		req, _ := http.NewRequest("POST", "https://github.com/login/oauth/access_token", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to exchange token")
		}
		defer resp.Body.Close()

		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to parse token response")
		}

		accessToken, ok := result["access_token"].(string)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).SendString("Failed to get access token")
		}

		// Get Current User
		token := c.Cookies("auth_token")
		claims, err := ValidateJWT(token)
		if err != nil {
			return c.Redirect("/?error=session_expired")
		}

		username := claims.Username
		ctx := c.Context()
		user, err := getUserByUsername(ctx, db, username)
		if err != nil {
			return c.Redirect("/?error=user_not_found")
		}

		// Store Token and Installation ID
		user.GitHubToken = accessToken
		if installationID != "" {
			user.GitHubInstallationID = installationID
		}
		user.UpdatedAt = time.Now()

		if err := updateUser(ctx, db, user); err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to save GitHub token")
		}

		return c.Redirect("/profile?github_connected=true")
	}
}
