package gitops

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"gopkg.in/yaml.v2"
)

// Local structs to match RBAC YAML structure
type Config struct {
	Orgs  []Org  `yaml:"orgs,omitempty"`
	Users []User `yaml:"users"`
	Roles []Role `yaml:"roles,omitempty"`
}

type Org struct {
	Name        string            `yaml:"name"`
	DisplayName string            `yaml:"display_name,omitempty"`
	Description string            `yaml:"description,omitempty"`
	Metadata    map[string]string `yaml:"metadata,omitempty"`
}

type User struct {
	Username     string   `yaml:"username"`
	Email        string   `yaml:"email"`
	Role         string   `yaml:"role"`
	Orgs         []string `yaml:"orgs,omitempty"`
	AuthProvider string   `yaml:"auth_provider,omitempty"`
}

type Role struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description,omitempty"`
	Permissions []string `yaml:"permissions,omitempty"`
}

// UpdateRBACRepo clones the remote repo, adds the new user/org, and pushes changes.
// It returns the updated YAML content string to be applied locally.
func UpdateRBACRepo(username, email, firstName, lastName, orgName string) (string, error) {
	repoURL := os.Getenv("RBAC_REPO")
	token := os.Getenv("RBAC_REPO_TOKEN")

	if repoURL == "" || token == "" {
		return "", fmt.Errorf("RBAC_REPO and RBAC_REPO_TOKEN environment variables must be set")
	}

	// Basic Auth using the token
	authMethod := &http.BasicAuth{
		Username: "oauth2",
		Password: token,
	}

	maxRetries := 3
	var updatedYaml string
	var err error

	for i := 0; i < maxRetries; i++ {
		updatedYaml, err = tryUpdateRepo(repoURL, authMethod, username, email, firstName, lastName, orgName)
		if err == nil {
			return updatedYaml, nil
		}
		time.Sleep(time.Duration(500*(i+1)) * time.Millisecond)
	}

	return "", fmt.Errorf("failed to update RBAC repo after %d attempts: %w", maxRetries, err)
}

func tryUpdateRepo(repoURL string, authMethod *http.BasicAuth, username, email, firstName, lastName, orgName string) (string, error) {
	// 1. Clone to a temporary directory
	tempDir, err := os.MkdirTemp("", "pdvd-rbac-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	repo, err := git.PlainClone(tempDir, false, &git.CloneOptions{
		URL:      repoURL,
		Auth:     authMethod,
		Progress: nil,
		Depth:    1,
	})
	if err != nil {
		return "", fmt.Errorf("failed to clone repo: %w", err)
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("failed to get worktree: %w", err)
	}

	// 2. Read and Parse rbac.yaml
	rbacPath := filepath.Join(tempDir, "rbac.yaml")
	yamlBytes, err := os.ReadFile(rbacPath)
	if err != nil {
		if os.IsNotExist(err) {
			yamlBytes = []byte("users: []\norgs: []\nroles: []")
		} else {
			return "", fmt.Errorf("failed to read rbac.yaml: %w", err)
		}
	}

	var config Config
	if err := yaml.Unmarshal(yamlBytes, &config); err != nil {
		return "", fmt.Errorf("failed to parse rbac.yaml: %w", err)
	}

	// 3. Update the Configuration in Memory
	configUpdated := false

	// Ensure Org exists
	orgExists := false
	for _, org := range config.Orgs {
		if org.Name == orgName {
			orgExists = true
			break
		}
	}
	if !orgExists {
		config.Orgs = append(config.Orgs, Org{
			Name:        orgName,
			DisplayName: orgName,
			Description: fmt.Sprintf("Created for %s %s", firstName, lastName),
		})
		configUpdated = true
	}

	// Ensure User exists
	userExists := false
	for _, user := range config.Users {
		if user.Username == username {
			userExists = true
			break
		}
	}
	if !userExists {
		role := "viewer"
		// If the organization was just created (it didn't exist before), make the creator an Owner
		if !orgExists {
			role = "owner"
		}

		config.Users = append(config.Users, User{
			Username:     username,
			Email:        email,
			Role:         role,
			Orgs:         []string{orgName},
			AuthProvider: "local",
		})
		configUpdated = true
	}

	newYamlBytes, err := yaml.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config: %w", err)
	}

	if !configUpdated {
		return string(newYamlBytes), nil
	}

	// 4. Write back to file system
	if err := os.WriteFile(rbacPath, newYamlBytes, 0644); err != nil {
		return "", fmt.Errorf("failed to write rbac.yaml: %w", err)
	}

	// 5. Commit
	_, err = worktree.Add("rbac.yaml")
	if err != nil {
		return "", fmt.Errorf("failed to stage changes: %w", err)
	}

	commitMsg := fmt.Sprintf("feat: onboarding user %s and org %s", username, orgName)
	_, err = worktree.Commit(commitMsg, &git.CommitOptions{
		Author: &object.Signature{
			Name:  "PDVD Backend",
			Email: "noreply@pdvd.com",
			When:  time.Now(),
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to commit changes: %w", err)
	}

	// 6. Push
	err = repo.Push(&git.PushOptions{
		Auth: authMethod,
	})
	if err != nil {
		return "", fmt.Errorf("failed to push changes: %w", err)
	}

	return string(newYamlBytes), nil
}
