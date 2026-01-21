package github

import "time"

type GitHubRepo struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	FullName    string `json:"full_name"`
	Description string `json:"description"`
	HTMLURL     string `json:"html_url"`
	Private     bool   `json:"private"`
}

type GitHubRelease struct {
	Name        string    `json:"name"`
	TagName     string    `json:"tag_name"`
	PublishedAt time.Time `json:"published_at"`
	Body        string    `json:"body"`
}

type GitHubWorkflowRun struct {
	ID         int       `json:"id"`
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	Conclusion string    `json:"conclusion"`
	UpdatedAt  time.Time `json:"updated_at"`
	HeadBranch string    `json:"head_branch"`
	HeadSha    string    `json:"head_sha"`
}

type OnboardRequest struct {
	Repos []string `json:"repos"` // List of full_names (e.g. "owner/repo")
}
