// Package admin defines the REST API types for admin operations.
package admin

// BackfillRequest represents the request body for MTTR backfill
type BackfillRequest struct {
	DaysBack int `json:"days_back"`
}

// BackfillStatusResponse represents the current backfill status
type BackfillStatusResponse struct {
	Running bool   `json:"running"`
	Status  string `json:"status"`
}
