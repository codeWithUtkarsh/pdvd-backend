// Package sync implements the REST API handlers for sync operations.
package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/gofiber/fiber/v2"
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/model"
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/lifecycle"
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/releases"
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/sbom"
	"github.com/ortelius/pdvd-backend/v12/util"
)

// PostSyncWithEndpoint handles POST requests for syncing multiple releases to an endpoint
func PostSyncWithEndpoint(db database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req model.SyncWithEndpoint

		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": "Invalid request body: " + err.Error(),
			})
		}

		if req.EndpointName == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": "endpoint_name is required",
			})
		}

		if len(req.Releases) == 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": "at least one release must be provided",
			})
		}

		ctx := context.Background()

		// Check if endpoint exists
		endpointExists, err := checkEndpointExists(ctx, db, req.EndpointName)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"success": false,
				"message": "Failed to query endpoint: " + err.Error(),
			})
		}

		// Create endpoint if it doesn't exist
		if !endpointExists {
			if err := createEndpoint(ctx, db, req); err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"success": false,
					"message": err.Error(),
				})
			}
		}

		// Get sync timestamp
		syncedAt := time.Now()
		if !req.SyncedAt.IsZero() {
			syncedAt = req.SyncedAt
		}

		// Step 1: Get current state
		currentReleases, err := getCurrentEndpointState(ctx, db, req.EndpointName)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"success": false,
				"message": "Failed to query current endpoint state: " + err.Error(),
			})
		}

		// Step 2: Process releases
		results, updatedReleases, err := processReleases(ctx, db, req, currentReleases)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"success": false,
				"message": err.Error(),
			})
		}

		// Step 3: Create sync records
		syncedCount, err := createSyncRecords(ctx, db, req.EndpointName, updatedReleases, syncedAt, results)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"success": false,
				"message": "Failed to create sync records: " + err.Error(),
			})
		}

		// Step 4: Update CVE lifecycle tracking (NEW LIFECYCLE INTEGRATION)
		// Process each synced release for lifecycle tracking
		for releaseName, releaseVersion := range updatedReleases {
			// Get CVEs for this release
			sbomCVEs, err := getCVEsForRelease(ctx, db, releaseName, releaseVersion)
			if err != nil {
				fmt.Printf("Warning: Failed to get CVEs for %s version %s: %v\n", releaseName, releaseVersion, err)
				continue
			}

			// Process lifecycle tracking for this release
			err = ProcessSync(
				ctx, db,
				req.EndpointName,
				releaseName,
				releaseVersion,
				sbomCVEs,
				syncedAt,
			)
			if err != nil {
				fmt.Printf("Warning: Failed to update CVE lifecycle for %s version %s: %v\n", releaseName, releaseVersion, err)
				// Don't fail the sync, just log the error
			}
		}

		// Build response
		return buildSyncResponse(c, results, syncedCount, endpointExists, req.EndpointName, syncedAt)
	}
}

// getCVEsForRelease retrieves CVEs affecting a specific release
func getCVEsForRelease(ctx context.Context, db database.DBConnection, releaseName, releaseVersion string) ([]lifecycle.CVEInfo, error) {
	query := `
		FOR release IN release
			FILTER release.name == @name AND release.version == @version
			LIMIT 1
			
			FOR cve, edge IN 1..1 OUTBOUND release release2cve
				RETURN {
					cve_id: cve.id,
					package: edge.package_purl,
					severity_rating: cve.database_specific.severity_rating,
					severity_score: cve.database_specific.cvss_base_score,
					published: cve.published
				}
	`

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"name":    releaseName,
			"version": releaseVersion,
		},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	var cves []lifecycle.CVEInfo
	for cursor.HasMore() {
		var raw struct {
			CveID          string  `json:"cve_id"`
			Package        string  `json:"package"`
			SeverityRating string  `json:"severity_rating"`
			SeverityScore  float64 `json:"severity_score"`
			Published      string  `json:"published"`
		}

		if _, err := cursor.ReadDocument(ctx, &raw); err != nil {
			continue
		}

		var publishedTime time.Time
		if raw.Published != "" {
			if t, err := time.Parse(time.RFC3339, raw.Published); err == nil {
				publishedTime = t
			}
		}

		cves = append(cves, lifecycle.CVEInfo{
			CVEID:          raw.CveID,
			Package:        raw.Package,
			SeverityRating: raw.SeverityRating,
			SeverityScore:  raw.SeverityScore,
			Published:      publishedTime,
		})
	}

	return cves, nil
}

// ProcessSync handles sync event and updates lifecycle tracking.
// This processes CVE lifecycle for a single release.
func ProcessSync(
	ctx context.Context,
	db database.DBConnection,
	endpointName string,
	releaseName string,
	releaseVersion string,
	sbomCVEs []lifecycle.CVEInfo,
	syncedAt time.Time,
) error {

	fmt.Printf("Processing lifecycle for: %s/%s version %s\n",
		endpointName, releaseName, releaseVersion)

	// Step 1: Find previous version (if any)
	previousVersion, err := lifecycle.GetPreviousVersion(
		ctx, db,
		releaseName, endpointName,
		syncedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to get previous version: %w", err)
	}

	isFirstDeployment := previousVersion == ""
	if isFirstDeployment {
		fmt.Printf("  First deployment of %s\n", releaseName)
	} else {
		fmt.Printf("  Upgrading from %s to %s\n", previousVersion, releaseVersion)
	}

	// Step 2: Create lifecycle records for all CVEs in this version
	currentCVEMap := make(map[string]lifecycle.CVEInfo)

	for _, cve := range sbomCVEs {
		key := fmt.Sprintf("%s:%s", cve.CVEID, cve.Package)
		currentCVEMap[key] = cve

		// Determine if CVE was disclosed after deployment
		disclosedAfter := !cve.Published.IsZero() && cve.Published.After(syncedAt)

		// CRITICAL: Use shared lifecycle package
		err := lifecycle.CreateOrUpdateLifecycleRecord(
			ctx, db,
			endpointName,
			releaseName,
			releaseVersion,
			cve,
			syncedAt, // ✅ Actual sync time
			disclosedAfter,
		)

		if err != nil {
			return fmt.Errorf("failed to create lifecycle record for %s: %w", cve.CVEID, err)
		}
	}

	fmt.Printf("  Created/updated %d lifecycle records\n", len(sbomCVEs))

	// Step 3: If not first deployment, compare versions and mark remediations
	if !isFirstDeployment {
		remediatedCount, err := lifecycle.CompareAndMarkRemediations(
			ctx, db,
			endpointName, releaseName,
			previousVersion, releaseVersion,
			currentCVEMap,
			syncedAt,
		)

		if err != nil {
			return fmt.Errorf("failed to compare versions: %w", err)
		}

		fmt.Printf("  Marked %d CVEs as remediated\n", remediatedCount)
	}

	return nil
}

// Rest of the original functions remain unchanged...
func checkEndpointExists(ctx context.Context, db database.DBConnection, endpointName string) (bool, error) {
	query := `
		FOR e IN endpoint
			FILTER e.name == @name
			LIMIT 1
			RETURN e
	`
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"name": endpointName,
		},
	})
	if err != nil {
		return false, err
	}
	defer cursor.Close()

	return cursor.HasMore(), nil
}

func createEndpoint(ctx context.Context, db database.DBConnection, req model.SyncWithEndpoint) error {
	if req.Endpoint.Name == "" || req.Endpoint.EndpointType == "" || req.Endpoint.Environment == "" {
		return fmt.Errorf("endpoint not found: %s. Provide endpoint name, endpoint_type, and environment to create it", req.EndpointName)
	}

	if req.Endpoint.Name != req.EndpointName {
		return fmt.Errorf("endpoint name in sync does not match endpoint name in endpoint object")
	}

	if req.Endpoint.ObjType == "" {
		req.Endpoint.ObjType = "Endpoint"
	}

	req.Endpoint.ParseAndSetNameComponents()
	_, err := db.Collections["endpoint"].CreateDocument(ctx, req.Endpoint)
	return err
}

func getCurrentEndpointState(ctx context.Context, db database.DBConnection, endpointName string) (map[string]string, error) {
	query := `
		FOR sync IN sync
			FILTER sync.endpoint_name == @endpoint_name
			COLLECT release_name = sync.release_name INTO syncGroups = sync
			LET latestSync = (
				FOR s IN syncGroups
					SORT s.synced_at DESC
					LIMIT 1
					RETURN s
			)[0]
			RETURN {
				name: latestSync.release_name,
				version: latestSync.release_version
			}
	`
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"endpoint_name": endpointName,
		},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	currentReleases := make(map[string]string)
	for cursor.HasMore() {
		var rel struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if _, err := cursor.ReadDocument(ctx, &rel); err == nil {
			currentReleases[rel.Name] = rel.Version
		}
	}

	return currentReleases, nil
}

func isVersionGreater(newRel, existingRel model.ProjectRelease) bool {
	getVal := func(ptr *int) int {
		if ptr == nil {
			return 0
		}
		return *ptr
	}

	if getVal(newRel.VersionMajor) > getVal(existingRel.VersionMajor) {
		return true
	}
	if getVal(newRel.VersionMajor) < getVal(existingRel.VersionMajor) {
		return false
	}

	if getVal(newRel.VersionMinor) > getVal(existingRel.VersionMinor) {
		return true
	}
	if getVal(newRel.VersionMinor) < getVal(existingRel.VersionMinor) {
		return false
	}

	if getVal(newRel.VersionPatch) > getVal(existingRel.VersionPatch) {
		return true
	}
	if getVal(newRel.VersionPatch) < getVal(existingRel.VersionPatch) {
		return false
	}

	if newRel.VersionPrerelease == "" && existingRel.VersionPrerelease != "" {
		return true
	}
	if newRel.VersionPrerelease != "" && existingRel.VersionPrerelease == "" {
		return false
	}

	if newRel.VersionPrerelease != "" && existingRel.VersionPrerelease != "" {
		return newRel.VersionPrerelease > existingRel.VersionPrerelease
	}

	return false
}

func processReleases(ctx context.Context, db database.DBConnection, req model.SyncWithEndpoint,
	currentReleases map[string]string) ([]ReleaseResult, map[string]string, error) {

	var results []ReleaseResult
	updatedReleases := make(map[string]string)
	latestInBatch := make(map[string]model.ProjectRelease)

	for name, version := range currentReleases {
		updatedReleases[name] = version
	}

	for _, relSync := range req.Releases {
		relSync.Release.Version = util.CleanVersion(relSync.Release.Version)
		relSync.Release.ParseAndSetVersion()

		result := processRelease(ctx, db, relSync, currentReleases)
		results = append(results, result)

		if result.Status != "error" {
			name := relSync.Release.Name

			if existing, exists := latestInBatch[name]; exists {
				if isVersionGreater(relSync.Release, existing) {
					latestInBatch[name] = relSync.Release
				}
			} else {
				latestInBatch[name] = relSync.Release
			}
		}
	}

	for name, release := range latestInBatch {
		updatedReleases[name] = release.Version
	}

	return results, updatedReleases, nil
}

func processRelease(ctx context.Context, db database.DBConnection, relSync model.ReleaseSync,
	currentReleases map[string]string) ReleaseResult {

	release := relSync.Release
	sbomData := relSync.SBOM

	if release.Name == "" || release.Version == "" {
		return ReleaseResult{
			Name:    release.Name,
			Version: release.Version,
			Status:  "error",
			Message: "Release name and version are required",
		}
	}

	cleanedVersion := util.CleanVersion(release.Version)
	release.Version = cleanedVersion
	release.ParseAndSetVersion()
	release.ParseAndSetNameComponents()

	if release.ObjType == "" {
		release.ObjType = "ProjectRelease"
	}

	releases.PopulateContentSha(&release)

	currentVersion, existsInCurrent := currentReleases[release.Name]

	if existsInCurrent && currentVersion == cleanedVersion && sbomData == nil {
		return ReleaseResult{
			Name:    release.Name,
			Version: cleanedVersion,
			Status:  "unchanged",
			Message: "Release already at this version",
		}
	}

	var existingReleaseKey string
	var err error
	if release.ContentSha != "" {
		existingReleaseKey, err = database.FindReleaseByCompositeKey(ctx, db.Database,
			release.Name, release.Version, release.ContentSha)
		if err != nil {
			return ReleaseResult{
				Name:    release.Name,
				Version: cleanedVersion,
				Status:  "error",
				Message: fmt.Sprintf("Failed to check for existing release: %s", err.Error()),
			}
		}
	}

	var releaseID string
	releaseCreated := false

	if existingReleaseKey != "" {
		releaseID = "release/" + existingReleaseKey
		release.Key = existingReleaseKey
	} else {
		releaseMeta, err := db.Collections["release"].CreateDocument(ctx, release)
		if err != nil {
			return ReleaseResult{
				Name:    release.Name,
				Version: cleanedVersion,
				Status:  "error",
				Message: fmt.Sprintf("Failed to create release: %s", err.Error()),
			}
		}
		releaseID = "release/" + releaseMeta.Key
		release.Key = releaseMeta.Key
		releaseCreated = true
	}

	sbomProcessed := false
	if sbomData != nil && len(sbomData.Content) > 0 {
		sbomProcessed = processSBOMForRelease(ctx, db, sbomData, releaseID)
		if !sbomProcessed {
			return ReleaseResult{
				Name:    release.Name,
				Version: cleanedVersion,
				Status:  "error",
				Message: "Failed to process SBOM",
			}
		}
	}

	var statusMsg string
	switch {
	case releaseCreated && sbomProcessed:
		statusMsg = "created_with_sbom"
	case releaseCreated:
		statusMsg = "created"
	case sbomProcessed:
		statusMsg = "updated_with_sbom"
	default:
		statusMsg = "updated"
	}

	return ReleaseResult{
		Name:    release.Name,
		Version: cleanedVersion,
		Status:  statusMsg,
		Message: "Release processed successfully",
	}
}

func processSBOMForRelease(ctx context.Context, db database.DBConnection, sbomData *model.SBOM,
	releaseID string) bool {

	var sbomContent interface{}
	if err := json.Unmarshal(sbomData.Content, &sbomContent); err != nil {
		return false
	}

	if sbomData.ObjType == "" {
		sbomData.ObjType = "SBOM"
	}

	_, sbomID, err := sbom.ProcessSBOM(ctx, db, *sbomData)
	if err != nil {
		return false
	}

	if err := releases.DeleteRelease2SBOMEdges(ctx, db, releaseID); err != nil {
		return false
	}

	edge := map[string]interface{}{
		"_from": releaseID,
		"_to":   sbomID,
	}
	if _, err := db.Collections["release2sbom"].CreateDocument(ctx, edge); err != nil {
		return false
	}

	if err := sbom.ProcessSBOMComponents(ctx, db, *sbomData, sbomID); err != nil {
		return false
	}

	return true
}

func createSyncRecords(ctx context.Context, db database.DBConnection, endpointName string,
	updatedReleases map[string]string, syncedAt time.Time, results []ReleaseResult) (int, error) {

	syncedCount := 0

	for releaseName, releaseVersion := range updatedReleases {
		relMeta, err := fetchReleaseMetadata(ctx, db, releaseName, releaseVersion)
		if err != nil {
			continue
		}

		syncDoc := buildSyncDocument(relMeta, endpointName, syncedAt)

		syncMeta, err := db.Collections["sync"].CreateDocument(ctx, syncDoc)
		if err != nil {
			updateResultError(results, releaseName, releaseVersion, err)
			continue
		}

		syncedCount++
		updateResultSyncKey(results, releaseName, releaseVersion, syncMeta.Key)
	}

	return syncedCount, nil
}

func fetchReleaseMetadata(ctx context.Context, db database.DBConnection, name, version string) (*ReleaseMetadata, error) {
	query := `
		FOR r IN release
			FILTER r.name == @name && r.version == @version
			LIMIT 1
			RETURN {
				name: r.name,
				version: r.version,
				version_major: r.version_major,
				version_minor: r.version_minor,
				version_patch: r.version_patch,
				version_prerelease: r.version_prerelease
			}
	`
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"name":    name,
			"version": version,
		},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	if !cursor.HasMore() {
		return nil, fmt.Errorf("release not found")
	}

	var meta ReleaseMetadata
	if _, err := cursor.ReadDocument(ctx, &meta); err != nil {
		return nil, err
	}

	return &meta, nil
}

func buildSyncDocument(relMeta *ReleaseMetadata, endpointName string, syncedAt time.Time) map[string]interface{} {
	sync := map[string]interface{}{
		"release_name":    relMeta.Name,
		"release_version": relMeta.Version,
		"endpoint_name":   endpointName,
		"synced_at":       syncedAt,
		"objtype":         "Sync",
	}

	if relMeta.VersionMajor != nil {
		sync["release_version_major"] = *relMeta.VersionMajor
	}
	if relMeta.VersionMinor != nil {
		sync["release_version_minor"] = *relMeta.VersionMinor
	}
	if relMeta.VersionPatch != nil {
		sync["release_version_patch"] = *relMeta.VersionPatch
	}
	if relMeta.VersionPrerelease != "" {
		sync["release_version_prerelease"] = relMeta.VersionPrerelease
	}

	return sync
}

func updateResultError(results []ReleaseResult, name, version string, err error) {
	for i := range results {
		if results[i].Name == name && results[i].Version == version {
			results[i].Status = "error"
			results[i].Message = fmt.Sprintf("Failed to save sync: %s", err.Error())
		}
	}
}

func updateResultSyncKey(results []ReleaseResult, name, version, syncKey string) {
	for i := range results {
		if results[i].Name == name && results[i].Version == version && results[i].Status != "unchanged" {
			results[i].SyncKey = syncKey
		}
	}
}

func buildSyncResponse(c *fiber.Ctx, results []ReleaseResult, syncedCount int, endpointExists bool,
	endpointName string, syncedAt time.Time) error {

	counts := countResults(results)

	overallSuccess := syncedCount > 0
	statusCode := fiber.StatusCreated
	if syncedCount == 0 {
		statusCode = fiber.StatusBadRequest
	} else if counts["errors"] > 0 {
		statusCode = fiber.StatusMultiStatus
	}

	message := buildResponseMessage(counts, syncedCount, endpointName, endpointExists)

	return c.Status(statusCode).JSON(fiber.Map{
		"success":           overallSuccess,
		"message":           message,
		"synced_at":         syncedAt,
		"total_in_request":  len(results),
		"total_synced":      syncedCount,
		"created":           counts["created"] + counts["created_with_sbom"],
		"created_with_sbom": counts["created_with_sbom"],
		"updated":           counts["updated"] + counts["updated_with_sbom"],
		"updated_with_sbom": counts["updated_with_sbom"],
		"unchanged":         counts["unchanged"],
		"errors":            counts["errors"],
		"results":           results,
	})
}

func countResults(results []ReleaseResult) map[string]int {
	counts := map[string]int{
		"created":           0,
		"created_with_sbom": 0,
		"updated":           0,
		"updated_with_sbom": 0,
		"unchanged":         0,
		"errors":            0,
	}

	for _, result := range results {
		switch result.Status {
		case "created":
			counts["created"]++
		case "created_with_sbom":
			counts["created_with_sbom"]++
		case "updated":
			counts["updated"]++
		case "updated_with_sbom":
			counts["updated_with_sbom"]++
		case "unchanged":
			counts["unchanged"]++
		case "error":
			counts["errors"]++
		}
	}

	return counts
}

func buildResponseMessage(counts map[string]int, syncedCount int, endpointName string, endpointExists bool) string {
	message := fmt.Sprintf("Created sync snapshot with %d releases for endpoint %s", syncedCount, endpointName)

	if !endpointExists {
		message += " (endpoint created)"
	}

	totalCreated := counts["created"] + counts["created_with_sbom"]
	if totalCreated > 0 {
		message += fmt.Sprintf(", %d created", totalCreated)
		if counts["created_with_sbom"] > 0 {
			message += fmt.Sprintf(" (%d with SBOM)", counts["created_with_sbom"])
		}
	}

	totalUpdated := counts["updated"] + counts["updated_with_sbom"]
	if totalUpdated > 0 {
		message += fmt.Sprintf(", %d updated", totalUpdated)
		if counts["updated_with_sbom"] > 0 {
			message += fmt.Sprintf(" (%d with SBOM)", counts["updated_with_sbom"])
		}
	}

	if counts["unchanged"] > 0 {
		message += fmt.Sprintf(", %d unchanged", counts["unchanged"])
	}

	if counts["errors"] > 0 {
		message += fmt.Sprintf(", %d errors", counts["errors"])
	}

	return message
}
