// Package lifecycle implements the REST API handlers for CVE lifecycle tracking operations.
package lifecycle

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/model"
	"github.com/ortelius/pdvd-backend/v12/util"
)

// UpdateCVELifecycleTracking processes CVE state changes for an endpoint
func UpdateCVELifecycleTracking(ctx context.Context, db database.DBConnection, endpointName string,
	syncedAt time.Time, updatedReleases map[string]string) error {

	// Step 1: Get CURRENT CVE state for this endpoint
	currentCVEs, err := getCurrentCVEsForEndpoint(ctx, db, updatedReleases)
	if err != nil {
		return fmt.Errorf("failed to get current CVEs: %w", err)
	}

	// Step 2: Get PREVIOUS CVE state from lifecycle collection
	previousCVEs, err := getPreviousCVEsFromLifecycle(ctx, db, endpointName)
	if err != nil {
		return fmt.Errorf("failed to get previous CVEs: %w", err)
	}

	// Step 3: Upsert ALL current CVEs
	for _, cveInfo := range currentCVEs {
		disclosedAfter := false
		if !cveInfo.Published.IsZero() {
			disclosedAfter = cveInfo.Published.After(syncedAt)
		}

		err := UpsertLifecycleRecord(ctx, db, endpointName, cveInfo, syncedAt, disclosedAfter)
		if err != nil {
			log.Printf("Failed to upsert lifecycle record for %s: %v", cveInfo.CveID, err)
		}
	}

	// Step 4: Detect REMEDIATED CVEs
	for cveKey, existingRecord := range previousCVEs {
		if _, stillExists := currentCVEs[cveKey]; !stillExists {
			remediatedVersion := updatedReleases[existingRecord.ReleaseName]
			err := MarkCVERemediated(ctx, db, existingRecord, syncedAt, remediatedVersion)
			if err != nil {
				log.Printf("Failed to mark CVE remediated for %s: %v", cveKey, err)
			}
		}
	}

	return nil
}

// getCurrentCVEsForEndpoint fetches all CVEs for the endpoint's current state
func getCurrentCVEsForEndpoint(ctx context.Context, db database.DBConnection, releases map[string]string) (map[string]CurrentCVEInfo, error) {
	result := make(map[string]CurrentCVEInfo)

	for releaseName, releaseVersion := range releases {
		cves, err := GetCVEsForReleaseTracking(ctx, db, releaseName, releaseVersion)
		if err != nil {
			log.Printf("Failed to get CVEs for release %s:%s: %v", releaseName, releaseVersion, err)
			continue
		}

		for cveID, cveInfo := range cves {
			key := fmt.Sprintf("%s:%s:%s", cveID, cveInfo.Package, releaseName)

			result[key] = CurrentCVEInfo{
				CVEKey: CVEKey{
					CveID:       cveID,
					Package:     cveInfo.Package,
					ReleaseName: releaseName,
				},
				SeverityRating: cveInfo.SeverityRating,
				SeverityScore:  cveInfo.SeverityScore,
				Published:      cveInfo.Published,
				ReleaseVersion: releaseVersion,
			}
		}
	}

	return result, nil
}

// GetCVEsForReleaseTracking fetches CVEs for a specific release
func GetCVEsForReleaseTracking(ctx context.Context, db database.DBConnection, releaseName, releaseVersion string) (map[string]CVEInfoTracking, error) {
	query := `
		FOR release IN release
			FILTER release.name == @name AND release.version == @version
			LIMIT 1
			
			LET sbomData = (
				FOR s IN 1..1 OUTBOUND release release2sbom
					LIMIT 1
					RETURN { id: s._id }
			)[0]
			
			FILTER sbomData != null
			
			LET vulns = (
				FOR sbomEdge IN sbom2purl
					FILTER sbomEdge._from == sbomData.id
					LET purl = DOCUMENT(sbomEdge._to)
					FILTER purl != null
					
					FOR cveEdge IN cve2purl
						FILTER cveEdge._to == purl._id
						
						FILTER (
							sbomEdge.version_major != null AND 
							cveEdge.introduced_major != null AND 
							(cveEdge.fixed_major != null OR cveEdge.last_affected_major != null)
						) ? (
							(sbomEdge.version_major > cveEdge.introduced_major OR
							(sbomEdge.version_major == cveEdge.introduced_major AND 
							sbomEdge.version_minor > cveEdge.introduced_minor) OR
							(sbomEdge.version_major == cveEdge.introduced_major AND 
							sbomEdge.version_minor == cveEdge.introduced_minor AND 
							sbomEdge.version_patch >= cveEdge.introduced_patch))
							AND
							(cveEdge.fixed_major != null ? (
								sbomEdge.version_major < cveEdge.fixed_major OR
								(sbomEdge.version_major == cveEdge.fixed_major AND 
								sbomEdge.version_minor < cveEdge.fixed_minor) OR
								(sbomEdge.version_major == cveEdge.fixed_major AND 
								sbomEdge.version_minor == cveEdge.fixed_minor AND 
								sbomEdge.version_patch < cveEdge.fixed_patch)
							) : (
								sbomEdge.version_major < cveEdge.last_affected_major OR
								(sbomEdge.version_major == cveEdge.last_affected_major AND 
								sbomEdge.version_minor < cveEdge.last_affected_minor) OR
								(sbomEdge.version_major == cveEdge.last_affected_major AND 
								sbomEdge.version_minor == cveEdge.last_affected_minor AND 
								sbomEdge.version_patch <= cveEdge.last_affected_patch)
							))
						) : true
						
						LET cve = DOCUMENT(cveEdge._from)
						FILTER cve != null
						
						LET matchedAffected = (
							FOR affected IN cve.affected != null ? cve.affected : []
								LET cveBasePurl = affected.package.purl != null ? 
									affected.package.purl : 
									CONCAT("pkg:", LOWER(affected.package.ecosystem), "/", affected.package.name)
								FILTER cveBasePurl == purl.purl
								RETURN affected
						)
						FILTER LENGTH(matchedAffected) > 0
						
						RETURN {
							cve_id: cve.id,
							published: cve.published,
							severity_rating: cve.database_specific.severity_rating,
							severity_score: cve.database_specific.cvss_base_score,
							package: purl.purl,
							affected_version: sbomEdge.version,
							all_affected: matchedAffected,
							needs_validation: sbomEdge.version_major == null OR cveEdge.introduced_major == null
						}
			)
			
			RETURN vulns
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

	type VulnRaw struct {
		CveID           string            `json:"cve_id"`
		Published       string            `json:"published"`
		SeverityRating  string            `json:"severity_rating"`
		SeverityScore   float64           `json:"severity_score"`
		Package         string            `json:"package"`
		AffectedVersion string            `json:"affected_version"`
		AllAffected     []models.Affected `json:"all_affected"`
		NeedsValidation bool              `json:"needs_validation"`
	}

	result := make(map[string]CVEInfoTracking)
	seen := make(map[string]bool)

	if !cursor.HasMore() {
		return result, nil
	}

	var vulns []VulnRaw
	if _, err = cursor.ReadDocument(ctx, &vulns); err != nil {
		return nil, err
	}

	for _, v := range vulns {
		if v.NeedsValidation && len(v.AllAffected) > 0 {
			isAffected := false
			for _, affected := range v.AllAffected {
				if util.IsVersionAffected(v.AffectedVersion, affected) {
					isAffected = true
					break
				}
			}
			if !isAffected {
				continue
			}
		}

		key := v.CveID + ":" + v.Package
		if seen[key] {
			continue
		}
		seen[key] = true

		var publishedTime time.Time
		if v.Published != "" {
			if t, err := time.Parse(time.RFC3339, v.Published); err == nil {
				publishedTime = t
			} else if t, err := time.Parse("2006-01-02T15:04:05", v.Published); err == nil {
				publishedTime = t
			}
		}

		result[v.CveID] = CVEInfoTracking{
			Package:        v.Package,
			SeverityRating: v.SeverityRating,
			SeverityScore:  v.SeverityScore,
			Published:      publishedTime,
		}
	}

	return result, nil
}

// getPreviousCVEsFromLifecycle retrieves open CVEs for this endpoint
func getPreviousCVEsFromLifecycle(ctx context.Context, db database.DBConnection,
	endpointName string) (map[string]model.CVELifecycleEvent, error) {

	query := `
		FOR record IN cve_lifecycle
			FILTER record.endpoint_name == @endpoint_name
			FILTER record.is_remediated == false
			RETURN record
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

	result := make(map[string]model.CVELifecycleEvent)

	for cursor.HasMore() {
		var record model.CVELifecycleEvent
		if _, err := cursor.ReadDocument(ctx, &record); err == nil {
			key := fmt.Sprintf("%s:%s:%s", record.CveID, record.Package, record.ReleaseName)
			result[key] = record
		}
	}

	return result, nil
}

// UpsertLifecycleRecord creates or updates a CVE lifecycle tracking record
func UpsertLifecycleRecord(ctx context.Context, db database.DBConnection, endpointName string,
	cveInfo CurrentCVEInfo, introducedAt time.Time, disclosedAfterDeployment bool) error {

	record := map[string]interface{}{
		"cve_id":                     cveInfo.CveID,
		"endpoint_name":              endpointName,
		"release_name":               cveInfo.ReleaseName,
		"package":                    cveInfo.Package,
		"severity_rating":            cveInfo.SeverityRating,
		"severity_score":             cveInfo.SeverityScore,
		"introduced_at":              introducedAt,
		"published":                  cveInfo.Published,
		"introduced_version":         cveInfo.ReleaseVersion,
		"is_remediated":              false,
		"disclosed_after_deployment": disclosedAfterDeployment,
		"objtype":                    "CVELifecycleEvent",
		"created_at":                 time.Now(),
		"updated_at":                 time.Now(),
	}

	query := `
        UPSERT { 
            cve_id: @record.cve_id, 
            endpoint_name: @record.endpoint_name, 
            release_name: @record.release_name, 
            package: @record.package 
        } 
        INSERT @record 
        UPDATE { 
            updated_at: DATE_NOW(), 
            disclosed_after_deployment: OLD.disclosed_after_deployment || @record.disclosed_after_deployment 
        } 
        IN cve_lifecycle
    `

	_, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{"record": record},
	})
	return err
}

// MarkCVERemediated updates a lifecycle record to mark CVE as fixed
func MarkCVERemediated(ctx context.Context, db database.DBConnection, existingRecord model.CVELifecycleEvent,
	remediatedAt time.Time, remediatedVersion string) error {

	daysToRemediate := remediatedAt.Sub(existingRecord.IntroducedAt).Hours() / 24

	update := map[string]interface{}{
		"remediated_at":      remediatedAt,
		"remediated_version": remediatedVersion,
		"days_to_remediate":  daysToRemediate,
		"is_remediated":      true,
		"updated_at":         time.Now(),
	}

	_, err := db.Collections["cve_lifecycle"].UpdateDocument(ctx, existingRecord.Key, update)
	return err
}
