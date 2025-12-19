// Package lifecycle provides CVE lifecycle event tracking and management.
package lifecycle

import (
	"context"
	"fmt"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/ortelius/pdvd-backend/v12/database"
)

// CreateOrUpdateLifecycleRecord creates a new lifecycle record or updates existing one.
func CreateOrUpdateLifecycleRecord(
	ctx context.Context,
	db database.DBConnection,
	endpointName string,
	releaseName string,
	releaseVersion string,
	cveInfo CVEInfo,
	introducedAt time.Time,
	disclosedAfter bool,
) error {

	// PERMANENT FIX: Block zero-value timestamps from polluting the collection
	if introducedAt.IsZero() {
		return fmt.Errorf("refusing to create lifecycle record with zero-value timestamp for %s", cveInfo.CVEID)
	}

	checkQuery := `
		FOR rec IN cve_lifecycle
			FILTER rec.cve_id == @cve_id
			AND rec.package == @package
			AND rec.release_name == @release_name
			AND rec.endpoint_name == @endpoint_name
			AND rec.introduced_version == @version
			LIMIT 1
			RETURN rec
	`

	cursor, err := db.Database.Query(ctx, checkQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"cve_id":        cveInfo.CVEID,
			"package":       cveInfo.Package,
			"release_name":  releaseName,
			"endpoint_name": endpointName,
			"version":       releaseVersion,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to check existing lifecycle record: %w", err)
	}
	defer cursor.Close()

	if cursor.HasMore() {
		var existing map[string]interface{}
		_, err := cursor.ReadDocument(ctx, &existing)
		if err != nil {
			return fmt.Errorf("failed to read existing record: %w", err)
		}

		updateQuery := `
			UPDATE @key WITH {
				updated_at: DATE_NOW(),
				disclosed_after_deployment: OLD.disclosed_after_deployment || @disclosed_after
			} IN cve_lifecycle
		`
		_, err = db.Database.Query(ctx, updateQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"key":             existing["_key"],
				"disclosed_after": disclosedAfter,
			},
		})
		return err
	}

	// Calculate disclosedAfter using introducedAt vs published time
	isDisclosedAfter := !cveInfo.Published.IsZero() && cveInfo.Published.After(introducedAt)

	record := map[string]interface{}{
		"cve_id":                     cveInfo.CVEID,
		"endpoint_name":              endpointName,
		"release_name":               releaseName,
		"package":                    cveInfo.Package,
		"severity_rating":            cveInfo.SeverityRating,
		"severity_score":             cveInfo.SeverityScore,
		"introduced_at":              introducedAt,
		"introduced_version":         releaseVersion,
		"remediated_at":              nil,
		"remediated_version":         nil,
		"days_to_remediate":          nil,
		"is_remediated":              false,
		"disclosed_after_deployment": isDisclosedAfter,
		"published":                  cveInfo.Published,
		"objtype":                    "CVELifecycleEvent",
		"created_at":                 time.Now().UTC(),
		"updated_at":                 time.Now().UTC(),
	}

	_, err = db.Collections["cve_lifecycle"].CreateDocument(ctx, record)
	return err
}

func MarkCVERemediated(
	ctx context.Context,
	db database.DBConnection,
	endpointName string,
	releaseName string,
	previousVersion string,
	currentVersion string,
	cveID string,
	packagePURL string,
	remediatedAt time.Time,
) error {

	query := `
		FOR r IN cve_lifecycle
			FILTER r.cve_id == @cve_id
			AND r.package == @package
			AND r.release_name == @release_name
			AND r.endpoint_name == @endpoint_name
			AND r.introduced_version == @previous_version
			AND r.is_remediated == false
			LIMIT 1
			
			LET daysDiff = DATE_DIFF(
				DATE_TIMESTAMP(r.introduced_at),
				@remediated_at_ts,
				"d"
			)
			
			UPDATE r WITH {
				is_remediated: true,
				remediated_at: @remediated_at,
				remediated_version: @current_version,
				days_to_remediate: daysDiff,
				updated_at: DATE_NOW()
			} IN cve_lifecycle
			RETURN NEW
	`

	_, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"cve_id":           cveID,
			"package":          packagePURL,
			"release_name":     releaseName,
			"endpoint_name":    endpointName,
			"previous_version": previousVersion,
			"current_version":  currentVersion,
			"remediated_at":    remediatedAt,
			"remediated_at_ts": remediatedAt.Unix() * 1000,
		},
	})
	return err
}

func CompareAndMarkRemediations(
	ctx context.Context,
	db database.DBConnection,
	endpointName string,
	releaseName string,
	previousVersion string,
	currentVersion string,
	currentCVEs map[string]CVEInfo,
	remediatedAt time.Time,
) (int, error) {

	query := `
		FOR r IN cve_lifecycle
			FILTER r.release_name == @release_name
			AND r.endpoint_name == @endpoint_name
			AND r.introduced_version == @previous_version
			AND r.is_remediated == false
			RETURN {
				cve_id: r.cve_id,
				package: r.package,
				key: CONCAT(r.cve_id, ":", r.package)
			}
	`

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"release_name":     releaseName,
			"endpoint_name":    endpointName,
			"previous_version": previousVersion,
		},
	})
	if err != nil {
		return 0, err
	}
	defer cursor.Close()

	remediatedCount := 0
	for cursor.HasMore() {
		var prev struct {
			CVEID   string `json:"cve_id"`
			Package string `json:"package"`
			Key     string `json:"key"`
		}
		if _, err := cursor.ReadDocument(ctx, &prev); err == nil {
			if _, exists := currentCVEs[prev.Key]; !exists {
				MarkCVERemediated(ctx, db, endpointName, releaseName, previousVersion, currentVersion, prev.CVEID, prev.Package, remediatedAt)
				remediatedCount++
			}
		}
	}
	return remediatedCount, nil
}

func GetPreviousVersion(ctx context.Context, db database.DBConnection, releaseName, endpointName string, currentSyncTime time.Time) (string, error) {
	// FIX: Use DATE_TIMESTAMP for robust sorting
	query := `
		FOR s IN sync
			FILTER s.release_name == @release_name
			AND s.endpoint_name == @endpoint_name
			AND DATE_TIMESTAMP(s.synced_at) < @current_time
			SORT DATE_TIMESTAMP(s.synced_at) DESC
			LIMIT 1
			RETURN s.release_version
	`
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"release_name":  releaseName,
			"endpoint_name": endpointName,
			"current_time":  currentSyncTime.Unix() * 1000,
		},
	})
	if err != nil {
		return "", err
	}
	defer cursor.Close()

	if cursor.HasMore() {
		var version string
		_, err := cursor.ReadDocument(ctx, &version)
		return version, err
	}
	return "", nil
}

func GetSyncTimestamp(ctx context.Context, db database.DBConnection, releaseName, releaseVersion, endpointName string) (time.Time, error) {
	// FIX: Use DATE_ISO8601 to ensure standard parsing into Go time.Time
	query := `
		FOR s IN sync
			FILTER s.release_name == @release_name
			AND s.release_version == @release_version
			AND s.endpoint_name == @endpoint_name
			SORT DATE_TIMESTAMP(s.synced_at) DESC
			LIMIT 1
			RETURN DATE_ISO8601(s.synced_at)
	`
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"release_name":    releaseName,
			"release_version": releaseVersion,
			"endpoint_name":   endpointName,
		},
	})
	if err != nil {
		return time.Time{}, err
	}
	defer cursor.Close()

	if cursor.HasMore() {
		var timestamp time.Time
		_, err := cursor.ReadDocument(ctx, &timestamp)
		return timestamp, err
	}
	return time.Time{}, fmt.Errorf("no sync record found")
}

func GetCVEsForReleaseTracking(ctx context.Context, db database.DBConnection, releaseName, releaseVersion string) (map[string]CVEInfo, error) {
	query := `
		FOR release IN release
			FILTER release.name == @release_name
			AND release.version == @release_version
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
		BindVars: map[string]interface{}{"release_name": releaseName, "release_version": releaseVersion},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	result := make(map[string]CVEInfo)
	for cursor.HasMore() {
		var raw struct {
			CveID          string  `json:"cve_id"`
			Package        string  `json:"package"`
			SeverityRating string  `json:"severity_rating"`
			SeverityScore  float64 `json:"severity_score"`
			Published      string  `json:"published"`
		}
		if _, err := cursor.ReadDocument(ctx, &raw); err == nil {
			pubTime, _ := time.Parse(time.RFC3339, raw.Published)
			result[raw.CveID] = CVEInfo{CVEID: raw.CveID, Package: raw.Package, SeverityRating: raw.SeverityRating, SeverityScore: raw.SeverityScore, Published: pubTime}
		}
	}
	return result, nil
}

func CreateRelease2CVEEdges(ctx context.Context, db database.DBConnection, releaseID string) error {
	query := `
		LET release = DOCUMENT(@release_id)
		LET sbomData = FIRST(FOR s IN 1..1 OUTBOUND release release2sbom LIMIT 1 RETURN s)
		FILTER sbomData != null
		FOR sbomEdge IN sbom2purl
			FILTER sbomEdge._from == sbomData._id
			LET purl = DOCUMENT(sbomEdge._to)
			FILTER purl != null
			FOR cveEdge IN cve2purl
				FILTER cveEdge._to == purl._id
				LET cve = DOCUMENT(cveEdge._from)
				FILTER cve != null
				RETURN {
					cve_id: cve._id,
					package_purl: purl.purl,
					package_version: sbomEdge.version
				}
	`
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: map[string]interface{}{"release_id": releaseID}})
	if err != nil {
		return err
	}
	defer cursor.Close()

	for cursor.HasMore() {
		var cand struct{ CveID, PackagePurl, PackageVersion string }
		if _, err := cursor.ReadDocument(ctx, &cand); err != nil {
			continue
		}
		edge := map[string]interface{}{
			"_from": releaseID, "_to": cand.CveID, "type": "sbom_analysis",
			"package_purl": cand.PackagePurl, "package_version": cand.PackageVersion, "created_at": time.Now(),
		}
		db.Collections["release2cve"].CreateDocument(ctx, edge)
	}
	return nil
}

func BuildCVEMap(cves []CVEInfo) map[string]CVEInfo {
	result := make(map[string]CVEInfo)
	for _, cve := range cves {
		result[fmt.Sprintf("%s:%s", cve.CVEID, cve.Package)] = cve
	}
	return result
}
