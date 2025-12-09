package dashboard

import (
	"context"
	"sort"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/util" // Import the util package
)

// --- ADDED MISSING RESOLVERS (Mocks) ---

// ResolveOverview handles fetching the high-level dashboard metrics
func ResolveOverview(db database.DBConnection) (interface{}, error) {
	// TODO: Replace with actual database query calculating these metrics
	return map[string]interface{}{
		"totalOpen":     142,
		"criticalOpen":  28,
		"mttr":          12.5,
		"remediatedPct": 76,
	}, nil
}

// ResolveSeverityDistribution fetches current breakdown of issues
func ResolveSeverityDistribution(db database.DBConnection) (interface{}, error) {
	// TODO: Replace with actual database query for current severity snapshots
	return map[string]interface{}{
		"critical": 28,
		"high":     45,
		"medium":   32,
		"low":      15,
	}, nil
}

// ResolveTopRisks fetches the top risky assets based on type
func ResolveTopRisks(db database.DBConnection, assetType string, limit int) (interface{}, error) {
	// TODO: Replace with actual database query filtering by assetType
	// Mock response
	var risks []map[string]interface{}

	// Example mock data
	risks = append(risks, map[string]interface{}{
		"name":        "payment-service-prod",
		"issuesCount": 12,
		"status":      "Risk",
	})
	risks = append(risks, map[string]interface{}{
		"name":        "auth-service-prod",
		"issuesCount": 8,
		"status":      "Risk",
	})

	// Ensure we don't return more than the limit
	if len(risks) > limit {
		return risks[:limit], nil
	}
	return risks, nil
}

// --- EXISTING RESOLVER ---

// ResolveVulnerabilityTrend returns counts of Critical/High/Medium/Low vulns grouped by sync date
// Implements "End of Day State" logic following ResolveAffectedReleases pattern
func ResolveVulnerabilityTrend(db database.DBConnection, days int) ([]map[string]interface{}, error) {
	ctx := context.Background()

	query := `
		LET startDate = DATE_SUBTRACT(DATE_NOW(), @days, "day")
		
		// 1. Get raw syncs in date range
		LET rawSyncs = (
			FOR s IN sync
				FILTER s.synced_at >= startDate
				RETURN { 
					date: DATE_FORMAT(s.synced_at, "%yyyy-%mm-%dd"), 
					datetime: s.synced_at,
					endpoint: s.endpoint_name,
					name: s.release_name, 
					version: s.release_version 
				}
		)

		// 2. DEDUPLICATE: Get "End of Day" State per Endpoint
		// If an endpoint was deployed 5 times today, only the last version counts
		LET dailyUniqueSyncs = (
			FOR s IN rawSyncs
				COLLECT date = s.date, endpoint = s.endpoint INTO dayMoves
				LET lastMove = (
					FOR m IN dayMoves 
						SORT m.s.datetime DESC 
						LIMIT 1 
						RETURN m.s
				)[0]
				RETURN {
					date: date,
					name: lastMove.name,
					version: lastMove.version
				}
		)

		// 3. Get Unique Releases from the deduplicated set
		LET uniqueReleases = (
			FOR s IN dailyUniqueSyncs
				COLLECT name = s.name, version = s.version
				RETURN { name, version }
		)

		// 4. Get Potential Vulnerabilities for each release
		LET releaseVulns = (
			FOR ur IN uniqueReleases
				LET releaseDoc = (
					FOR r IN release 
						FILTER r.name == ur.name AND r.version == ur.version 
						LIMIT 1 
						RETURN r
				)[0]
				
				FILTER releaseDoc != null

				LET potentialCves = (
					FOR sbom IN 1..1 OUTBOUND releaseDoc release2sbom
						FOR sbomEdge IN sbom2purl
							FILTER sbomEdge._from == sbom._id
							LET purl = DOCUMENT(sbomEdge._to)
							FILTER purl != null

							FOR cveEdge IN cve2purl
								FILTER cveEdge._to == purl._id
								
								// Coarse AQL filter matching releases module pattern
								FILTER (
									sbomEdge.version_major != null AND 
									cveEdge.introduced_major != null
								) ? (
									(sbomEdge.version_major > cveEdge.introduced_major OR
									 (sbomEdge.version_major == cveEdge.introduced_major AND sbomEdge.version_minor > cveEdge.introduced_minor) OR
									 (sbomEdge.version_major == cveEdge.introduced_major AND sbomEdge.version_minor == cveEdge.introduced_minor AND sbomEdge.version_patch >= cveEdge.introduced_patch))
									AND
									(cveEdge.fixed_major == null OR
									 (sbomEdge.version_major < cveEdge.fixed_major OR
									  (sbomEdge.version_major == cveEdge.fixed_major AND sbomEdge.version_minor < cveEdge.fixed_minor) OR
									  (sbomEdge.version_major == cveEdge.fixed_major AND sbomEdge.version_minor == cveEdge.fixed_minor AND sbomEdge.version_patch < cveEdge.fixed_patch)))
								) : true

								LET cve = DOCUMENT(cveEdge._from)
								FILTER cve != null
                                // UPDATED: Included MEDIUM and LOW
								FILTER cve.database_specific.severity_rating IN ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
								
								// Must return enough data for Go validation
								LET matchedAffected = (
									FOR affected IN cve.affected != null ? cve.affected : []
										LET cveBasePurl = affected.package.purl != null ? 
											affected.package.purl : 
											CONCAT("pkg:", LOWER(affected.package.ecosystem), "/", affected.package.name)
										FILTER cveBasePurl == purl.purl
										RETURN affected
								)

								RETURN {
									rating: cve.database_specific.severity_rating,
									version: sbomEdge.version,
									all_affected: matchedAffected,
									needs_validation: sbomEdge.version_major == null OR cveEdge.introduced_major == null
								}
				)

				RETURN {
					name: ur.name,
					version: ur.version,
					cves: potentialCves
				}
		)

		RETURN {
			syncs: dailyUniqueSyncs,
			releases: releaseVulns
		}
	`

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"days": days,
		},
	})
	if err != nil {
		return []map[string]interface{}{}, err
	}
	defer cursor.Close()

	type PotentialCVE struct {
		Rating          string            `json:"rating"`
		Version         string            `json:"version"`
		AllAffected     []models.Affected `json:"all_affected"`
		NeedsValidation bool              `json:"needs_validation"`
	}

	type ReleaseData struct {
		Name    string         `json:"name"`
		Version string         `json:"version"`
		CVEs    []PotentialCVE `json:"cves"`
	}

	type SyncData struct {
		Date    string `json:"date"`
		Name    string `json:"name"`
		Version string `json:"version"`
	}

	type QueryResult struct {
		Syncs    []SyncData    `json:"syncs"`
		Releases []ReleaseData `json:"releases"`
	}

	if !cursor.HasMore() {
		return []map[string]interface{}{}, nil
	}

	var result QueryResult
	_, err = cursor.ReadDocument(ctx, &result)
	if err != nil {
		return []map[string]interface{}{}, err
	}

	// 1. Pre-calculate risk counts for each unique release
	releaseRiskMap := make(map[string]struct {
		crit   int
		high   int
		medium int
		low    int
	})

	for _, rel := range result.Releases {
		critCount := 0
		highCount := 0
		mediumCount := 0
		lowCount := 0

		for _, cve := range rel.CVEs {
			isValid := true
			// If AQL couldn't be sure, we check in Go using the official logic
			if cve.NeedsValidation && len(cve.AllAffected) > 0 {
				// Use util.IsVersionAffected to validate
				matchFound := false
				for _, affected := range cve.AllAffected {
					if util.IsVersionAffected(cve.Version, affected) {
						matchFound = true
						break
					}
				}
				if !matchFound {
					isValid = false
				}
			}

			if isValid {
				switch cve.Rating {
				case "CRITICAL":
					critCount++
				case "HIGH":
					highCount++
				case "MEDIUM":
					mediumCount++
				case "LOW":
					lowCount++
				}
			}
		}

		key := rel.Name + ":" + rel.Version
		releaseRiskMap[key] = struct {
			crit   int
			high   int
			medium int
			low    int
		}{critCount, highCount, mediumCount, lowCount}
	}

	// 2. Aggregate counts by Date using the DEDUPLICATED Sync records
	dateMap := make(map[string]struct {
		crit   int
		high   int
		medium int
		low    int
	})

	for _, sync := range result.Syncs {
		key := sync.Name + ":" + sync.Version
		if counts, ok := releaseRiskMap[key]; ok {
			curr := dateMap[sync.Date]
			curr.crit += counts.crit
			curr.high += counts.high
			curr.medium += counts.medium
			curr.low += counts.low
			dateMap[sync.Date] = curr
		}
	}

	// 3. Format and Sort results for the frontend
	var finalResults []map[string]interface{}
	for date, counts := range dateMap {
		finalResults = append(finalResults, map[string]interface{}{
			"date":     date,
			"critical": counts.crit,
			"high":     counts.high,
			"medium":   counts.medium,
			"low":      counts.low,
		})
	}

	// Sort by date ascending
	sort.Slice(finalResults, func(i, j int) bool {
		d1, _ := time.Parse("2006-01-02", finalResults[i]["date"].(string))
		d2, _ := time.Parse("2006-01-02", finalResults[j]["date"].(string))
		return d1.Before(d2)
	})

	return finalResults, nil
}
