// Package dashboard implements the resolvers for dashboard metrics.
package dashboard

import (
	"context"
	"sort"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/util"
)

func isVersionAffectedAny(version string, allAffected []models.Affected) bool {
	for _, affected := range allAffected {
		if util.IsVersionAffected(version, affected) {
			return true
		}
	}
	return false
}

// ResolveOverview handles fetching the high-level dashboard metrics
func ResolveOverview(_ database.DBConnection) (interface{}, error) {
	// TODO: Replace with actual database query calculating these metrics
	return map[string]interface{}{
		"total_releases":  142,
		"total_endpoints": 36,
		"total_cves":      328,
	}, nil
}

// ResolveSeverityDistribution fetches current breakdown of issues
func ResolveSeverityDistribution(_ database.DBConnection) (interface{}, error) {
	// TODO: Replace with actual database query for current severity snapshots
	return map[string]interface{}{
		"critical": 28,
		"high":     45,
		"medium":   32,
		"low":      15,
	}, nil
}

// ResolveTopRisks fetches the top risky assets based on type
func ResolveTopRisks(_ database.DBConnection, _ string, limit int) (interface{}, error) {
	// TODO: Replace with actual database query filtering by assetType
	var risks []map[string]interface{}
	risks = append(risks, map[string]interface{}{
		"name":           "payment-service-prod",
		"version":        "v2.1.0",
		"critical_count": 4,
		"high_count":     8,
		"total_vulns":    12,
	})
	if len(risks) > limit {
		return risks[:limit], nil
	}
	return risks, nil
}

// ResolveVulnerabilityTrend returns counts of vulns grouped by sync date with Go-side validation
func ResolveVulnerabilityTrend(db database.DBConnection, days int) ([]map[string]interface{}, error) {
	ctx := context.Background()

	// Query to get historical raw vulnerability data per day
	// We return the raw list of potential vulnerabilities for Go-side processing
	trendQuery := `
		LET today = DATE_NOW()
		
		// Generate date range
		LET dateRange = (
			FOR i IN 0..@days-1
				LET date = DATE_SUBTRACT(today, i, "day")
				RETURN DATE_FORMAT(date, "%yyyy-%mm-%dd")
		)
		
		// For each date, find all syncs that occurred on or before that date
		FOR targetDate IN dateRange
			LET targetTimestamp = DATE_ISO8601(CONCAT(targetDate, "T23:59:59Z"))
			
			// Get all endpoints that had syncs by this date
			LET endpointsAtDate = (
				FOR endpoint IN endpoint
					// Get the latest sync for each release on this endpoint up to targetDate
					LET syncedReleasesAtDate = (
						FOR sync IN sync
							FILTER sync.endpoint_name == endpoint.name
							FILTER sync.synced_at <= targetTimestamp
							COLLECT releaseName = sync.release_name INTO groupedSyncs = sync
							
							// Get the latest sync for this release up to targetDate
							LET latestSync = (
								FOR s IN groupedSyncs
									SORT s.release_version_major != null ? s.release_version_major : -1 DESC,
										s.release_version_minor != null ? s.release_version_minor : -1 DESC,
										s.release_version_patch != null ? s.release_version_patch : -1 DESC,
										s.release_version_prerelease != null && s.release_version_prerelease != "" ? 1 : 0 ASC,
										s.release_version_prerelease ASC,
										s.release_version DESC
									LIMIT 1
									RETURN s
							)[0]
							
							LET releaseDoc = (
								FOR r IN release
									FILTER r.name == latestSync.release_name AND r.version == latestSync.release_version
									LIMIT 1
									RETURN r
							)[0]
							
							FILTER releaseDoc != null
							RETURN releaseDoc
					)
					
					FILTER LENGTH(syncedReleasesAtDate) > 0
					
					// Get all vulnerabilities for this endpoint at this date
					LET vulnsAtDate = (
						FOR releaseDoc IN syncedReleasesAtDate
							FOR sbom IN 1..1 OUTBOUND releaseDoc release2sbom
								FOR sbomEdge IN sbom2purl
									FILTER sbomEdge._from == sbom._id
									LET purl = DOCUMENT(sbomEdge._to)
									FILTER purl != null
									
									FOR cveEdge IN cve2purl
										FILTER cveEdge._to == purl._id
										
										// Basic AQL filtering (coarse)
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
											severity_rating: cve.database_specific.severity_rating,
											package: purl.purl,
											affected_version: sbomEdge.version,
											all_affected: matchedAffected,
											needs_validation: sbomEdge.version_major == null OR cveEdge.introduced_major == null
										}
					)
					
					RETURN vulnsAtDate
			)
			
			// Flatten the list of all potential vulnerabilities across all endpoints for this date
			RETURN {
				date: targetDate,
				potential_vulns: FLATTEN(endpointsAtDate)
			}
	`

	trendCursor, err := db.Database.Query(ctx, trendQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"days": days,
		},
	})
	if err != nil {
		return []map[string]interface{}{}, err
	}
	defer trendCursor.Close()

	// Struct to match the query result
	type SyncedVulnMatch struct {
		CveID           string            `json:"cve_id"`
		SeverityRating  string            `json:"severity_rating"`
		Package         string            `json:"package"`
		AffectedVersion string            `json:"affected_version"`
		AllAffected     []models.Affected `json:"all_affected"`
		NeedsValidation bool              `json:"needs_validation"`
	}

	type TrendDayResult struct {
		Date           string            `json:"date"`
		PotentialVulns []SyncedVulnMatch `json:"potential_vulns"`
	}

	var trendData []map[string]interface{}

	for trendCursor.HasMore() {
		var dayResult TrendDayResult
		_, err := trendCursor.ReadDocument(ctx, &dayResult)
		if err != nil {
			continue
		}

		// Deduplicate vulnerabilities by CVE ID in Go
		seenCves := make(map[string]string) // cve_id -> severity_rating

		for _, vuln := range dayResult.PotentialVulns {
			// 1. Validation Logic
			if vuln.NeedsValidation && len(vuln.AllAffected) > 0 {
				if !isVersionAffectedAny(vuln.AffectedVersion, vuln.AllAffected) {
					continue
				}
			}

			// 2. Deduplication Logic (Only keep unique CVEs for this day)
			if _, exists := seenCves[vuln.CveID]; !exists {
				seenCves[vuln.CveID] = vuln.SeverityRating
			}
		}

		// 3. Count by severity
		criticalCount := 0
		highCount := 0
		mediumCount := 0
		lowCount := 0

		for _, rating := range seenCves {
			switch rating {
			case "CRITICAL":
				criticalCount++
			case "HIGH":
				highCount++
			case "MEDIUM":
				mediumCount++
			case "LOW":
				lowCount++
			}
		}

		trendData = append(trendData, map[string]interface{}{
			"date":     dayResult.Date,
			"critical": criticalCount,
			"high":     highCount,
			"medium":   mediumCount,
			"low":      lowCount,
			"total":    len(seenCves),
		})
	}

	// Sort by date ascending (oldest to newest)
	sort.Slice(trendData, func(i, j int) bool {
		dateI, okI := trendData[i]["date"].(string)
		dateJ, okJ := trendData[j]["date"].(string)
		if !okI || !okJ {
			return false
		}
		return dateI < dateJ
	})

	return trendData, nil
}

// ResolveDashboardGlobalStatus calculates aggregated vulnerability counts and deltas across all synced endpoints
func ResolveDashboardGlobalStatus(db database.DBConnection, limit int) (map[string]interface{}, error) {
	ctx := context.Background()

	// Step 1: Fetch Endpoints and their Services (Current via SemVer, Previous via Date)
	query := `
		FOR endpoint IN endpoint
			LIMIT @limit
			LET serviceSyncs = (
				FOR s IN sync
					FILTER s.endpoint_name == endpoint.name
					COLLECT releaseName = s.release_name INTO groups = s
					
					// DEDUPLICATION: Get unique versions. 
					// We use MAX(synced_at) to find the latest sync time for this specific version.
					LET uniqueVersions = (
						FOR g IN groups
							COLLECT ver = g.release_version INTO vGroups = g
							
							LET maxDate = MAX(vGroups[*].synced_at)
							LET anyDoc = vGroups[0]
							
							RETURN { 
								version: ver, 
								synced_at: maxDate,
								major: anyDoc.release_version_major,
								minor: anyDoc.release_version_minor,
								patch: anyDoc.release_version_patch,
								prerelease: anyDoc.release_version_prerelease
							}
					)

					// 1. Determine CURRENT state using SemVer (Highest Version)
					LET current = (
						FOR v IN uniqueVersions 
							SORT v.major != null ? v.major : -1 DESC,
								v.minor != null ? v.minor : -1 DESC,
								v.patch != null ? v.patch : -1 DESC,
								v.prerelease != null && v.prerelease != "" ? 1 : 0 ASC,
								v.prerelease ASC,
								v.version DESC
							LIMIT 1 
							RETURN { version: v.version, synced_at: v.synced_at }
					)[0]

					// 2. Determine PREVIOUS state using Synced Date (Most recent sync excluding Current)
					LET previous = (
						FOR v IN uniqueVersions
							FILTER v.version != current.version
							SORT v.synced_at DESC
							LIMIT 1
							RETURN { version: v.version, synced_at: v.synced_at }
					)[0]
					
					RETURN {
						name: releaseName,
						current: current,
						previous: previous,
						history: uniqueVersions
					}
			)
			
			FILTER LENGTH(serviceSyncs) > 0
			
			RETURN {
				endpoint_name: endpoint.name,
				services: serviceSyncs
			}
	`

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"limit": limit,
		},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	type ServiceState struct {
		Name    string `json:"name"`
		Current struct {
			Version  string `json:"version"`
			SyncedAt string `json:"synced_at"`
		} `json:"current"`
		Previous *struct {
			Version  string `json:"version"`
			SyncedAt string `json:"synced_at"`
		} `json:"previous"`
		History []struct {
			Version  string `json:"version"`
			SyncedAt string `json:"synced_at"`
		} `json:"history"`
	}

	type EndpointData struct {
		EndpointName string         `json:"endpoint_name"`
		Services     []ServiceState `json:"services"`
	}

	var endpoints []EndpointData
	type ReleaseKey struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	var releasesToFetch []ReleaseKey
	seenRelease := make(map[string]bool)

	// Collect all unique releases needed
	for cursor.HasMore() {
		var ep EndpointData
		_, err := cursor.ReadDocument(ctx, &ep)
		if err != nil {
			continue
		}
		endpoints = append(endpoints, ep)

		for _, svc := range ep.Services {
			keyCurr := svc.Name + ":" + svc.Current.Version
			if !seenRelease[keyCurr] {
				releasesToFetch = append(releasesToFetch, ReleaseKey{Name: svc.Name, Version: svc.Current.Version})
				seenRelease[keyCurr] = true
			}
			if svc.Previous != nil {
				keyPrev := svc.Name + ":" + svc.Previous.Version
				if !seenRelease[keyPrev] {
					releasesToFetch = append(releasesToFetch, ReleaseKey{Name: svc.Name, Version: svc.Previous.Version})
					seenRelease[keyPrev] = true
				}
			}
		}
	}

	// Step 2: Batch fetch Raw Vulnerability Candidates
	type RawVulnMatch struct {
		CveID           string            `json:"cve_id"`
		SeverityRating  string            `json:"severity_rating"`
		AffectedVersion string            `json:"affected_version"`
		AllAffected     []models.Affected `json:"all_affected"`
		NeedsValidation bool              `json:"needs_validation"`
	}

	releaseVulnsMap := make(map[string][]RawVulnMatch)

	if len(releasesToFetch) > 0 {
		vulnQuery := `
			FOR item IN @releases
				LET releaseDoc = (
					FOR r IN release 
						FILTER r.name == item.name AND r.version == item.version 
						LIMIT 1 
						RETURN r
				)[0]
				
				FILTER releaseDoc != null

				LET cveMatches = (
					FOR sbom IN 1..1 OUTBOUND releaseDoc release2sbom
						FOR sbomEdge IN sbom2purl
							FILTER sbomEdge._from == sbom._id
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
									severity_rating: cve.database_specific.severity_rating,
									affected_version: sbomEdge.version,
									all_affected: matchedAffected,
									needs_validation: sbomEdge.version_major == null OR cveEdge.introduced_major == null
								}
				)

				RETURN {
					name: item.name,
					version: item.version,
					cves: cveMatches
				}
		`

		vCursor, err := db.Database.Query(ctx, vulnQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"releases": releasesToFetch,
			},
		})
		if err != nil {
			return nil, err
		}
		defer vCursor.Close()

		type ReleaseVulnResult struct {
			Name    string         `json:"name"`
			Version string         `json:"version"`
			CVEs    []RawVulnMatch `json:"cves"`
		}

		for vCursor.HasMore() {
			var r ReleaseVulnResult
			_, err := vCursor.ReadDocument(ctx, &r)
			if err != nil {
				continue
			}

			// Pre-validate vulns for this release
			var validVulns []RawVulnMatch
			for _, vuln := range r.CVEs {
				if vuln.NeedsValidation && len(vuln.AllAffected) > 0 {
					if !isVersionAffectedAny(vuln.AffectedVersion, vuln.AllAffected) {
						continue
					}
				}
				validVulns = append(validVulns, vuln)
			}
			releaseVulnsMap[r.Name+":"+r.Version] = validVulns
		}
	}

	// Step 3: Aggregate globally
	// - Counts: Include ALL services (Active + Stale).
	// - Deltas: Include ONLY services updated in the latest sync batch (Active).
	aggCritical := struct{ count, delta int }{}
	aggHigh := struct{ count, delta int }{}
	aggMedium := struct{ count, delta int }{}
	aggLow := struct{ count, delta int }{}
	totalCount := 0
	totalDelta := 0

	for _, ep := range endpoints {
		// 3a. Determine Latest Sync Time for this Endpoint
		var latestSyncTime time.Time
		hasTime := false

		for _, svc := range ep.Services {
			if svc.Current.SyncedAt == "" {
				continue
			}
			t, err := time.Parse(time.RFC3339, svc.Current.SyncedAt)
			if err != nil {
				continue
			}
			if !hasTime || t.After(latestSyncTime) {
				latestSyncTime = t
				hasTime = true
			}
		}

		// If we can't determine time, assume all are active (fallback)
		staleCutoff := latestSyncTime.Add(-2 * time.Hour) // 2 Hour tolerance for "Same Batch"

		// Helper to count unique vulns for a release
		countReleaseVulns := func(name, version string) map[string]int {
			counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
			key := name + ":" + version
			vulns, ok := releaseVulnsMap[key]
			if !ok {
				return counts
			}
			seen := make(map[string]bool)
			for _, v := range vulns {
				if seen[v.CveID] {
					continue
				}
				seen[v.CveID] = true
				counts["total"]++
				switch v.SeverityRating {
				case "CRITICAL":
					counts["critical"]++
				case "HIGH":
					counts["high"]++
				case "MEDIUM":
					counts["medium"]++
				case "LOW":
					counts["low"]++
				}
			}
			return counts
		}

		for _, svc := range ep.Services {
			currCounts := countReleaseVulns(svc.Name, svc.Current.Version)

			// 1. ALWAYS Add to Total Count (Retention Policy)
			aggCritical.count += currCounts["critical"]
			aggHigh.count += currCounts["high"]
			aggMedium.count += currCounts["medium"]
			aggLow.count += currCounts["low"]
			totalCount += currCounts["total"]

			// 2. Check if Service is ACTIVE (synced recently) for Delta Calculation
			isStale := false
			if hasTime && svc.Current.SyncedAt != "" {
				t, err := time.Parse(time.RFC3339, svc.Current.SyncedAt)
				if err == nil && t.Before(staleCutoff) {
					isStale = true
				}
			}

			if !isStale {
				// ACTIVE: Calculate Delta (Current - Previous)
				prevCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
				if svc.Previous != nil {
					prevCounts = countReleaseVulns(svc.Name, svc.Previous.Version)
				}

				aggCritical.delta += (currCounts["critical"] - prevCounts["critical"])
				aggHigh.delta += (currCounts["high"] - prevCounts["high"])
				aggMedium.delta += (currCounts["medium"] - prevCounts["medium"])
				aggLow.delta += (currCounts["low"] - prevCounts["low"])
				totalDelta += (currCounts["total"] - prevCounts["total"])
			}
			// STALE: Delta is 0 (No change in this sync run)
		}
	}

	return map[string]interface{}{
		"critical":    map[string]int{"count": aggCritical.count, "delta": aggCritical.delta},
		"high":        map[string]int{"count": aggHigh.count, "delta": aggHigh.delta},
		"medium":      map[string]int{"count": aggMedium.count, "delta": aggMedium.delta},
		"low":         map[string]int{"count": aggLow.count, "delta": aggLow.delta},
		"total_count": totalCount,
		"total_delta": totalDelta,
	}, nil
}
