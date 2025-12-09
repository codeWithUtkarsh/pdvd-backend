// Package dashboard implements the resolvers for dashboard metrics.
package dashboard

import (
	"context"
	"sort"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/ortelius/pdvd-backend/v12/database"
)

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

// ResolveVulnerabilityTrend returns counts of vulns grouped by sync date
func ResolveVulnerabilityTrend(db database.DBConnection, days int) ([]map[string]interface{}, error) {
	ctx := context.Background()

	// 1. Get raw syncs and deduplicate to "End of Day" state per endpoint
	query := `
		LET startDate = DATE_SUBTRACT(DATE_NOW(), @days, "day")
		
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

		LET uniqueReleases = (
			FOR s IN dailyUniqueSyncs
				COLLECT name = s.name, version = s.version
				RETURN { name, version }
		)
		
		RETURN {
			syncs: dailyUniqueSyncs,
			releases: uniqueReleases
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

	type UniqueRelease struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}

	type SyncData struct {
		Date    string `json:"date"`
		Name    string `json:"name"`
		Version string `json:"version"`
	}

	type QueryResult struct {
		Syncs    []SyncData      `json:"syncs"`
		Releases []UniqueRelease `json:"releases"`
	}

	if !cursor.HasMore() {
		return []map[string]interface{}{}, nil
	}

	var result QueryResult
	_, err = cursor.ReadDocument(ctx, &result)
	if err != nil {
		return []map[string]interface{}{}, err
	}

	// 2. Batch fetch Vulnerability Counts (Inline Logic)
	type VulnBuckets struct {
		crit, high, medium, low, total int
	}
	releaseRiskMap := make(map[string]VulnBuckets)

	type ReleaseKey struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	var releasesToFetch []ReleaseKey
	for _, r := range result.Releases {
		releasesToFetch = append(releasesToFetch, ReleaseKey{Name: r.Name, Version: r.Version})
	}

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
								FILTER cve.database_specific.cvss_base_score != null
								
								LET matchedAffected = (
									FOR affected IN cve.affected != null ? cve.affected : []
										LET cveBasePurl = affected.package.purl != null ? 
											affected.package.purl : 
											CONCAT("pkg:", LOWER(affected.package.ecosystem), "/", affected.package.name)
										FILTER cveBasePurl == purl.purl
										RETURN affected
								)
								
								RETURN {
									cve_id: cve.id,
									score: cve.database_specific.cvss_base_score
								}
				)

				// DEDUPLICATION: Group by CVE ID and take the MAX score to represent it
				LET uniqueCves = (
					FOR match IN cveMatches
						COLLECT cveId = match.cve_id INTO group
						LET score = MAX(group[*].match.score)
						RETURN { score }
				)
				
				RETURN {
					name: item.name,
					version: item.version,
					cves: uniqueCves
				}
		`

		vCursor, err := db.Database.Query(ctx, vulnQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"releases": releasesToFetch,
			},
		})
		if err == nil {
			defer vCursor.Close()
			type UniqueCVE struct {
				Score float64 `json:"score"`
			}
			type ReleaseVulnResult struct {
				Name    string      `json:"name"`
				Version string      `json:"version"`
				CVEs    []UniqueCVE `json:"cves"`
			}

			for vCursor.HasMore() {
				var r ReleaseVulnResult
				_, err := vCursor.ReadDocument(ctx, &r)
				if err != nil {
					continue
				}
				// Bucket in Go
				counts := VulnBuckets{}
				for _, cve := range r.CVEs {
					counts.total++
					if cve.Score >= 9.0 {
						counts.crit++
					} else if cve.Score >= 7.0 {
						counts.high++
					} else if cve.Score >= 4.0 {
						counts.medium++
					} else if cve.Score >= 0.1 {
						counts.low++
					}
				}
				releaseRiskMap[r.Name+":"+r.Version] = counts
			}
		}
	}

	// 3. Aggregate by Date
	dateMap := make(map[string]struct{ crit, high, medium, low int })
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

	// 4. Format Result
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

	sort.Slice(finalResults, func(i, j int) bool {
		d1, _ := time.Parse("2006-01-02", finalResults[i]["date"].(string))
		d2, _ := time.Parse("2006-01-02", finalResults[j]["date"].(string))
		return d1.Before(d2)
	})

	return finalResults, nil
}

// ResolveDashboardGlobalStatus calculates aggregated vulnerability counts and deltas across all synced endpoints
func ResolveDashboardGlobalStatus(db database.DBConnection, limit int) (map[string]interface{}, error) {
	ctx := context.Background()

	// Step 1: Fetch Endpoints and their Services (Current + Previous versions)
	query := `
		FOR endpoint IN endpoint
			LIMIT @limit
			LET serviceSyncs = (
				FOR s IN sync
					FILTER s.endpoint_name == endpoint.name
					COLLECT releaseName = s.release_name INTO groups = s
					
					// Get the last 2 sync events for this service on this endpoint
					LET sorted = (
						FOR g IN groups 
							SORT g.synced_at DESC 
							LIMIT 2 
							RETURN { version: g.release_version, synced_at: g.synced_at }
					)
					
					RETURN {
						name: releaseName,
						current: sorted[0],
						previous: LENGTH(sorted) > 1 ? sorted[1] : null
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
		Name     string                    `json:"name"`
		Current  struct{ Version string }  `json:"current"`
		Previous *struct{ Version string } `json:"previous"`
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
			// Current
			keyCurr := svc.Name + ":" + svc.Current.Version
			if !seenRelease[keyCurr] {
				releasesToFetch = append(releasesToFetch, ReleaseKey{Name: svc.Name, Version: svc.Current.Version})
				seenRelease[keyCurr] = true
			}
			// Previous
			if svc.Previous != nil {
				keyPrev := svc.Name + ":" + svc.Previous.Version
				if !seenRelease[keyPrev] {
					releasesToFetch = append(releasesToFetch, ReleaseKey{Name: svc.Name, Version: svc.Previous.Version})
					seenRelease[keyPrev] = true
				}
			}
		}
	}

	// Step 2: Batch fetch Deduplicated Vulnerability Counts (Inline Logic)
	type VulnBuckets struct {
		crit, high, medium, low, total int
	}
	releaseVulns := make(map[string]VulnBuckets)

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
								FILTER cve.database_specific.cvss_base_score != null
								
								LET matchedAffected = (
									FOR affected IN cve.affected != null ? cve.affected : []
										LET cveBasePurl = affected.package.purl != null ? 
											affected.package.purl : 
											CONCAT("pkg:", LOWER(affected.package.ecosystem), "/", affected.package.name)
										FILTER cveBasePurl == purl.purl
										RETURN affected
								)
								
								RETURN {
									cve_id: cve.id,
									score: cve.database_specific.cvss_base_score
								}
				)

				// DEDUPLICATION: Group by CVE ID and take the MAX score
				LET uniqueCves = (
					FOR match IN cveMatches
						COLLECT cveId = match.cve_id INTO group
						LET score = MAX(group[*].match.score)
						RETURN { score }
				)
				
				RETURN {
					name: item.name,
					version: item.version,
					cves: uniqueCves
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

		type UniqueCVE struct {
			Score float64 `json:"score"`
		}
		type ReleaseVulnResult struct {
			Name    string      `json:"name"`
			Version string      `json:"version"`
			CVEs    []UniqueCVE `json:"cves"`
		}

		for vCursor.HasMore() {
			var r ReleaseVulnResult
			_, err := vCursor.ReadDocument(ctx, &r)
			if err != nil {
				continue
			}
			// Bucket in Go
			counts := VulnBuckets{}
			for _, cve := range r.CVEs {
				counts.total++
				if cve.Score >= 9.0 {
					counts.crit++
				} else if cve.Score >= 7.0 {
					counts.high++
				} else if cve.Score >= 4.0 {
					counts.medium++
				} else if cve.Score >= 0.1 {
					counts.low++
				}
			}
			releaseVulns[r.Name+":"+r.Version] = counts
		}
	}

	// Step 3: Aggregate globally
	aggCritical := struct{ count, delta int }{}
	aggHigh := struct{ count, delta int }{}
	aggMedium := struct{ count, delta int }{}
	aggLow := struct{ count, delta int }{}
	totalCount := 0
	totalDelta := 0

	for _, ep := range endpoints {
		for _, svc := range ep.Services {
			// Current State
			curr := releaseVulns[svc.Name+":"+svc.Current.Version]

			// Previous State
			prev := VulnBuckets{}
			if svc.Previous != nil {
				prev = releaseVulns[svc.Name+":"+svc.Previous.Version]
			}

			// Aggregate Critical
			aggCritical.count += curr.crit
			aggCritical.delta += (curr.crit - prev.crit)

			// Aggregate High
			aggHigh.count += curr.high
			aggHigh.delta += (curr.high - prev.high)

			// Aggregate Medium
			aggMedium.count += curr.medium
			aggMedium.delta += (curr.medium - prev.medium)

			// Aggregate Low
			aggLow.count += curr.low
			aggLow.delta += (curr.low - prev.low)

			// Total
			totalCount += curr.total
			totalDelta += (curr.total - prev.total)
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
