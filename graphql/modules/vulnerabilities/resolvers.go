package vulnerabilities

import (
	"context"

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

func ResolveVulnerabilities(db database.DBConnection, limit int) ([]map[string]interface{}, error) {
	ctx := context.Background()

	query := `
		LET vulnData = (
			FOR release IN release
				FOR sbomEdge IN 1..1 OUTBOUND release release2sbom
					FOR purlEdge IN sbom2purl
						FILTER purlEdge._from == sbomEdge._id
						LET purl = DOCUMENT(purlEdge._to)
						FILTER purl != null
						
						FOR cveEdge IN cve2purl
							FILTER cveEdge._to == purl._id
							
							FILTER (
								purlEdge.version_major != null AND 
								cveEdge.introduced_major != null AND 
								(cveEdge.fixed_major != null OR cveEdge.last_affected_major != null)
							) ? (
								(purlEdge.version_major > cveEdge.introduced_major OR
								 (purlEdge.version_major == cveEdge.introduced_major AND 
								  purlEdge.version_minor > cveEdge.introduced_minor) OR
								 (purlEdge.version_major == cveEdge.introduced_major AND 
								  purlEdge.version_minor == cveEdge.introduced_minor AND 
								  purlEdge.version_patch >= cveEdge.introduced_patch))
								AND
								(cveEdge.fixed_major != null ? (
									purlEdge.version_major < cveEdge.fixed_major OR
									(purlEdge.version_major == cveEdge.fixed_major AND 
									 purlEdge.version_minor < cveEdge.fixed_minor) OR
									(purlEdge.version_major == cveEdge.fixed_major AND 
									 purlEdge.version_minor == cveEdge.fixed_minor AND 
									 purlEdge.version_patch < cveEdge.fixed_patch)
								) : (
									purlEdge.version_major < cveEdge.last_affected_major OR
									(purlEdge.version_major == cveEdge.last_affected_major AND 
									 purlEdge.version_minor < cveEdge.last_affected_minor) OR
									(purlEdge.version_major == cveEdge.last_affected_major AND 
									 purlEdge.version_minor == cveEdge.last_affected_minor AND 
									 purlEdge.version_patch <= cveEdge.last_affected_patch)
								))
							) : true
							
							LET cve = DOCUMENT(cveEdge._from)
							FILTER cve != null
							FILTER cve.database_specific.cvss_base_score != null
							
							LET matchedAffected = (
								FOR affected IN cve.affected != null ? cve.affected : []
									FILTER affected.package != null
									LET cveBasePurl = affected.package.purl != null ? 
										affected.package.purl : 
										CONCAT("pkg:", LOWER(affected.package.ecosystem), "/", affected.package.name)
									FILTER cveBasePurl == purl.purl
									RETURN affected
							)
							
							FILTER LENGTH(matchedAffected) > 0
							
							RETURN {
								cve_id: cve.id,
								package: purl.purl,
								affected_version: purlEdge.version,
								full_purl: purlEdge.full_purl,
								summary: cve.summary,
								severity_score: cve.database_specific.cvss_base_score,
								severity_rating: cve.database_specific.severity_rating,
								release_name: release.name,
								release_version: release.version,
								all_affected: matchedAffected,
								needs_validation: purlEdge.version_major == null OR cveEdge.introduced_major == null
							}
		)
		
		FOR vuln IN vulnData
			COLLECT 
				cve_id = vuln.cve_id,
				package = vuln.package,
				affected_version = vuln.affected_version
			AGGREGATE 
				summaries = UNIQUE(vuln.summary),
				severity_scores = UNIQUE(vuln.severity_score),
				severity_ratings = UNIQUE(vuln.severity_rating),
				releaseList = UNIQUE(CONCAT(vuln.release_name, ":", vuln.release_version)),
				full_purls = UNIQUE(vuln.full_purl),
				all_affected_data = UNIQUE(vuln.all_affected),
				needs_validation_flags = UNIQUE(vuln.needs_validation)
			
			LET endpointCount = LENGTH(
				FOR rel_str IN releaseList
					LET parts = SPLIT(rel_str, ":")
					FOR sync IN sync
						FILTER sync.release_name == parts[0] AND sync.release_version == parts[1]
						LIMIT 1
						RETURN 1
			)
			
			LET max_severity_score = MAX(severity_scores)
			
			SORT max_severity_score DESC
			LIMIT @limit
			
			RETURN {
				cve_id: cve_id,
				summary: FIRST(summaries) != null ? FIRST(summaries) : "",
				severity_score: max_severity_score,
				severity_rating: FIRST(severity_ratings) != null ? FIRST(severity_ratings) : "UNKNOWN",
				package: package,
				affected_version: affected_version,
				full_purl: FIRST(full_purls),
				affected_releases: LENGTH(releaseList),
				affected_endpoints: endpointCount,
				affected_data: FIRST(all_affected_data),
				needs_validation: FIRST(needs_validation_flags)
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

	type VulnerabilityResult struct {
		CveID             string            `json:"cve_id"`
		Summary           string            `json:"summary"`
		SeverityScore     float64           `json:"severity_score"`
		SeverityRating    string            `json:"severity_rating"`
		Package           string            `json:"package"`
		AffectedVersion   string            `json:"affected_version"`
		FullPurl          string            `json:"full_purl"`
		AffectedReleases  int               `json:"affected_releases"`
		AffectedEndpoints int               `json:"affected_endpoints"`
		AllAffected       []models.Affected `json:"all_affected"`
		NeedsValidation   bool              `json:"needs_validation"`
	}

	var vulnerabilities []map[string]interface{}
	seen := make(map[string]bool)

	for cursor.HasMore() {
		var result VulnerabilityResult
		_, err := cursor.ReadDocument(ctx, &result)
		if err != nil {
			continue
		}

		if result.NeedsValidation {
			if !isVersionAffectedAny(result.AffectedVersion, result.AllAffected) {
				continue
			}
		}

		key := result.CveID + ":" + result.Package + ":" + result.AffectedVersion
		if seen[key] {
			continue
		}
		seen[key] = true

		vulnerabilities = append(vulnerabilities, map[string]interface{}{
			"cve_id":             result.CveID,
			"summary":            result.Summary,
			"severity_score":     result.SeverityScore,
			"severity_rating":    result.SeverityRating,
			"package":            result.Package,
			"affected_version":   result.AffectedVersion,
			"full_purl":          result.FullPurl,
			"fixed_in":           util.ExtractApplicableFixedVersion(result.AffectedVersion, result.AllAffected),
			"affected_releases":  result.AffectedReleases,
			"affected_endpoints": result.AffectedEndpoints,
		})
	}
	return vulnerabilities, nil
}
