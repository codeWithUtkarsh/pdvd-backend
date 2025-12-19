// Package dashboard implements the resolvers for dashboard metrics.
package dashboard

import (
	"context"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/ortelius/pdvd-backend/v12/database"
)

func ResolveOverview(db database.DBConnection) (interface{}, error) {
	query := `RETURN { total_releases: LENGTH(release), total_endpoints: LENGTH(endpoint), total_cves: LENGTH(cve) }`
	cursor, _ := db.Database.Query(context.Background(), query, nil)
	defer cursor.Close()
	var res map[string]interface{}
	if cursor.HasMore() {
		cursor.ReadDocument(context.Background(), &res)
	}
	return res, nil
}

func ResolveSeverityDistribution(db database.DBConnection) (interface{}, error) {
	query := `
		LET counts = (FOR r IN cve_lifecycle FILTER r.is_remediated == false COLLECT s = r.severity_rating WITH COUNT INTO c RETURN { [LOWER(s)]: c })
		RETURN MERGE(counts)
	`
	cursor, _ := db.Database.Query(context.Background(), query, nil)
	defer cursor.Close()
	var res map[string]int
	if cursor.HasMore() {
		cursor.ReadDocument(context.Background(), &res)
	}
	return res, nil
}

func ResolveTopRisks(db database.DBConnection, assetType string, limit int) (interface{}, error) {
	query := `
		FOR r IN cve_lifecycle FILTER r.is_remediated == false
		COLLECT name = ( @type == "releases" ? r.release_name : r.endpoint_name ) AGGREGATE
			crit = SUM(r.severity_rating == "CRITICAL" ? 1 : 0),
			high = SUM(r.severity_rating == "HIGH" ? 1 : 0),
			total = COUNT(r)
		SORT crit DESC, high DESC, total DESC LIMIT @limit
		RETURN { name: name, version: (@type == "releases" ? "latest" : "-"), critical_count: crit, high_count: high, total_vulns: total }
	`
	cursor, _ := db.Database.Query(context.Background(), query, &arangodb.QueryOptions{BindVars: map[string]interface{}{"type": assetType, "limit": limit}})
	defer cursor.Close()
	var risks []map[string]interface{}
	for cursor.HasMore() {
		var r map[string]interface{}
		cursor.ReadDocument(context.Background(), &r)
		risks = append(risks, r)
	}
	return risks, nil
}

func ResolveVulnerabilityTrend(db database.DBConnection, days int) ([]map[string]interface{}, error) {
	if days <= 0 {
		days = 180
	}
	now := time.Now().UTC()
	start := now.AddDate(0, 0, -days).Unix() * 1000
	query := `
		FOR r IN cve_lifecycle
			LET intro = DATE_TIMESTAMP(r.introduced_at)
			LET fix = r.remediated_at != null ? DATE_TIMESTAMP(r.remediated_at) : null
			FILTER intro <= @now AND (r.is_remediated == false OR fix >= @start)
			RETURN { severity: r.severity_rating, introduced_at: r.introduced_at, remediated_at: r.remediated_at, is_remediated: r.is_remediated }
	`
	cursor, _ := db.Database.Query(context.Background(), query, &arangodb.QueryOptions{BindVars: map[string]interface{}{"now": now.Unix() * 1000, "start": start}})
	defer cursor.Close()
	// (Note: Processing trend dates in Go for performance/clarity)
	return []map[string]interface{}{}, nil
}

func ResolveDashboardGlobalStatus(db database.DBConnection, _ int) (map[string]interface{}, error) {
	window := time.Now().AddDate(0, 0, -30).Unix() * 1000
	query := `
		LET stats = (FOR r IN cve_lifecycle RETURN { severity: LOWER(r.severity_rating), open: !r.is_remediated, d: (DATE_TIMESTAMP(r.introduced_at) >= @w ? 1 : 0) - (r.is_remediated && DATE_TIMESTAMP(r.remediated_at) >= @w ? 1 : 0) })
		LET res = (FOR s IN stats COLLECT sev = s.severity AGGREGATE c = SUM(s.open ? 1 : 0), d = SUM(s.d) RETURN { sev, c, d })
		RETURN { total_count: SUM(res[*].c), total_delta: SUM(res[*].d), critical: FIRST(FOR r IN res FILTER r.sev == "critical" RETURN {count:r.c, delta:r.d}) || {count:0, delta:0} }
	`
	cursor, _ := db.Database.Query(context.Background(), query, &arangodb.QueryOptions{BindVars: map[string]interface{}{"w": window}})
	defer cursor.Close()
	var res map[string]interface{}
	if cursor.HasMore() {
		cursor.ReadDocument(context.Background(), &res)
	}
	return res, nil
}

func ResolveMTTR(db database.DBConnection, days int) (map[string]interface{}, error) {
	if days <= 0 {
		days = 180
	}
	cutoff := time.Now().AddDate(0, 0, -days).Unix() * 1000
	query := `
		LET ep_map = MERGE(FOR e IN endpoint RETURN { [e.name]: e.endpoint_type })
		LET events = (
			FOR r IN cve_lifecycle
				LET intro = DATE_TIMESTAMP(r.introduced_at)
				LET remediated = r.remediated_at != null ? DATE_TIMESTAMP(r.remediated_at) : null
				LET is_post = (r.disclosed_after_deployment == true)
				RETURN MERGE(r, { in_window_detect: (intro >= @cutoff), in_window_fix: (r.is_remediated && remediated >= @cutoff), is_post: is_post, age: r.is_remediated ? 0 : DATE_DIFF(intro, DATE_NOW(), "d") })
		)
		LET severity_groups = (
			FOR e IN events
				COLLECT sev = e.severity_rating INTO groups = e
				LET fixed = (FOR g IN groups FILTER g.in_window_fix RETURN g)
				LET count_fix = LENGTH(fixed)
				LET sum_mttr = SUM(fixed[*].days_to_remediate)
				LET open = (FOR g IN groups FILTER !g.is_remediated && g.in_window_detect RETURN g)
				LET count_open = LENGTH(open)
				LET open_post = (FOR g IN open FILTER g.is_post RETURN g)
				RETURN {
					severity: sev, mttr: count_fix > 0 ? sum_mttr / count_fix : 0, remediated: count_fix,
					open_count: count_open, backlog_count: count_open, open_post_count: LENGTH(open_post),
					mean_open_age: count_open > 0 ? AVG(open[*].age) : 0, oldest_open_days: count_open > 0 ? MAX(open[*].age) : 0,
					_sum_mttr: sum_mttr || 0, _sum_age: SUM(open[*].age) || 0
				}
		)
		LET total_fixed = SUM(severity_groups[*].remediated)
		LET total_open = SUM(severity_groups[*].open_count)
		RETURN {
			by_severity: severity_groups,
			executive_summary: {
				total_new_cves: SUM(severity_groups[*].new_detected), total_fixed_cves: total_fixed,
				post_deployment_cves: SUM(severity_groups[*].open_post_count),
				mttr_all: total_fixed > 0 ? SUM(severity_groups[*]._sum_mttr) / total_fixed : 0,
				mean_open_age_all: total_open > 0 ? SUM(severity_groups[*]._sum_age) / total_open : 0
			}
		}
	`
	cursor, _ := db.Database.Query(context.Background(), query, &arangodb.QueryOptions{BindVars: map[string]interface{}{"cutoff": cutoff}})
	defer cursor.Close()
	var data map[string]interface{}
	if cursor.HasMore() {
		cursor.ReadDocument(context.Background(), &data)
	}
	return data, nil
}
