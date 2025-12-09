// Package dashboard defines the GraphQL types for the application dashboard.
package dashboard

import (
	"github.com/graphql-go/graphql"
)

// DashboardOverviewType represents the high-level metrics for the top cards
var DashboardOverviewType = graphql.NewObject(graphql.ObjectConfig{
	Name: "DashboardOverview",
	Fields: graphql.Fields{
		"total_releases":  &graphql.Field{Type: graphql.Int},
		"total_endpoints": &graphql.Field{Type: graphql.Int},
		"total_cves":      &graphql.Field{Type: graphql.Int},
	},
})

// SeverityDistributionType represents the data for the pie/bar charts
var SeverityDistributionType = graphql.NewObject(graphql.ObjectConfig{
	Name: "SeverityDistribution",
	Fields: graphql.Fields{
		"critical": &graphql.Field{Type: graphql.Int},
		"high":     &graphql.Field{Type: graphql.Int},
		"medium":   &graphql.Field{Type: graphql.Int},
		"low":      &graphql.Field{Type: graphql.Int},
	},
})

// RiskyAssetType represents rows for the "Top Risky" tables
var RiskyAssetType = graphql.NewObject(graphql.ObjectConfig{
	Name: "RiskyAsset",
	Fields: graphql.Fields{
		"name":           &graphql.Field{Type: graphql.String},
		"version":        &graphql.Field{Type: graphql.String},
		"critical_count": &graphql.Field{Type: graphql.Int},
		"high_count":     &graphql.Field{Type: graphql.Int},
		"total_vulns":    &graphql.Field{Type: graphql.Int},
	},
})

// VulnerabilityTrendType represents the daily count of vulnerabilities from sync events
var VulnerabilityTrendType = graphql.NewObject(graphql.ObjectConfig{
	Name: "VulnerabilityTrend",
	Fields: graphql.Fields{
		"date":     &graphql.Field{Type: graphql.String},
		"critical": &graphql.Field{Type: graphql.Int},
		"high":     &graphql.Field{Type: graphql.Int},
		"medium":   &graphql.Field{Type: graphql.Int},
		"low":      &graphql.Field{Type: graphql.Int},
	},
})

// SeverityMetricType represents a count and its delta for a specific severity
var SeverityMetricType = graphql.NewObject(graphql.ObjectConfig{
	Name: "SeverityMetric",
	Fields: graphql.Fields{
		"count": &graphql.Field{Type: graphql.Int},
		"delta": &graphql.Field{Type: graphql.Int},
	},
})

// DashboardGlobalStatusType represents the aggregated vulnerability status across all endpoints
var DashboardGlobalStatusType = graphql.NewObject(graphql.ObjectConfig{
	Name: "DashboardGlobalStatus",
	Fields: graphql.Fields{
		"critical":    &graphql.Field{Type: SeverityMetricType},
		"high":        &graphql.Field{Type: SeverityMetricType},
		"medium":      &graphql.Field{Type: SeverityMetricType},
		"low":         &graphql.Field{Type: SeverityMetricType},
		"total_count": &graphql.Field{Type: graphql.Int},
		"total_delta": &graphql.Field{Type: graphql.Int},
	},
})
