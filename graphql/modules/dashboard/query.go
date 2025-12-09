// Package dashboard defines the GraphQL queries for the dashboard.
package dashboard

import (
	"github.com/graphql-go/graphql"
	"github.com/ortelius/pdvd-backend/v12/database"
)

// GetQueryFields returns the dashboard queries to be mounted in the root schema
func GetQueryFields(db database.DBConnection) graphql.Fields {
	return graphql.Fields{
		// Section 1: Top Cards (Overview)
		"dashboardOverview": &graphql.Field{
			Type: DashboardOverviewType,
			Resolve: func(_ graphql.ResolveParams) (interface{}, error) {
				return ResolveOverview(db)
			},
		},
		// Section 2: Charts (Severity)
		"dashboardSeverity": &graphql.Field{
			Type: SeverityDistributionType,
			Resolve: func(_ graphql.ResolveParams) (interface{}, error) {
				return ResolveSeverityDistribution(db)
			},
		},
		// Section 3: Tables (Top Risks)
		"dashboardTopRisks": &graphql.Field{
			Type: graphql.NewList(RiskyAssetType),
			Args: graphql.FieldConfigArgument{
				"limit": &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 5},
				"type":  &graphql.ArgumentConfig{Type: graphql.String, DefaultValue: "endpoints"},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				limit := p.Args["limit"].(int)
				assetType := p.Args["type"].(string)
				return ResolveTopRisks(db, assetType, limit)
			},
		},
		// Section 4: Trend Line (Total Open Vulnerabilities)
		"dashboardVulnerabilityTrend": &graphql.Field{
			Type: graphql.NewList(VulnerabilityTrendType),
			Args: graphql.FieldConfigArgument{
				"days": &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 90},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				days := p.Args["days"].(int)
				return ResolveVulnerabilityTrend(db, days)
			},
		},
		// Section 5: Aggregated Endpoint Status with Deltas
		"dashboardGlobalStatus": &graphql.Field{
			Type: DashboardGlobalStatusType,
			Args: graphql.FieldConfigArgument{
				"limit": &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 100},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				limit := p.Args["limit"].(int)
				return ResolveDashboardGlobalStatus(db, limit)
			},
		},
	}
}
