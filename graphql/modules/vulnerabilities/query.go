package vulnerabilities

import (
	"github.com/graphql-go/graphql"
	"github.com/ortelius/pdvd-backend/v12/database"
)

func GetQueryFields(db database.DBConnection) graphql.Fields {
	return graphql.Fields{
		"vulnerabilities": &graphql.Field{
			Type: graphql.NewList(MitigationType),
			Args: graphql.FieldConfigArgument{
				"limit": &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 1000},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				limit := p.Args["limit"].(int)
				return ResolveVulnerabilities(db, limit)
			},
		},
	}
}
