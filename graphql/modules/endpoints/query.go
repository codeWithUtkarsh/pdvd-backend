package endpoints

import (
	"github.com/graphql-go/graphql"
	"github.com/ortelius/pdvd-backend/v12/database"
)

func GetQueryFields(db database.DBConnection, syncedEndpointType *graphql.Object, endpointDetailsType *graphql.Object) graphql.Fields {
	return graphql.Fields{
		"syncedEndpoints": &graphql.Field{
			Type: graphql.NewList(syncedEndpointType),
			Args: graphql.FieldConfigArgument{
				"limit": &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 1000},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				limit := p.Args["limit"].(int)
				return ResolveSyncedEndpoints(db, limit)
			},
		},
		"endpointDetails": &graphql.Field{
			Type: endpointDetailsType,
			Args: graphql.FieldConfigArgument{
				"name": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				name := p.Args["name"].(string)
				return ResolveEndpointDetails(db, name)
			},
		},
	}
}
