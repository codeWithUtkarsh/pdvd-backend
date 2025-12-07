# Modular GraphQL Schema Architecture

This directory contains a modular GraphQL schema implementation following Relay/GraphQL best practices.

## Directory Structure

```
graphql/
├── schema.go                    # Main schema assembly point
└── modules/
    ├── releases/
    │   ├── type.go             # Release, SBOM, AffectedRelease types
    │   ├── resolvers.go        # Release data fetching logic
    │   └── query.go            # Release query fields
    ├── vulnerabilities/
    │   ├── type.go             # Vulnerability, VulnerabilityCount types
    │   ├── resolvers.go        # Vulnerability analysis logic
    │   └── query.go            # Vulnerability query fields
    ├── endpoints/
    │   ├── type.go             # Endpoint types and EndpointDetails
    │   ├── resolvers.go        # Endpoint data fetching logic
    │   └── query.go            # Endpoint query fields
    └── scorecard/
        └── type.go             # Scorecard types
        
Note: The scorecard module only contains type definitions. Scorecard data is accessed through the `release.scorecard_result` field, not through dedicated queries.
```

## Module Organization

Each module follows a consistent three-file pattern:

### 1. `type.go`
Defines GraphQL object types for the domain:
- Object types (e.g., `ReleaseType`, `VulnerabilityType`)
- Input types
- Enum types
- Interfaces (if needed)

**Key Feature**: Uses factory functions (e.g., `GetReleaseType()`) to handle circular dependencies between modules.

### 2. `resolvers.go`
Contains business logic for fetching and processing data:
- Database queries (ArangoDB AQL)
- Data transformation
- Validation logic
- Utility functions

**Example**: `ResolveReleaseVulnerabilities()`, `ResolveEndpointDetails()`

### 3. `query.go`
Exports query fields to be assembled in the root schema:
- Query field definitions
- Argument specifications
- Connection to resolver functions

**Example**: `GetQueryFields()` returns a `graphql.Fields` map

## Schema Assembly (`schema.go`)

The main schema file orchestrates all modules:

1. **Initialize database**: `InitDB()` sets up the database connection
2. **Create base types**: Start with types that have no circular dependencies
3. **Inject dependencies**: Pass required types to factory functions
4. **Merge query fields**: Combine fields from all modules
5. **Build schema**: Create the final GraphQL schema

### Dependency Injection Pattern

To handle circular dependencies between modules:

```go
// Endpoints depend on Vulnerabilities
syncedEndpointType, endpointDetailsType := endpoints.GetEndpointTypes(
    vulnerabilityCountType,
    vulnerabilityType,
)

// Releases depend on Vulnerabilities, Endpoints, and Scorecard
releaseType := releases.GetReleaseType(
    db,
    vulnerabilityType,
    affectedEndpointType,
    scorecardResultType,
)
```

## Available Queries

### Releases Module
- `release(name: String!, version: String!)`: Get specific release details
- `affectedReleases(severity: Severity!, limit: Int)`: List releases affected by vulnerabilities

### Vulnerabilities Module
- `vulnerabilities(limit: Int)`: List all vulnerabilities with mitigation info

### Endpoints Module
- `syncedEndpoints(limit: Int)`: List all endpoints with sync status
- `endpointDetails(name: String!)`: Get detailed endpoint information

### Scorecard Module
- (Reserved for future queries)

## Key Design Decisions

### 1. Separation of Concerns
Each domain (releases, vulnerabilities, endpoints, scorecard) is isolated in its own module, making the codebase easier to navigate and maintain.

### 2. No Circular Imports
Using dependency injection (factory functions) prevents Go import cycles while allowing types to reference each other.

### 3. Consistent Patterns
Every module follows the same three-file structure (type, resolvers, query), making it predictable where to find functionality.

### 4. Testability
Each module can be tested independently with mocked database connections and type dependencies.

### 5. Scalability
New modules can be added without modifying existing code - just create the three files and register queries in `schema.go`.

## Adding a New Module

To add a new domain module (e.g., `packages`):

1. Create directory: `mkdir graphql/modules/packages`

2. Create `type.go`:
```go
package packages

import "github.com/graphql-go/graphql"

var PackageType = graphql.NewObject(graphql.ObjectConfig{
    Name: "Package",
    Fields: graphql.Fields{
        "name": &graphql.Field{Type: graphql.String},
        // ... more fields
    },
})
```

3. Create `resolvers.go`:
```go
package packages

import "github.com/ortelius/pdvd-backend/v12/database"

func ResolvePackages(db database.DBConnection) ([]map[string]interface{}, error) {
    // Implementation
}
```

4. Create `query.go`:
```go
package packages

import "github.com/graphql-go/graphql"

func GetQueryFields(db database.DBConnection, packageType *graphql.Object) graphql.Fields {
    return graphql.Fields{
        "packages": &graphql.Field{
            Type: graphql.NewList(packageType),
            Resolve: func(p graphql.ResolveParams) (interface{}, error) {
                return ResolvePackages(db)
            },
        },
    }
}
```

5. Register in `schema.go`:
```go
import "github.com/ortelius/pdvd-backend/v12/graphql/modules/packages"

// In CreateSchema():
packageType := packages.PackageType

for k, v := range packages.GetQueryFields(db, packageType) {
    queryFields[k] = v
}
```

## Integration with Existing Code

### Backend Integration

Replace the existing `schema.go` with this modular structure:

```go
import "github.com/ortelius/pdvd-backend/v12/graphql"

// Initialize database connection
graphql.InitDB(dbConn)

// Create schema
schema, err := graphql.CreateSchema()
if err != nil {
    log.Fatal(err)
}

// Use schema with HTTP handler
h := handler.New(&handler.Config{
    Schema: &schema,
    Pretty: true,
})
```

### Frontend Integration

No changes required - the GraphQL API surface remains identical:

```graphql
query {
  release(name: "myapp", version: "1.0.0") {
    name
    version
    vulnerabilities {
      cve_id
      severity_rating
    }
  }
}
```

## Performance Considerations

### Query Optimization
- All resolvers use indexed fields for filtering (version components, edges)
- Vulnerability matching uses semantic versioning comparisons
- COLLECT operations minimize data transfer from database
- Duplicate CVEs are deduplicated in resolvers

### Caching Opportunities
- Release metadata rarely changes - cache for 5-10 minutes
- Vulnerability data updates daily - cache for 1 hour
- Endpoint sync status changes frequently - cache for 30 seconds

## Testing Strategy

### Unit Tests
Test individual resolvers with mocked database:

```go
func TestResolveReleaseVulnerabilities(t *testing.T) {
    mockDB := &MockDBConnection{}
    // ... setup mock responses
    
    vulns, err := releases.ResolveReleaseVulnerabilities(mockDB, "app", "1.0.0")
    
    assert.NoError(t, err)
    assert.Equal(t, 5, len(vulns))
}
```

### Integration Tests
Test complete schema assembly:

```go
func TestSchemaCreation(t *testing.T) {
    graphql.InitDB(testDB)
    schema, err := graphql.CreateSchema()
    
    assert.NoError(t, err)
    assert.NotNil(t, schema)
    
    // Test query execution
    result := graphql.Do(graphql.Params{
        Schema: schema,
        RequestString: `{ release(name: "test", version: "1.0") { name } }`,
    })
    
    assert.False(t, result.HasErrors())
}
```

### End-to-End Tests
Test GraphQL HTTP endpoint:

```go
func TestGraphQLEndpoint(t *testing.T) {
    req := httptest.NewRequest("POST", "/api/v1/graphql", body)
    w := httptest.NewRecorder()
    
    handler.ServeHTTP(w, req)
    
    assert.Equal(t, 200, w.Code)
    // ... assert response
}
```

## Migration Guide

### From Monolithic schema.go

1. **Backup existing**: `cp schema.go schema.go.backup`

2. **Copy modules**: Copy the `graphql/` directory to your backend

3. **Update imports**: Change GraphQL handler setup to use new package

4. **Test queries**: Run existing GraphQL queries to verify compatibility

5. **Update CI/CD**: Ensure build process includes new directory structure

6. **Deploy**: Deploy with zero downtime (API is backwards compatible)

### Rollback Plan

If issues occur, simply revert to the original `schema.go.backup` file - the API surface is identical.

## Benefits of This Architecture

### For Development
- **Easier onboarding**: New developers can understand one module at a time
- **Faster debugging**: Issues are isolated to specific modules
- **Better IDE support**: Smaller files with clear responsibilities
- **Cleaner git diffs**: Changes affect fewer files

### For Maintenance
- **Independent testing**: Test modules in isolation
- **Refactoring safety**: Changes to one module don't break others
- **Performance tuning**: Optimize specific resolvers without risk
- **Documentation**: Each module can have its own docs

### For Operations
- **Debugging**: Logs and errors reference specific modules
- **Monitoring**: Track performance per module
- **Scaling**: Identify and optimize slow resolvers
- **Security**: Audit permissions per module

## Related Documentation

- [GraphQL Schema Design Best Practices](https://graphql.org/learn/schema/)
- [Relay GraphQL Server Specification](https://relay.dev/docs/guides/graphql-server-specification/)
- [ArangoDB AQL Documentation](https://www.arangodb.com/docs/stable/aql/)
- [go-graphql Documentation](https://github.com/graphql-go/graphql)

## Support

For questions or issues with the modular GraphQL structure:
1. Check the module's `resolvers.go` for implementation details
2. Review AQL queries for database interaction logic
3. Examine `type.go` for GraphQL schema definitions
4. See `schema.go` for how modules are assembled

## Future Enhancements

Potential additions to this architecture:

- **Mutations**: Add `mutation.go` files to each module
- **Subscriptions**: Add real-time updates for vulnerability changes
- **DataLoader**: Batch and cache related data fetches
- **Field-level auth**: Add permission checks to resolvers
- **Schema stitching**: Federate with external GraphQL services
- **Code generation**: Auto-generate TypeScript types from schema
