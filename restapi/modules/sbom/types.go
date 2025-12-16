// Package sbom defines the REST API types for SBOM operations.
package sbom

// edgeInfo holds edge information for batch processing
type EdgeInfo struct {
	From     string
	To       string
	Version  string
	FullPurl string
}

// purlInfo holds PURL information for batch processing
type PurlInfo struct {
	BasePurl     string
	Version      string
	FullPurl     string
	VersionMajor *int
	VersionMinor *int
	VersionPatch *int
	Ecosystem    string
}
