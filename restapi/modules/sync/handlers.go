// Package sync handles the synchronization of release and CVE data.
// It processes SBOMs and updates CVE lifecycle tracking using the shared lifecycle package.
package sync

import (
	"context"
	"fmt"
	"time"

	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/lifecycle"
)

// ProcessSync handles a sync event and updates lifecycle tracking.
// This is called whenever a new version is deployed.
func ProcessSync(
	ctx context.Context,
	db database.DBConnection,
	endpointName string,
	releaseName string,
	releaseVersion string,
	sbomCVEs []lifecycle.CVEInfo,
	syncedAt time.Time,
) error {
	
	fmt.Printf("Processing sync: %s/%s version %s\n",
		endpointName, releaseName, releaseVersion)
	
	// Step 1: Find previous version (if any)
	previousVersion, err := lifecycle.GetPreviousVersion(
		ctx, db,
		releaseName, endpointName,
		syncedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to get previous version: %w", err)
	}
	
	isFirstDeployment := previousVersion == ""
	if isFirstDeployment {
		fmt.Printf("  First deployment of %s\n", releaseName)
	} else {
		fmt.Printf("  Upgrading from %s to %s\n", previousVersion, releaseVersion)
	}
	
	// Step 2: Create lifecycle records for all CVEs in this version
	currentCVEMap := make(map[string]lifecycle.CVEInfo)
	
	for _, cve := range sbomCVEs {
		key := fmt.Sprintf("%s:%s", cve.CVEID, cve.Package)
		currentCVEMap[key] = cve
		
		// Determine if this CVE was disclosed after deployment
		disclosedAfter := !cve.Published.IsZero() && cve.Published.After(syncedAt)
		
		// CRITICAL: Use shared lifecycle package
		err := lifecycle.CreateOrUpdateLifecycleRecord(
			ctx, db,
			endpointName,
			releaseName,
			releaseVersion,
			cve,
			syncedAt,        // ✅ Actual sync time
			disclosedAfter,
		)
		
		if err != nil {
			return fmt.Errorf("failed to create lifecycle record for %s: %w", cve.CVEID, err)
		}
	}
	
	fmt.Printf("  Created/updated %d lifecycle records\n", len(sbomCVEs))
	
	// Step 3: If not first deployment, compare versions and mark remediations
	if !isFirstDeployment {
		remediatedCount, err := lifecycle.CompareAndMarkRemediations(
			ctx, db,
			endpointName, releaseName,
			previousVersion, releaseVersion,
			currentCVEMap,
			syncedAt,
		)
		
		if err != nil {
			return fmt.Errorf("failed to compare versions: %w", err)
		}
		
		fmt.Printf("  Marked %d CVEs as remediated\n", remediatedCount)
	}
	
	return nil
}
