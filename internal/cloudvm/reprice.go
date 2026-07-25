package cloudvm

import "github.com/d0cd/dispatcher/internal/adapter"

// RepriceInstancesLive overrides each instance resource's MonthlyUSD with a live
// catalog price when the catalog has one, so gc's ongoing-cost estimate tracks
// live rates instead of the static rate card. This matters most for GPU
// instances, whose prices drift the most and whose static rows go stale.
// Non-instance resources (disks/images/IPs) and instances the live catalog does
// not price are left unchanged. A nil live catalog is a no-op (offline or live
// pricing disabled → keep the static estimates rather than zero them).
func RepriceInstancesLive(resources []adapter.ResourceInfo, live *Catalog) {
	if live == nil {
		return
	}
	for i := range resources {
		r := &resources[i]
		if r.Kind != adapter.ResourceInstance || r.InstanceType == "" {
			continue
		}
		if price := live.PriceByName(ProviderID(r.Provider), r.InstanceType); price > 0 {
			r.MonthlyUSD = price * gcpMonthlyHours
		}
	}
}
