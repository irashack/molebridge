//go:build !drill

package exit

import "testing"

func TestTheReleaseBuildHasMultiProviderExitsOff(t *testing.T) {
	if multiProviderAvailable {
		t.Fatal("multi-provider exits are on in the release build")
	}
}
