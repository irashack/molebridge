//go:build drill

package exit

import "testing"

func TestTheDrillBuildHasMultiProviderExitsOn(t *testing.T) {
	if !multiProviderAvailable {
		t.Fatal("multi-provider exits are off in the drill build")
	}
}
