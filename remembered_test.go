package tectonic_test

import (
	"context"
	"testing"
	"time"

	"github.com/pangeavpn/tectonic"
)

// A weaker mode remembered before the node had a cover domain was chosen
// without Own on offer. Once the profile has one, the client tries Own again
// and remembers it; a weaker mode remembered with the same cover domain (Own
// was tried then and failed) is kept, until it is old enough that the client
// looks again, so one reset doesn't settle a network for good.
func TestRememberedModeRetriesOwnOnceOffered(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cover string        // the remembered choice's cover domain
		age   time.Duration // how long ago it was chosen
		want  tectonic.SNIMode
	}{
		{"borrowed before Own existed", "", 0, tectonic.SNIOwn},
		{"borrowed under another cover domain", "old.cover.test", 0, tectonic.SNIOwn},
		{"borrowed after Own failed here", coverDomain, time.Minute, tectonic.SNIBorrowed},
		{"borrowed long enough ago to look again", coverDomain, tectonic.WeakerModeFor + time.Minute, tectonic.SNIOwn},
		{"borrowed with no time at all", coverDomain, 0, tectonic.SNIOwn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modes := tectonic.NewMemoryModeStore()
			remembered := tectonic.Choice{Mode: tectonic.SNIBorrowed, Name: "allowed.example", Cover: tc.cover}
			if tc.age > 0 {
				remembered.At = time.Now().Add(-tc.age)
			}
			modes.SetMode("home", remembered)
			_, _, c, _ := tunnel(t, func(cfg *tectonic.Config) {
				cfg.Modes = modes
				cfg.Network = "home"
			})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := c.WaitForSession(ctx, 0); err != nil {
				t.Fatal(err)
			}
			got, _ := modes.Mode("home")
			if got.Mode != tc.want || c.Stats().Mode.Mode != tc.want {
				t.Fatalf("remembered %+v, stats %+v; want %v", got, c.Stats().Mode, tc.want)
			}
			if tc.want == tectonic.SNIOwn && got.Cover != coverDomain {
				t.Fatalf("remembered %+v without the cover domain", got)
			}
		})
	}
}
