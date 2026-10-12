package oidc

// Shared fixtures for the tests ported from panel/test_oidc.py. All names and
// addresses are fictitious and every connection stays on loopback.

const (
	testClientID  = "switchyard-test"
	testIssuer    = "https://idp.example.test"
	testPublicURL = "https://exit.example.test"
)

var testExitIDs = []string{"mine", "a", "b"}

// envFor is a valid sign-in environment; a value override of nil removes
// that setting.
func envFor(issuer string, overrides map[string]*string) map[string]string {
	env := map[string]string{
		"PANEL_OIDC_ISSUER": issuer, "PANEL_OIDC_CLIENT_ID": testClientID, "PANEL_PUBLIC_URL": testPublicURL,
		"PANEL_ADMIN_GROUPS": "admins", "PANEL_ACCESS": "friends-a=a,friends-b=b",
	}
	for k, v := range overrides {
		if v == nil {
			delete(env, k)
		} else {
			env[k] = *v
		}
	}
	return env
}

func ptr(s string) *string { return &s }

// o builds an override map from alternating names and values; a value of
// "\x00" removes the setting.
func o(pairs ...string) map[string]*string {
	m := map[string]*string{}
	for i := 0; i < len(pairs); i += 2 {
		if pairs[i+1] == "\x00" {
			m[pairs[i]] = nil
		} else {
			m[pairs[i]] = ptr(pairs[i+1])
		}
	}
	return m
}
