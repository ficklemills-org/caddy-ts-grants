// Copyright 2026 Ficklemills
// SPDX-License-Identifier: Apache-2.0

package caddytsgrants

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

const testCap = "example.com/cap/web"

func TestIsAllowed(t *testing.T) {
	tests := []struct {
		name         string
		host         string
		allowedHosts []string
		want         bool
	}{
		{"exact match", "app.example.com", []string{"app.example.com"}, true},
		{"exact mismatch", "admin.example.com", []string{"app.example.com"}, false},
		{"case insensitive", "App.Example.com", []string{"app.example.COM"}, true},
		{"wildcard matches single label", "admin.example.com", []string{"*.example.com"}, true},
		{"wildcard does not match multi-label", "a.b.example.com", []string{"*.example.com"}, false},
		{"wildcard does not match apex", "example.com", []string{"*.example.com"}, false},
		{"wildcard does not match empty label", ".example.com", []string{"*.example.com"}, false},
		{"wildcard does not match other domain", "app.example.org", []string{"*.example.com"}, false},
		{"wildcard does not match suffix lookalike", "app.badexample.com", []string{"*.example.com"}, false},
		{"bare star matches nothing", "app.example.com", []string{"*"}, false},
		{"host in second entry", "media.example.com", []string{"app.example.com", "media.example.com"}, true},
		{"empty allowedHosts", "app.example.com", []string{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAllowed(tc.host, tc.allowedHosts); got != tc.want {
				t.Errorf("isAllowed(%q, %v) = %v, want %v", tc.host, tc.allowedHosts, got, tc.want)
			}
		})
	}
}

func TestHostOnly(t *testing.T) {
	tests := []struct{ input, want string }{
		{"app.example.com", "app.example.com"},
		{"app.example.com:443", "app.example.com"},
		{"100.64.0.1:54321", "100.64.0.1"},
	}
	for _, tc := range tests {
		if got := hostOnly(tc.input); got != tc.want {
			t.Errorf("hostOnly(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestValidateCapability(t *testing.T) {
	for _, c := range []string{"example.com/cap/web", "sub.example.org/x"} {
		if err := validateCapability(c); err != nil {
			t.Errorf("validateCapability(%q) = %v, want nil", c, err)
		}
	}
	for _, c := range []string{"", "example.com", "example.com/", "localcap/web", "tailscale.com/cap/web"} {
		if err := validateCapability(c); err == nil {
			t.Errorf("validateCapability(%q) = nil, want error", c)
		}
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"argument", "ts_grants example.com/cap/web", testCap, false},
		{"block", "ts_grants {\n capability example.com/cap/web\n}", testCap, false},
		{"none", "ts_grants", "", false},
		{"two arguments", "ts_grants a.com/x b.com/y", "", true},
		{"unknown option", "ts_grants {\n hosts x\n}", "", true},
		{"capability without value", "ts_grants {\n capability\n}", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var g TsGrants
			err := g.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.input))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && g.Capability != tc.want {
				t.Errorf("Capability = %q, want %q", g.Capability, tc.want)
			}
		})
	}
}

func grant(hosts ...string) tailcfg.PeerCapMap {
	raw := `{"allowedHosts":[`
	for i, h := range hosts {
		if i > 0 {
			raw += ","
		}
		raw += `"` + h + `"`
	}
	raw += `]}`
	return tailcfg.PeerCapMap{testCap: {tailcfg.RawMessage(raw)}}
}

func user(caps tailcfg.PeerCapMap) *apitype.WhoIsResponse {
	return &apitype.WhoIsResponse{
		Node:        &tailcfg.Node{Name: "laptop.example.ts.net."},
		UserProfile: &tailcfg.UserProfile{LoginName: "alice@example.com"},
		CapMap:      caps,
	}
}

func taggedNode(caps tailcfg.PeerCapMap) *apitype.WhoIsResponse {
	return &apitype.WhoIsResponse{
		Node:   &tailcfg.Node{Name: "monitor.example.ts.net.", Tags: []string{"tag:monitoring"}},
		CapMap: caps,
	}
}

func TestServeHTTP(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		who        *apitype.WhoIsResponse
		whoErr     error
		wantStatus int // 0: passed to the next handler
		wantTagged bool
	}{
		{"user with grant", "app.example.com", user(grant("app.example.com")), nil, 0, false},
		{"user with grant and port", "app.example.com:443", user(grant("app.example.com")), nil, 0, false},
		{"user with wildcard grant", "app.example.com", user(grant("*.example.com")), nil, 0, false},
		{"user granted another host", "admin.example.com", user(grant("app.example.com")), nil, http.StatusForbidden, false},
		{"user without grant", "app.example.com", user(nil), nil, http.StatusForbidden, false},
		{"user with other capability only", "app.example.com", user(tailcfg.PeerCapMap{
			"example.com/cap/other": {`{"allowedHosts":["app.example.com"]}`},
		}), nil, http.StatusForbidden, false},
		{"user with malformed grant", "app.example.com", user(tailcfg.PeerCapMap{testCap: {`not json`}}), nil, http.StatusForbidden, false},
		{"tagged node with grant", "app.example.com", taggedNode(grant("app.example.com")), nil, 0, true},
		{"tagged node granted another host", "admin.example.com", taggedNode(grant("app.example.com")), nil, http.StatusForbidden, false},
		{"tagged node without grant", "app.example.com", taggedNode(nil), nil, http.StatusForbidden, false},
		{"lookup fails", "app.example.com", nil, errors.New("not a tailnet peer"), http.StatusInternalServerError, false},
		{"lookup returns no node", "app.example.com", &apitype.WhoIsResponse{}, nil, http.StatusInternalServerError, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := &TsGrants{
				Capability: testCap,
				logger:     zap.NewNop(),
				whoIs:      func(*http.Request) (*apitype.WhoIsResponse, error) { return tc.who, tc.whoErr },
			}
			vars := map[string]any{}
			r := httptest.NewRequest(http.MethodGet, "https://"+tc.host+"/", nil)
			r.Host = tc.host
			r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, vars))

			called := false
			next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
				called = true
				return nil
			})
			err := g.ServeHTTP(httptest.NewRecorder(), r, next)

			if tc.wantStatus == 0 {
				if err != nil || !called {
					t.Fatalf("want next handler called, got called=%v err=%v", called, err)
				}
			} else {
				var he caddyhttp.HandlerError
				if called || !errors.As(err, &he) || he.StatusCode != tc.wantStatus {
					t.Fatalf("want status %d, got called=%v err=%v", tc.wantStatus, called, err)
				}
			}
			if got := vars[TaggedVar] == true; got != tc.wantTagged {
				t.Errorf("%s = %v, want %v", TaggedVar, got, tc.wantTagged)
			}
		})
	}
}

func TestCaddyfileAdapt(t *testing.T) {
	input := `{
	auto_https off
}

(protected) {
	ts_grants {$TS_GRANTS_CAPABILITY}
	@human not vars ts_grants_tagged true
	respond @human "human"
}

http://app.example.com {
	import protected
	respond "tagged"
}
`
	t.Setenv("TS_GRANTS_CAPABILITY", testCap)
	out, warnings, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	if len(warnings) > 0 {
		t.Logf("warnings: %v", warnings)
	}
	if !strings.Contains(string(out), `{"capability":"`+testCap+`","handler":"ts_grants"}`) {
		t.Errorf("adapted config lacks ts_grants with the capability:\n%s", out)
	}
	var cfg caddy.Config
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	if err := caddy.Validate(&cfg); err != nil {
		t.Errorf("validate: %v", err)
	}
}
