// Copyright 2026 Ficklemills
// SPDX-License-Identifier: Apache-2.0

// Package caddytsgrants provides ts_grants, a Caddy HTTP handler that
// authorizes requests from Tailscale peers against app capability grants
// in the tailnet policy file.
package caddytsgrants

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

// TaggedVar is the Caddy variable ts_grants sets to true when it allows a
// request from a tagged node. Match it with the vars matcher, for example to
// skip tailscale_auth, which rejects tagged nodes. Clients cannot set it.
const TaggedVar = "ts_grants_tagged"

func init() {
	caddy.RegisterModule(TsGrants{})
	httpcaddyfile.RegisterHandlerDirective("ts_grants", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("ts_grants", httpcaddyfile.Before, "basic_auth")
}

// TsGrants allows a request only if the Tailscale peer that sent it holds a
// grant of Capability whose allowedHosts covers the request's host. It looks
// up the peer with WhoIs on the connection's remote address, so Caddy must
// accept the connection from the tailnet directly: on a caddy-tailscale
// (tsnet) listener, or on the host's tailscaled with real peer addresses.
// Behind another proxy, every request carries the proxy's identity.
//
// Users and tagged nodes are checked the same way. Anything without a
// matching grant is denied (403); a failed identity lookup is an error (500).
type TsGrants struct {
	// Capability is the app capability name to read grants from, in the
	// form "<domain>/<path>", such as "example.com/cap/web". Required.
	// Placeholders such as {env.TS_GRANTS_CAPABILITY} are expanded.
	Capability string `json:"capability,omitempty"`

	logger *zap.Logger
	whoIs  func(*http.Request) (*apitype.WhoIsResponse, error)
}

// CaddyModule returns the Caddy module information.
func (TsGrants) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ts_grants",
		New: func() caddy.Module { return new(TsGrants) },
	}
}

// Provision sets up the handler.
func (g *TsGrants) Provision(ctx caddy.Context) error {
	g.logger = ctx.Logger()
	g.Capability = caddy.NewReplacer().ReplaceKnown(g.Capability, "")
	if g.whoIs == nil {
		g.whoIs = whoIs
	}
	return nil
}

// Validate checks the capability name.
func (g *TsGrants) Validate() error {
	return validateCapability(g.Capability)
}

func validateCapability(c string) error {
	if c == "" {
		return fmt.Errorf("ts_grants: capability is required, such as example.com/cap/web")
	}
	domain, path, ok := strings.Cut(c, "/")
	if !ok || path == "" || !strings.Contains(domain, ".") {
		return fmt.Errorf("ts_grants: capability %q must have the form <domain>/<path>", c)
	}
	if domain == "tailscale.com" {
		return fmt.Errorf("ts_grants: capability %q: tailscale.com is reserved for Tailscale", c)
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (g *TsGrants) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	who, err := g.whoIs(r)
	if err != nil || who == nil || who.Node == nil {
		g.logger.Error("identity lookup failed", zap.String("remote_addr", r.RemoteAddr), zap.Error(err))
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("identity lookup failed"))
	}

	host := hostOnly(r.Host)
	tagged := who.Node.IsTagged()
	identity := zap.String("node", who.Node.Name)
	if !tagged && who.UserProfile != nil {
		identity = zap.String("user", who.UserProfile.LoginName)
	}

	allowedHosts := extractAllowedHosts(who.CapMap[tailcfg.PeerCapability(g.Capability)], g.logger)
	if !isAllowed(host, allowedHosts) {
		g.logger.Info("denied", identity, zap.Bool("tagged", tagged),
			zap.String("host", host), zap.Strings("allowed_hosts", allowedHosts))
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("no grant for host %s", host))
	}

	g.logger.Debug("allowed", identity, zap.Bool("tagged", tagged), zap.String("host", host))
	if tagged {
		caddyhttp.SetVar(r.Context(), TaggedVar, true)
	}
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//	ts_grants [<capability>] {
//	    capability <capability>
//	}
func (g *TsGrants) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // directive name
	if d.NextArg() {
		g.Capability = d.Val()
	}
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		switch d.Val() {
		case "capability":
			if !d.NextArg() {
				return d.ArgErr()
			}
			g.Capability = d.Val()
			if d.NextArg() {
				return d.ArgErr()
			}
		default:
			return d.Errf("unrecognized ts_grants option %q", d.Val())
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	g := new(TsGrants)
	err := g.UnmarshalCaddyfile(h.Dispenser)
	return g, err
}

// extractAllowedHosts collects allowedHosts from every grant of the capability.
func extractAllowedHosts(caps []tailcfg.RawMessage, logger *zap.Logger) []string {
	var allowedHosts []string
	for _, raw := range caps {
		var entry struct {
			AllowedHosts []string `json:"allowedHosts"`
		}
		if err := json.Unmarshal([]byte(raw), &entry); err != nil {
			logger.Error("failed to parse grant", zap.Error(err))
			continue
		}
		allowedHosts = append(allowedHosts, entry.AllowedHosts...)
	}
	return allowedHosts
}

// isAllowed reports whether host is permitted by allowedHosts. An entry is an
// exact host name or "*.<domain>", which matches exactly one label below
// <domain> (not <domain> itself, not deeper names). Comparison ignores case.
func isAllowed(host string, allowedHosts []string) bool {
	host = strings.ToLower(host)
	for _, allowed := range allowedHosts {
		allowed = strings.ToLower(allowed)
		if allowed == host {
			return true
		}
		if suffix, ok := strings.CutPrefix(allowed, "*"); ok && strings.HasPrefix(suffix, ".") {
			label, found := strings.CutSuffix(host, suffix)
			if found && label != "" && !strings.Contains(label, ".") {
				return true
			}
		}
	}
	return false
}

func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// Interface guards
var (
	_ caddy.Module                = (*TsGrants)(nil)
	_ caddy.Provisioner           = (*TsGrants)(nil)
	_ caddy.Validator             = (*TsGrants)(nil)
	_ caddyhttp.MiddlewareHandler = (*TsGrants)(nil)
	_ caddyfile.Unmarshaler       = (*TsGrants)(nil)
)
