// Copyright 2026 Ficklemills
// SPDX-License-Identifier: Apache-2.0
//
// Portions adapted from github.com/tailscale/caddy-tailscale (auth.go),
// Copyright (c) Tailscale Inc & contributors, licensed under Apache-2.0.
// Changed: the listener lookup returns a WhoIs result instead of a client.

package caddytsgrants

import (
	"net"
	"net/http"
	"reflect"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tsnet"
)

// tsnetListener is a listener backed by a tsnet.Server, as caddy-tailscale
// provides.
type tsnetListener interface {
	Server() *tsnet.Server
}

// wrappedListener is a listener that wraps another one, such as for TLS.
type wrappedListener interface {
	Unwrap() net.Listener
}

// whoIs looks up the peer that sent r. It asks the tsnet server of the
// caddy-tailscale listener that accepted the request, or the host's
// tailscaled when the server has no such listener.
func whoIs(r *http.Request) (*apitype.WhoIsResponse, error) {
	lc, err := localClient(r)
	if err != nil {
		return nil, err
	}
	return lc.WhoIs(r.Context(), r.RemoteAddr)
}

func localClient(r *http.Request) (*local.Client, error) {
	server, ok := r.Context().Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server)
	if !ok || server == nil {
		return new(local.Client), nil
	}
	for _, ln := range server.Listeners() {
		if tsl, ok := findTsnetListener(ln); ok {
			return tsl.Server().LocalClient()
		}
	}
	return new(local.Client), nil
}

// findTsnetListener unwraps nested listeners to find a tsnetListener.
func findTsnetListener(ln net.Listener) (_ tsnetListener, ok bool) {
	if ln == nil {
		return nil, false
	}
	if tsl, ok := ln.(tsnetListener); ok {
		return tsl, true
	}
	if wl, ok := ln.(wrappedListener); ok {
		return findTsnetListener(wl.Unwrap())
	}
	s := reflect.ValueOf(ln)
	if s.Kind() == reflect.Pointer {
		s = s.Elem()
	}
	if s.Kind() != reflect.Struct {
		return nil, false
	}
	inner := s.FieldByName("Listener")
	if !inner.IsValid() || inner.IsZero() {
		return nil, false
	}
	if wl, ok := inner.Interface().(net.Listener); ok {
		return findTsnetListener(wl)
	}
	return nil, false
}
