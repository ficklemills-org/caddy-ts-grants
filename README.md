# caddy-ts-grants

A [Caddy](https://caddyserver.com) HTTP handler that decides which Tailscale
users and tagged nodes may reach which sites, using
[app capabilities](https://tailscale.com/docs/features/access-control/grants/grants-app-capabilities) granted
in your tailnet policy file. The policy file stays the single source of truth:
no access lists live in the Caddyfile.

Tailscale's network grants decide who can reach Caddy on port 443. They cannot
tell one virtual host from another, since every site shares the port. `ts_grants`
adds that per-host check.

## How it works

For each request, `ts_grants`:

1. Looks up the peer that opened the connection with Tailscale's `WhoIs`.
2. Reads that peer's grants of the capability you configure, and collects their
   `allowedHosts`.
3. Passes the request on if the request's host is in that list, and answers
   `403 Forbidden` if not.

```
client ──► Caddy ──► ts_grants ──► WhoIs(peer) ──► CapMap["example.com/cap/web"]
                         │                                   │
                         │        host ∈ allowedHosts? ◄─────┘
                         ▼
               yes: next handler · no: 403
```

Users and tagged nodes are checked the same way. Anything without a matching
grant is denied, including users and nodes the policy does not mention.

## Requirements

`WhoIs` needs the real tailnet address of the peer, so Caddy must accept the
connection from the tailnet directly, either:

- on a [caddy-tailscale](https://github.com/tailscale/caddy-tailscale) listener,
  where Caddy is its own node (recommended), or
- on a host running `tailscaled`, listening on its Tailscale address.

**Do not put another proxy in front of it.** Behind a proxy (or a container
network that masquerades source addresses), every request carries the proxy's
address. The lookup then either fails (`500`) or, if the proxy is a tailnet node,
grants every client the proxy's access.

## Install

Build Caddy with the module, usually alongside caddy-tailscale:

```bash
xcaddy build \
    --with github.com/tailscale/caddy-tailscale \
    --with github.com/ficklemills-org/caddy-ts-grants@v1.0.0
```

## Configure

### 1. Choose a capability name

Tailscale requires custom capability names of the form `<domain>/<path>`,
such as `example.com/cap/web`. The domain only keeps your names apart from
other people's: use one you control. `tailscale.com/` is reserved.

### 2. Grant it in the policy file

Each grant needs the network part (`ip`) to reach Caddy and the app part to
name the hosts:

```json
{
  "grants": [
    {
      "src": ["group:admins"],
      "dst": ["tag:caddy"],
      "ip": ["443"],
      "app": {
        "example.com/cap/web": [{ "allowedHosts": ["*.example.com"] }]
      }
    },
    {
      "src": ["group:users"],
      "dst": ["tag:caddy"],
      "ip": ["443"],
      "app": {
        "example.com/cap/web": [{ "allowedHosts": ["photos.example.com", "wiki.example.com"] }]
      }
    },
    {
      "src": ["tag:monitoring"],
      "dst": ["tag:caddy"],
      "ip": ["443"],
      "app": {
        "example.com/cap/web": [{ "allowedHosts": ["status.example.com"] }]
      }
    }
  ]
}
```

When several grants apply to a peer, their `allowedHosts` are combined.

An entry is either an exact host name or `*.<domain>`, which matches exactly
one label below the domain: `*.example.com` matches `wiki.example.com`, but not
`example.com` or `a.wiki.example.com`. Host names are compared without regard
to case. There is no entry that matches every host.

### 3. Add it to the Caddyfile

```caddyfile
wiki.example.com {
    ts_grants example.com/cap/web
    reverse_proxy localhost:8080
}
```

The block form is the same:

```caddyfile
ts_grants {
    capability example.com/cap/web
}
```

To take the name from the environment, use Caddyfile environment variables:
`ts_grants {$TS_GRANTS_CAPABILITY}`. In JSON config, the `capability` field
expands placeholders such as `{env.TS_GRANTS_CAPABILITY}`. Caddy refuses to
start if the capability is missing or malformed.

`ts_grants` is ordered before `basic_auth`, so it runs before other
authentication handlers. Inside a `route` block, handlers run in the order
written.

## Using it with tailscale_auth

caddy-tailscale's `tailscale_auth` provides the user's identity as
placeholders (`{http.auth.user.tailscale_user}` and others), but it rejects
every tagged node. To combine them, let `ts_grants` decide access and run
`tailscale_auth` for users only.

When `ts_grants` allows a tagged node, it sets the Caddy variable
`ts_grants_tagged` to `true`. Clients cannot set Caddy variables, so it is safe
to match on:

```caddyfile
(protected) {
    route {
        ts_grants example.com/cap/web
        @user not vars ts_grants_tagged true
        handle @user {
            tailscale_auth
        }
    }
}

wiki.example.com {
    import protected
    reverse_proxy localhost:8080
}
```

The variable is also available as the placeholder `{http.vars.ts_grants_tagged}`.

## Responses

| Situation | Result |
|-----------|--------|
| Peer has a grant covering the host | Passed to the next handler |
| No grant, or grants for other hosts only | `403` |
| Identity lookup fails | `500` |

Denials are returned as Caddy errors, so you can customize them with
`handle_errors`. Denials are logged at `INFO` with the user or node, the host
and the peer's `allowedHosts`; allowed requests at `DEBUG`.

## Development

```bash
go test ./...
```

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Parts of
`whois.go` are adapted from caddy-tailscale, © Tailscale Inc & contributors,
also under Apache-2.0.
