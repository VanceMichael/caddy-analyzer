# caddy-analyzer v0.8.0

Automatic self-ban protection for guard, including home servers with dynamic public IPs, plus protected-ban recovery fixes and refreshed English/Italian documentation.

## Install

```bash
curl -sSfL https://raw.githubusercontent.com/lenny-ts/caddy-analyzer/main/install.sh | bash
go install github.com/lenny-ts/caddy-analyzer/cmd/caddy-analyze@v0.8.0
docker run --rm -v /var/log/caddy:/logs ghcr.io/lenny-ts/caddy-analyzer:v0.8.0 /logs/access.log
```

## Upgrade

```bash
caddy-analyze update --check
caddy-analyze update --version v0.8.0
```

## Added

- **Automatic self-ban protection**: guard discovers server interface and public egress IPs by default, refreshes them every 30 seconds and checks again before each new ban. These addresses are protected from request/auth/404 thresholds, pattern detection, blocklists, country rules and covering subnet bans.
- **Dynamic-IP handling**: a successful refresh replaces the old protected addresses and removes tracked bans covering the new server IP. Dry-run simulates these decisions without changing firewall rules or saved state.

## Upgrade notes for guard deployments

- `--protect-self` defaults to `true`. Discovery makes direct IPv4/IPv6 HTTPS requests to ipify, with icanhazip as fallback, and ignores HTTP proxy settings. Each request is limited to 4 seconds; the overall discovery is limited to 10 seconds.
- If discovery fails at startup, guard refuses to start. Later failures retain known protected addresses and suspend new bans until discovery recovers. A failure in a required address family, including configured IPv6 without Internet connectivity, fails the entire check.
- Errors explain how to restart with `--protect-self=false`. This disables interface/public-IP discovery and its before-ban checks; explicit `--never-block` entries and whitelist files still work. For a fixed-IP or restricted-network deployment:

  ```bash
  sudo caddy-analyze guard /var/log/caddy/access.log \
    --protect-self=false --never-block 203.0.113.10
  ```

  Replace the example address with the trusted server/administrator IP. Update the service's startup arguments if it runs guard automatically.
- A remote administrator on another connection still needs a separate whitelist entry. Protection applies to this guard, not Fail2Ban or explicit manual `block` commands. Shared-NAT sources receive the same exemption; multiple-WAN deployments must use the same egress path as the processes being protected. Synchronous discovery adds latency to ban decisions.

## Fixed

- Saved bans for protected server or explicitly allowlisted addresses are removed instead of recreated; failed firewall removals remain tracked for retry.
- Stale expiry entries cannot remove a newer ban after protection cleanup.
- Blocklist/country-ban counters and terminal messages reflect only successful block decisions.

## Documentation

- Update README, English and Italian website pages, command/flag references, configuration, troubleshooting, FAQ, architecture and Go guard examples.
- Regenerate published pages and the search index, and refresh the documentation service-worker cache.
