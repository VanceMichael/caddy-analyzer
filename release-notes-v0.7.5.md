# caddy-analyzer v0.7.5

Patch release that adds dates to log listings and updates the release signing and SBOM actions.

## Install

```bash
curl -sSfL https://raw.githubusercontent.com/lenny-ts/caddy-analyzer/main/install.sh | bash
go install github.com/lenny-ts/caddy-analyzer/cmd/caddy-analyze@v0.7.5
docker run --rm -v /var/log/caddy:/logs ghcr.io/lenny-ts/caddy-analyzer:v0.7.5 /logs/access.log
```

## Upgrade

```bash
caddy-analyze update --check
caddy-analyze update --version v0.7.5
```

## Changed

- **Dates in log listings (#115)**: `tail` and filtered listings now show `YYYY-MM-DD HH:MM:SS` for HTTP requests and operational events.
- **Release action dependencies (#114)**: update `anchore/sbom-action` to v0.24.3 and `sigstore/cosign-installer` to v4.1.2 (Cosign v3.0.6).

## Fixed

- **Cosign 3 release compatibility**: retain signature and certificate sidecars alongside the Sigstore bundle for older updaters.
