# caddy-analyzer v0.7.4

Patch release that allows large Caddy access-log records to be analyzed without scanner errors.

## Install

```bash
curl -sSfL https://raw.githubusercontent.com/lenny-ts/caddy-analyzer/main/install.sh | bash
go install github.com/lenny-ts/caddy-analyzer/cmd/caddy-analyze@v0.7.4
docker run --rm -v /var/log/caddy:/logs ghcr.io/lenny-ts/caddy-analyzer:v0.7.4 /logs/access.log
```

## Upgrade

```bash
caddy-analyze update --check
caddy-analyze update --version v0.7.4
```

## Fixed

- **Oversized Caddy access-log lines**: accept log records up to 16 MiB instead of stopping at the `bufio.Scanner` 1 MiB limit, so `--detect` can process entries with large headers or URIs.
