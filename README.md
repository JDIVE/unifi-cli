# unifi-cli

`unifi` is a safe, scriptable UniFi Network CLI for inventory, DNS,
reservations, firewall inspection, and guarded controller writes.

It is designed for both humans in a terminal and non-interactive agents that
need stable subcommands and machine-readable output.

## Features

- read-first command surface for sites, devices, clients, networks, WLANs,
  WANs, DNS, firewall zones, traffic routes, and generic legacy resources
- guarded write commands with dry-run by default and explicit `--yes` to apply
- `--json` support for machine-readable success output and structured errors
- `doctor` command for config, auth, and live API verification
- raw API escape hatch that stays read-only by default
- installable as a normal Python package and releasable as standalone binaries

## Install

### From a GitHub release

Download the archive for your platform from the
[GitHub releases page](https://github.com/JDIVE/unifi-cli/releases), extract
it, and put the `unifi` binary somewhere on your `PATH`.

Current release automation publishes:

- Linux `x86_64`
- macOS `x86_64`
- macOS `arm64`

### From source

```bash
git clone https://github.com/JDIVE/unifi-cli.git
cd unifi-cli
make install-local
```

`make install-local` prefers `uv tool install --force --editable .` when `uv`
is available, and otherwise falls back to `python3 -m pip install --user
--upgrade .`.

## Configuration

Configuration precedence is:

1. command-line flags
2. environment variables
3. config file
4. defaults

Preferred environment variables:

```bash
export UNIFI_BASE_URL="https://192.168.1.1"
export UNIFI_API_KEY="your-api-key"
export UNIFI_SITE="default"
export UNIFI_SITE_ID="optional-site-uuid"
export UNIFI_VERIFY_TLS="false"
export UNIFI_TIMEOUT_SECONDS="30"
```

Legacy aliases are also accepted for compatibility:

- `UNIFI_NETWORK_BASE_URL`
- `UNIFI_NETWORK_API_KEY`

Default config file:

```toml
# ~/.config/unifi/config.toml
base_url = "https://192.168.1.1"
api_key = "your-api-key"
site = "default"
site_id = ""
verify_tls = false
timeout_seconds = 30
```

The CLI never prints your API key.

## Quick start

```bash
unifi --json doctor
unifi summary
unifi clients
unifi client-show office-ap
unifi dns-static
```

Writes are dry-run by default:

```bash
unifi dns-upsert --key nas.example.internal --record-type A --value 10.0.10.15
unifi dns-upsert --key nas.example.internal --record-type A --value 10.0.10.15 --yes
```

## Command surface

Read and discovery:

- `doctor`
- `summary`
- `sites`
- `devices`
- `clients`
- `client-show`
- `networks`
- `network-show`
- `wlans`
- `wans`
- `dns-static`
- `dns-policies`
- `firewall-zones`
- `firewall-policies`
- `firewall-audit`
- `traffic-routes`
- `content-filtering`
- `resource-types`
- `resource-list`
- `resource-show`

Guarded writes:

- `reservation-set`
- `reservation-clear`
- `local-dns-set`
- `local-dns-clear`
- `client-forget`
- `network-merge`
- `dns-upsert`
- `dns-delete`
- `resource-create`
- `resource-merge`
- `resource-delete`

Escape hatch:

- `request` (alias: `raw`)

## JSON behaviour

With `--json`, successful commands emit command-native JSON:

- discovery and read commands return the underlying controller payloads
- helper commands such as `doctor`, `summary`, and `firewall-audit` return
  structured CLI-owned objects
- dry-run write previews return a JSON object with the proposed request

With `--json`, errors are emitted as:

```json
{
  "ok": false,
  "error": {
    "code": "config_missing",
    "message": "Missing UniFi API key.",
    "details": {
      "hint": "Set UNIFI_API_KEY or add api_key to ~/.config/unifi/config.toml."
    }
  }
}
```

Secrets are redacted from both success and error output.

## Examples

```bash
unifi --json doctor
unifi clients --online
unifi client-show 01:23:45:67:89:ab
unifi dns-policies --limit 100
unifi firewall-audit --format human
unifi request /proxy/network/integration/v1/sites
unifi request --method OPTIONS /proxy/network/integration/v1/sites
```

## Development

```bash
make install-dev
make check
make build
```

Standalone binaries are built with PyInstaller:

```bash
make release-binaries
```
