# unifi-cli

`unifi` is a safe, scriptable UniFi Network CLI built around the official local
UniFi Network API.

It is designed for humans in a terminal and for non-interactive agents that need
stable subcommands, machine-readable output, dry-run writes, and predictable
error shapes.

## API Model

Primary API surface:

- Official local Network API:
  `/proxy/network/integration/v1/...`
- Public reference:
  <https://developer.ui.com/network/v10.3.58/gettingstarted>

Legacy and local fallback routes are intentionally limited to features that are
not currently exposed by the official Network API surface:

- remembered-client state used for DHCP reservations and per-client local DNS
- switch port profiles
- port forwards
- static routes
- dynamic DNS
- user groups
- content-filtering profiles
- older traffic routes distinct from official traffic matching lists

The fallback commands are named as fallbacks so callers do not mistake them for
the preferred path.

## Features

- official-API reads for sites, app info, adopted and pending devices, clients,
  networks, WiFi broadcasts, DNS policies, firewall zones/policies, ACL rules,
  traffic matching lists, WANs, RADIUS profiles, device tags, VPNs, hotspot
  vouchers, DPI metadata, and countries
- official-API guarded writes for networks, WiFi broadcasts, DNS policies,
  firewall zones/policies, ACL rules, traffic matching lists, actions, and
  vouchers where the API supports them
- official Cloud Connector forwarding commands for Site Manager API paths
- best-effort `network-references` fallback when the official controller
  endpoint returns a 5xx for networks with local switch/WiFi dependencies
- fetch-merge update helpers with repeatable dotted `--set` assignments
- dry-run by default for every write, with explicit `--yes` to apply
- `--json` support for machine-readable success output and structured errors
- `doctor` command for config, auth, application version, and live API
  verification
- `schema` command that introspects the command tree into agent-facing JSON
  (commands, flags, exit codes, and which commands write), fully offline
- human table output on a TTY for common list commands, with JSON preserved when
  output is piped or `--json` is passed
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
export UNIFI_CLOUD_API_KEY="optional-cloud-connector-key"
export UNIFI_SITE="default"
export UNIFI_SITE_ID="optional-site-uuid"
export UNIFI_VERIFY_TLS="false"
export UNIFI_TIMEOUT_SECONDS="30"
export UNIFI_ALLOW_FOREIGN_HOST="false"
```

Legacy aliases are also accepted for compatibility:

- `UNIFI_NETWORK_BASE_URL`
- `UNIFI_NETWORK_API_KEY`

Default config file:

```toml
# ~/.config/unifi/config.toml
base_url = "https://192.168.1.1"
api_key = "your-api-key"
cloud_api_key = ""
site = "default"
site_id = ""
verify_tls = false
timeout_seconds = 30
allow_foreign_host = false
```

Notable global flags:

- `--version` prints the CLI version.
- `--cloud-api-key` supplies the key sent to the Cloud Connector host, distinct
  from the controller `--api-key`.
- `--allow-foreign-host` lets a raw/connector request send the API key to a host
  other than the configured controller or cloud connector. Off by default: the
  CLI refuses to leak the key to an unexpected host unless this is set.

The CLI never prints your API key.

## Quick Start

```bash
unifi --json doctor
unifi app-info
unifi summary
unifi networks
unifi network-show Home
unifi dns-policies
unifi firewall-policies
```

Writes are dry-run by default:

```bash
unifi dns-upsert --domain nas.example.internal --record-type A --value 10.0.10.15
unifi dns-upsert --domain nas.example.internal --record-type A --value 10.0.10.15 --yes
```

Fetch-merge updates use official item endpoints:

```bash
unifi network-merge Home --set ipv4Configuration.dhcpConfiguration.leaseTimeSeconds=86400
unifi wifi-broadcast-merge IoT --set enabled=false
```

`network-references` uses the official endpoint first. On affected controller
versions, that endpoint can return a server-side 5xx for networks with active
switch-port/profile references; the CLI then returns a best-effort read-only
reference report from official WiFi data plus local configuration/state reads.

## Command Surface

Core:

- `doctor`
- `schema`
- `app-info`
- `summary`
- `sites`
- `request` / `raw`

Official reads:

- `devices`
- `device-show`
- `pending-devices`
- `device-statistics`
- `clients`
- `client-show`
- `networks`
- `network-show`
- `network-references`
- `wifi-broadcasts` / `wlans`
- `wifi-broadcast-show`
- `dns-policies` / `dns-static`
- `dns-show`
- `firewall-zones`
- `firewall-zone-show`
- `firewall-policies`
- `firewall-policy-show`
- `firewall-policy-ordering`
- `firewall-audit`
- `acl-rules`
- `acl-rule-show`
- `acl-rule-ordering`
- `traffic-matching-lists`
- `traffic-matching-list-show`
- `wans`
- `wan-show`
- `radius-profiles`
- `radius-profile-show`
- `device-tags`
- `device-tag-show`
- `vpn-servers`
- `vpn-server-show`
- `site-to-site-vpns`
- `site-to-site-vpn-show`
- `switch-lags`
- `switch-lag-show`
- `mc-lag-domains`
- `mc-lag-domain-show`
- `switch-stacks`
- `switch-stack-show`
- `vouchers`
- `voucher-show`
- `dpi-categories`
- `dpi-applications`
- `countries`

Official guarded writes:

- `device-adopt`
- `device-remove`
- `device-action`
- `port-action`
- `client-action`
- `network-create`
- `network-merge`
- `network-delete`
- `wifi-broadcast-create`
- `wifi-broadcast-merge`
- `wifi-broadcast-delete`
- `dns-upsert`
- `dns-merge`
- `dns-delete`
- `firewall-zone-create`
- `firewall-zone-merge`
- `firewall-zone-delete`
- `firewall-policy-create`
- `firewall-policy-merge`
- `firewall-policy-patch`
- `firewall-policy-delete`
- `firewall-policy-reorder`
- `acl-rule-create`
- `acl-rule-merge`
- `acl-rule-delete`
- `acl-rule-reorder`
- `traffic-matching-list-create`
- `traffic-matching-list-merge`
- `traffic-matching-list-delete`
- `vouchers-generate`
- `voucher-delete`
- `vouchers-delete`

Official Cloud Connector:

- `connector-get`
- `connector-post`
- `connector-put`
- `connector-delete`
- `connector-patch`

Legacy fallback commands:

- `remembered-clients`
- `remembered-client-show`
- `reservation-set`
- `reservation-create`
- `reservation-clear`
- `local-dns-set`
- `local-dns-clear`
- `client-forget`
- `legacy-fallback-types`
- `legacy-fallback-list`
- `legacy-fallback-show`
- `legacy-fallback-create`
- `legacy-fallback-merge`
- `legacy-fallback-delete`

## JSON Behaviour

With `--json`, successful commands emit command-native JSON:

- official reads return the underlying controller payloads
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

## Human Tables

When stdout is a TTY and `--json` is not passed, list commands with a table spec
render aligned, truncated human tables with a `N of M` footer: `devices`,
`clients`, `networks`, `wifi-broadcasts`, `dns-policies`, `firewall-zones`, and
`firewall-policies`. When stdout is not a TTY and `--json` is absent, those
commands still emit JSON, so piping without `--json` keeps stable machine output
for agents. Pass `--json` to force JSON everywhere; commands without a table spec
are unaffected.

## Exit Codes

The CLI maps outcomes to a stable exit-code contract so scripts and agents can
branch on failure classes without parsing messages:

| Code | Meaning |
| ---- | ------- |
| `0`  | success, including dry-run previews |
| `1`  | generic error |
| `2`  | usage error (argument parsing) |
| `3`  | configuration or auth (missing config, HTTP 401/403) |
| `4`  | not found or ambiguous selector |
| `5`  | server error (HTTP 5xx) |
| `6`  | network or timeout |
| `70` | unexpected error |

`unifi schema` emits the same table as machine-readable JSON alongside the full
command surface, so agents can discover commands, arguments, and which commands
perform writes without scraping help text.

## Controller Quirks

Behaviours the CLI works around so callers do not have to:

- Pagination defaults to 25 items and caps at 200 per page. The CLI paginates
  internally for its own reads and offers `--all` on list commands to follow
  pagination and return every page in one synthetic envelope.
- `PUT` is a full replacement and rejects read-only fields. The fetch-merge
  commands (`*-merge`, `dns-merge`, `dns-upsert` updates) strip read-only
  top-level fields (`id`, `metadata`, `statistics`, `createdAt`, `updatedAt`,
  `revision`) before sending, and reject `--set` assignments that target them.
- A destination `IP_ADDRESS` `trafficFilter` requires an `ipAddressFilter`;
  port-only matches must use type `PORT` instead.
- Port-53 policies without a `protocolFilter` match both TCP and UDP.

## Examples

```bash
unifi --json doctor
unifi --json schema
unifi app-info
unifi clients --limit 100
unifi clients --all
unifi client-show 01:23:45:67:89:ab
unifi pending-devices
unifi remembered-client-show 01:23:45:67:89:ab
unifi dns-policies --limit 100
unifi dns-merge foo.internal --record-type A --set enabled=false --yes
unifi switch-lags
unifi switch-lag-show core
unifi reservation-create --mac 00:11:22:33:44:55 --ip 10.1.40.50 --name printer
unifi legacy-fallback-create port-forward --data-json '{"name": "web", "dst_port": "443"}'
unifi firewall-policy-ordering --source-zone Internal --destination-zone External
unifi firewall-audit --format human
unifi legacy-fallback-list port-profile
unifi dpi-categories
unifi request /proxy/network/integration/v1/sites
unifi request --method OPTIONS /proxy/network/integration/v1/sites
unifi connector-get console-id network/integration/v1/sites
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
