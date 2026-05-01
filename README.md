# SBOM CVE Checker

Scans a Software Bill of Materials (SBOM) against [OSV.dev](https://osv.dev) and [NIST NVD](https://nvd.nist.gov) and reports known CVEs with full remediation details: CVSS scores, attack vectors, affected version ranges, and fixed versions.

Zero external dependencies — standard library only (Python 3.9+).

---

## Quick start

```bash
# Console report — no API key needed
python sbom_cve_checker.py --sbom sbom.json

# HTML report for sharing
python sbom_cve_checker.py --sbom sbom.json --format html --output report.html

# CI gate — exits 2 on Critical, 1 on High
python sbom_cve_checker.py --sbom sbom.json --min-severity high --no-nvd
```

---

## Input formats

The tool auto-detects the format from file content.

### CycloneDX JSON (recommended)

Standard output from Syft, Trivy, and Docker Scout.  
Generate from a container image in one command:

```bash
syft your-image:tag -o cyclonedx-json > sbom.json
```

The tool reads `components[].purl` for ecosystem, name, and version — including the `?distro=` qualifier that identifies the OS release for packages like `openssl`.

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "components": [
    {
      "name": "django",
      "version": "3.2.0",
      "purl": "pkg:pypi/django@3.2.0"
    },
    {
      "name": "openssl",
      "version": "1.1.1n-0+deb11u4",
      "purl": "pkg:deb/debian/openssl@1.1.1n-0+deb11u4?distro=bullseye"
    }
  ]
}
```

---

### SPDX JSON

Standard output from many supply-chain tools.  
The tool reads `packages[].externalRefs` for PURLs.

```json
{
  "spdxVersion": "SPDX-2.3",
  "packages": [
    {
      "name": "lodash",
      "versionInfo": "4.17.20",
      "externalRefs": [
        { "referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.20" }
      ]
    }
  ]
}
```

---

### Simple JSON array

Minimal format for custom tooling. `ecosystem` must use an OSV-compatible value (see [Ecosystem reference](#ecosystem-reference)).

```json
[
  { "name": "django",   "version": "3.2.0",   "ecosystem": "PyPI"      },
  { "name": "lodash",   "version": "4.17.20",  "ecosystem": "npm"       },
  { "name": "openssl",  "version": "1.1.1n-0+deb11u4", "ecosystem": "Debian:11" },
  { "name": "openssl",  "version": "3.0.2-0ubuntu1.10", "ecosystem": "Ubuntu:22.04" },
  { "name": "openssl",  "version": "1.1.1t-r2",         "ecosystem": "Alpine:v3.17" }
]
```

A `purl` field is optional — if present it overrides `ecosystem`/`name`/`version`.

---

### Custom scanner JSON

Format produced by internal or lightweight scanners.  
The tool infers the ecosystem from the `type` field and `path`.

```json
[
  {
    "type": "os",
    "name": "openssl",
    "version": "1.1.1n-0+deb11u4",
    "path": "/usr/bin/openssl",
    "licenses": ["OpenSSL"]
  },
  {
    "type": "jar",
    "name": "log4j-core",
    "version": "2.14.1",
    "path": "/root/.m2/repository/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar",
    "licenses": ["Apache-2.0"]
  },
  {
    "type": null,
    "name": "requests",
    "version": "2.25.0",
    "path": "/usr/local/lib/python3.9/site-packages/requests",
    "licenses": ["Apache-2.0"]
  }
]
```

**Field reference**

| Field | Type | Description |
|---|---|---|
| `type` | `"os"` \| `"jar"` \| `null` | Package type. `"os"` = distro package; `"jar"` = Java archive; `null` = inferred from path |
| `name` | string | Package name. For JARs in a Maven local repo, the Maven `groupId` is extracted from the path automatically. |
| `version` | string | Package version (distro version string for OS packages, e.g. `1.1.1n-0+deb11u4`) |
| `path` | string \| `null` | Install path. Used to infer ecosystem when `type` is `null`, and to extract the Maven `groupId` for JARs. |
| `licenses` | array \| `null` | Ignored by this tool. |

**Ecosystem inference for `type: "os"`**

The OS distro is read from the version string when possible:

| Version pattern | Inferred ecosystem |
|---|---|
| `…+deb11u…` | `Debian:11` |
| `…ubuntu…` | `Ubuntu` (release from version suffix or `--base-image`) |
| `…-r\d+` | `Alpine` (release from `--base-image`) |
| `….el10` | `Red Hat` |
| `….fc40` | `Fedora` |

When the version string alone is not enough, pass `--base-image` or `--distro`.

**Ecosystem inference for `type: null`**

The install path is matched against known path patterns:

| Path contains | Ecosystem |
|---|---|
| `/site-packages/` or `/dist-packages/` | PyPI |
| `/node_modules/` | npm |
| `/gems/` or `/.gem/` | RubyGems |
| `/.nuget/` or `/nuget/` | NuGet |
| `/.cargo/` or `/cargo/registry/` | crates.io |
| `/go/pkg/` or `/go/mod/` | Go |
| `/composer/` | Packagist |
| `.jar` extension | Maven |

---

### CSV

Columns: `name`, `version`, `ecosystem` (required). `purl` is optional.

```csv
name,version,ecosystem,purl
django,3.2.0,PyPI,pkg:pypi/django@3.2.0
lodash,4.17.20,npm,pkg:npm/lodash@4.17.20
openssl,1.1.1n-0+deb11u4,Debian:11,
```

---

## Ecosystem reference

OSV ecosystem strings for common package types:

| Ecosystem string | Package manager |
|---|---|
| `PyPI` | Python / pip |
| `npm` | Node.js / npm / yarn |
| `Maven` | Java / Maven / Gradle |
| `Go` | Go modules |
| `crates.io` | Rust / Cargo |
| `NuGet` | .NET / NuGet |
| `RubyGems` | Ruby / gem |
| `Packagist` | PHP / Composer |
| `Debian:11` | Debian Bullseye |
| `Debian:12` | Debian Bookworm |
| `Ubuntu:20.04` | Ubuntu Focal |
| `Ubuntu:22.04` | Ubuntu Jammy |
| `Alpine:v3.17` | Alpine Linux 3.17 |
| `Red Hat` | RHEL / CentOS / UBI |
| `Rocky Linux` | Rocky Linux |
| `AlmaLinux` | AlmaLinux |

> **Why ecosystem matters for OS packages:** Distros backport security patches without
> changing the upstream version number. `openssl 1.1.1n` on Debian 11 and on Ubuntu 22.04
> are tracked separately and have different sets of open CVEs. Always include the distro
> release in the ecosystem string.

---

## Options

### Input

| Flag | Description |
|---|---|
| `--sbom PATH` | SBOM file to scan. Format is auto-detected. |
| `--base-image IMAGE` | Base container image tag (e.g. `python:3.9-slim-bullseye`). Resolves the OS ecosystem for custom scanner format files. Supports Debian, Ubuntu, Alpine, RHEL/UBI, Rocky Linux, AlmaLinux, and distroless images. |
| `--distro DISTRO` | Explicit OS ecosystem (e.g. `debian:11`). Overrides `--base-image`. |

### Output

| Flag | Description |
|---|---|
| `--format` | `console` (default), `json`, `csv`, `html` |
| `--output PATH` | Write report to file instead of stdout. |
| `--min-severity` | Filter to `critical`, `high`, `medium`, or `low` and above. |
| `--no-color` | Disable ANSI colour in console output. |

### Vulnerability data

| Flag | Description |
|---|---|
| `--nvd-api-key KEY` | [Free NVD API key](https://nvd.nist.gov/developers/request-an-api-key). Raises rate limit from 5 to 50 requests/30 s and unlocks authoritative CVSS scores. |
| `--no-nvd` | Skip NVD entirely. Uses OSV CVSS data and computed scores only. Faster; no rate limiting. |

### Cache

Results are cached in a local SQLite database so repeated scans of the same packages make no API calls.

| Flag | Default | Description |
|---|---|---|
| `--cache-db PATH` | `~/.cache/sbom_cve_checker/cache.db` | Override the cache file location. |
| `--cache-ttl SECS` | `3600` | Seconds before a cached entry is considered stale. |
| `--no-cache` | — | Bypass cache for this run (does not clear it). |
| `--clear-cache` | — | Delete all cached entries, then exit. Combine with `--sbom` to clear and immediately rescan. |
| `--cache-info` | — | Print entry counts and ages, then exit. |

---

## Exit codes

Designed for use in CI pipelines.

| Code | Meaning |
|---|---|
| `0` | No vulnerabilities found (or none at or above `--min-severity`) |
| `1` | One or more High severity CVEs found |
| `2` | One or more Critical severity CVEs found |

---

## Examples

```bash
# Scan a CycloneDX SBOM, console output
python sbom_cve_checker.py --sbom sbom.cdx.json

# Generate SBOM from a container image and scan in one pipeline
syft myapp:latest -o cyclonedx-json | python sbom_cve_checker.py --sbom /dev/stdin

# Custom scanner format — image base known
python sbom_cve_checker.py --sbom scanner_output.json --base-image node:18-alpine3.17

# Custom scanner format — distro specified explicitly
python sbom_cve_checker.py --sbom scanner_output.json --distro debian:12

# HTML report with authoritative NVD CVSS scores
python sbom_cve_checker.py --sbom sbom.json --nvd-api-key $NVD_KEY \
    --format html --output report.html

# Only critical and high, for a CI gate
python sbom_cve_checker.py --sbom sbom.json --min-severity high --no-nvd
echo "Exit code: $?"   # 0=clean, 1=high, 2=critical

# Check cache state
python sbom_cve_checker.py --cache-info

# Force a fresh scan (ignore cached results)
python sbom_cve_checker.py --sbom sbom.json --no-cache
```

---

## Data sources

| Source | Used for | Rate limit |
|---|---|---|
| [OSV.dev](https://osv.dev) | Vulnerability discovery across all ecosystems | None |
| [NIST NVD](https://nvd.nist.gov) | Authoritative CVSS scores and metrics | 5 req/30 s (no key) · 50 req/30 s (with key) |

NVD does not support batch requests — each CVE ID is a separate call. The cache eliminates repeat NVD calls across runs; on a warm cache the tool makes zero NVD requests.
