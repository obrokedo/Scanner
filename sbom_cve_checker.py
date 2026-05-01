#!/usr/bin/env python3
"""
SBOM CVE Checker

Parses a Software Bill of Materials (SBOM) and checks each package against
OSV.dev and NIST NVD for known CVEs, providing full remediation details.

Supported SBOM formats:
  - CycloneDX JSON (v1.4+)
  - SPDX JSON
  - Simple JSON: [{"name": "pkg", "version": "1.0", "ecosystem": "npm"}]
  - CSV with columns: name, version, ecosystem  (purl optional)

Output formats: console (default), json, csv, html

Usage:
  python sbom_cve_checker.py --sbom sbom.json
  python sbom_cve_checker.py --sbom sbom.cdx.json --format html --output report.html
  python sbom_cve_checker.py --sbom packages.csv --nvd-api-key YOUR_KEY --format json
  python sbom_cve_checker.py --sbom sbom.json --min-severity high --no-nvd

NVD API key (free): https://nvd.nist.gov/developers/request-an-api-key
  Without a key: 5 requests / 30 s  |  With a key: 50 requests / 30 s
"""

import argparse
import csv
import io
import json
import math
import sqlite3
import sys
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import unquote, quote


# ─── Cache ───────────────────────────────────────────────────────────────────

_CACHE_MISS = object()   # sentinel: distinguishes "not cached" from "cached None"
_DEFAULT_CACHE_DB = Path.home() / ".cache" / "sbom_cve_checker" / "cache.db"


class CacheDB:
    """SQLite-backed result cache for OSV and NVD API responses.

    Two tables:
      osv_pkg  — full vulnerability list per package (ecosystem:name:version)
      nvd_cvss — CVSS dict per CVE ID (NULL row = NVD confirmed no data)

    Entries older than `ttl` seconds are considered stale and re-fetched.
    """

    def __init__(self, path: Path, ttl: int = 3600):
        self.path = path
        self.ttl  = ttl
        path.parent.mkdir(parents=True, exist_ok=True)
        self._con = sqlite3.connect(str(path), check_same_thread=False)
        self._con.execute("PRAGMA journal_mode=WAL")   # safe for concurrent readers
        self._con.execute("PRAGMA synchronous=NORMAL") # faster writes, still crash-safe
        self._init_schema()

    def _init_schema(self):
        self._con.executescript("""
            CREATE TABLE IF NOT EXISTS osv_pkg (
                pkg_key    TEXT PRIMARY KEY,
                vulns_json TEXT NOT NULL,
                fetched_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS nvd_cvss (
                cve_id     TEXT PRIMARY KEY,
                cvss_json  TEXT,
                fetched_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rh_pkg (
                pkg_key    TEXT PRIMARY KEY,
                cves_json  TEXT NOT NULL,
                fetched_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_osv_pkg_age  ON osv_pkg  (fetched_at);
            CREATE INDEX IF NOT EXISTS idx_nvd_cvss_age ON nvd_cvss (fetched_at);
            CREATE INDEX IF NOT EXISTS idx_rh_pkg_age   ON rh_pkg   (fetched_at);
        """)
        self._con.commit()

    def _fresh(self, fetched_at: float) -> bool:
        return (time.time() - fetched_at) < self.ttl

    # ── OSV package cache ─────────────────────────────────────────────────────

    @staticmethod
    def _pkg_key(pkg) -> str:
        return f"{pkg.ecosystem}:{pkg.name}:{pkg.version}"

    def get_osv(self, pkg):
        """Return cached vuln list (possibly empty), or _CACHE_MISS if stale/absent."""
        row = self._con.execute(
            "SELECT vulns_json, fetched_at FROM osv_pkg WHERE pkg_key = ?",
            (self._pkg_key(pkg),)
        ).fetchone()
        if row and self._fresh(row[1]):
            return json.loads(row[0])
        return _CACHE_MISS

    def put_osv(self, pkg, vulns: list):
        self._con.execute(
            "INSERT OR REPLACE INTO osv_pkg (pkg_key, vulns_json, fetched_at) "
            "VALUES (?, ?, ?)",
            (self._pkg_key(pkg), json.dumps(vulns), time.time()),
        )
        self._con.commit()

    # ── NVD CVE cache ─────────────────────────────────────────────────────────

    def get_nvd(self, cve_id: str):
        """Return cached CVSS dict, None (NVD had no data), or _CACHE_MISS."""
        row = self._con.execute(
            "SELECT cvss_json, fetched_at FROM nvd_cvss WHERE cve_id = ?",
            (cve_id,)
        ).fetchone()
        if row and self._fresh(row[1]):
            # cvss_json is NULL when NVD was queried but returned nothing
            return json.loads(row[0]) if row[0] is not None else None
        return _CACHE_MISS

    def put_nvd(self, cve_id: str, data: Optional[dict]):
        self._con.execute(
            "INSERT OR REPLACE INTO nvd_cvss (cve_id, cvss_json, fetched_at) "
            "VALUES (?, ?, ?)",
            (cve_id, json.dumps(data) if data is not None else None, time.time()),
        )
        self._con.commit()

    # ── Red Hat package CVE cache ─────────────────────────────────────────────

    def get_rh(self, key: str):
        """Return cached Red Hat CVE list or _CACHE_MISS. Key: '{el_major}:{pkg_name}'."""
        row = self._con.execute(
            "SELECT cves_json, fetched_at FROM rh_pkg WHERE pkg_key = ?", (key,)
        ).fetchone()
        if row and self._fresh(row[1]):
            return json.loads(row[0])
        return _CACHE_MISS

    def put_rh(self, key: str, cves: list):
        self._con.execute(
            "INSERT OR REPLACE INTO rh_pkg (pkg_key, cves_json, fetched_at) VALUES (?, ?, ?)",
            (key, json.dumps(cves), time.time()),
        )
        self._con.commit()

    # ── Maintenance ───────────────────────────────────────────────────────────

    def prune(self) -> tuple:
        """Delete entries older than TTL. Returns (osv_removed, nvd_removed, rh_removed)."""
        cutoff = time.time() - self.ttl
        c1 = self._con.execute(
            "DELETE FROM osv_pkg  WHERE fetched_at < ?", (cutoff,)
        ).rowcount
        c2 = self._con.execute(
            "DELETE FROM nvd_cvss WHERE fetched_at < ?", (cutoff,)
        ).rowcount
        c3 = self._con.execute(
            "DELETE FROM rh_pkg   WHERE fetched_at < ?", (cutoff,)
        ).rowcount
        self._con.commit()
        return c1, c2, c3

    def clear(self):
        self._con.executescript("DELETE FROM osv_pkg; DELETE FROM nvd_cvss; DELETE FROM rh_pkg;")
        self._con.commit()

    def info(self) -> dict:
        def _age(ts):
            if ts is None:
                return "empty"
            secs = int(time.time() - ts)
            return f"{secs // 60}m {secs % 60}s ago"

        osv_n  = self._con.execute("SELECT COUNT(*) FROM osv_pkg").fetchone()[0]
        nvd_n  = self._con.execute("SELECT COUNT(*) FROM nvd_cvss").fetchone()[0]
        rh_n   = self._con.execute("SELECT COUNT(*) FROM rh_pkg").fetchone()[0]
        osv_ol = self._con.execute("SELECT MIN(fetched_at) FROM osv_pkg").fetchone()[0]
        nvd_ol = self._con.execute("SELECT MIN(fetched_at) FROM nvd_cvss").fetchone()[0]
        rh_ol  = self._con.execute("SELECT MIN(fetched_at) FROM rh_pkg").fetchone()[0]
        return {
            "db_path":     str(self.path),
            "ttl_seconds": self.ttl,
            "osv_entries": osv_n,
            "nvd_entries": nvd_n,
            "rh_entries":  rh_n,
            "oldest_osv":  _age(osv_ol),
            "oldest_nvd":  _age(nvd_ol),
            "oldest_rh":   _age(rh_ol),
        }

    def close(self):
        self._con.close()


# ─── CVSS v3 Parsing & Scoring ───────────────────────────────────────────────

_CVSS_V3_METRIC_MAP = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S":  {"U": "Unchanged", "C": "Changed"},
    "C":  {"N": "None", "L": "Low", "H": "High"},
    "I":  {"N": "None", "L": "Low", "H": "High"},
    "A":  {"N": "None", "L": "Low", "H": "High"},
}

_CVSS_AV   = {"Network": 0.85, "Adjacent": 0.62, "Local": 0.55, "Physical": 0.20}
_CVSS_AC   = {"Low": 0.77, "High": 0.44}
_CVSS_UI   = {"None": 0.85, "Required": 0.62}
_CVSS_CIA  = {"High": 0.56, "Low": 0.22, "None": 0.0}
_CVSS_PR_U = {"None": 0.85, "Low": 0.62, "High": 0.27}
_CVSS_PR_C = {"None": 0.85, "Low": 0.68, "High": 0.50}


def _parse_cvss_v3_vector(vector: str) -> dict:
    result = {}
    if not vector or "CVSS:3" not in vector:
        return result
    for part in vector.split("/")[1:]:
        if ":" in part:
            k, v = part.split(":", 1)
            result[k] = _CVSS_V3_METRIC_MAP.get(k, {}).get(v, v)
    return result


def _compute_cvss_v3_score(vector: str) -> float:
    """Compute CVSS v3.1 base score from vector string."""
    m = _parse_cvss_v3_vector(vector)
    if not m:
        return 0.0
    try:
        scope_changed = m.get("S") == "Changed"
        pr_table = _CVSS_PR_C if scope_changed else _CVSS_PR_U
        av  = _CVSS_AV.get(m.get("AV", "Network"), 0.85)
        ac  = _CVSS_AC.get(m.get("AC", "Low"), 0.77)
        pr  = pr_table.get(m.get("PR", "None"), 0.85)
        ui  = _CVSS_UI.get(m.get("UI", "None"), 0.85)
        c   = _CVSS_CIA.get(m.get("C", "None"), 0.0)
        i   = _CVSS_CIA.get(m.get("I", "None"), 0.0)
        a   = _CVSS_CIA.get(m.get("A", "None"), 0.0)

        isc_base = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
        if scope_changed:
            isc = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
        else:
            isc = 6.42 * isc_base

        if isc <= 0:
            return 0.0

        exploit = 8.22 * av * ac * pr * ui
        base = min(1.08 * (isc + exploit), 10) if scope_changed else min(isc + exploit, 10)
        return math.ceil(base * 10) / 10
    except Exception:
        return 0.0


def _score_to_severity(score: float) -> str:
    if score == 0.0:  return "None"
    if score < 4.0:   return "Low"
    if score < 7.0:   return "Medium"
    if score < 9.0:   return "High"
    return "Critical"


# ─── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class Package:
    name: str
    version: str
    ecosystem: str
    purl: Optional[str] = None

    def display(self) -> str:
        return f"{self.ecosystem}/{self.name}@{self.version}"


@dataclass
class CvssV3:
    vector_string: str
    base_score: float
    severity: str
    attack_vector: str = ""
    attack_complexity: str = ""
    privileges_required: str = ""
    user_interaction: str = ""
    scope: str = ""
    confidentiality_impact: str = ""
    integrity_impact: str = ""
    availability_impact: str = ""


@dataclass
class Vulnerability:
    id: str
    aliases: list = field(default_factory=list)
    cve_ids: list = field(default_factory=list)
    summary: str = ""
    details: str = ""
    cvss_v3: Optional[CvssV3] = None
    severity_label: str = "Unknown"
    affected_ranges: list = field(default_factory=list)
    fixed_version: Optional[str] = None
    published: str = ""
    modified: str = ""
    references: list = field(default_factory=list)

    def primary_id(self) -> str:
        return self.cve_ids[0] if self.cve_ids else self.id


@dataclass
class PackageReport:
    package: Package
    vulnerabilities: list = field(default_factory=list)
    error: Optional[str] = None

    @property
    def vuln_count(self) -> int:
        return len(self.vulnerabilities)

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity_label == "Critical")

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity_label == "High")


# ─── PURL & SBOM Parsing ─────────────────────────────────────────────────────

_PURL_ECOSYSTEM = {
    "pypi": "PyPI", "npm": "npm", "maven": "Maven", "golang": "Go",
    "cargo": "crates.io", "nuget": "NuGet", "gem": "RubyGems",
    "packagist": "Packagist", "composer": "Packagist", "hex": "Hex",
    "pub": "Pub", "cocoapods": "CocoaPods", "swift": "SwiftURL",
    # OS ecosystems resolved dynamically by _parse_purl (distro version appended)
    "deb": "Debian", "apk": "Alpine", "rpm": "Red Hat",
}

# Distro codename → OSV ecosystem suffix  (e.g. "bullseye" → "Debian:11")
_DEBIAN_CODENAMES: dict = {
    "wheezy": "7", "jessie": "8", "stretch": "9", "buster": "10",
    "bullseye": "11", "bookworm": "12", "trixie": "13",
}
_UBUNTU_CODENAMES: dict = {
    "trusty": "14.04", "xenial": "16.04", "bionic": "18.04",
    "focal": "20.04", "jammy": "22.04", "noble": "24.04",
}


def distro_from_image_tag(tag: str) -> str:
    """Derive an OSV ecosystem string from a container image tag.

    Handles patterns produced by common base images:

      debian:11  debian:bullseye  debian:11-slim
      ubuntu:22.04  ubuntu:jammy
      alpine:3.17  alpine:3.17.3
      python:3.9-slim-bullseye  node:18-alpine3.17  openjdk:17-jammy
      gcr.io/distroless/base-debian11

    Returns e.g. 'Debian:11', 'Ubuntu:22.04', 'Alpine:v3.17', or '' if unknown.
    """
    import re

    # Drop registry prefix and digest — keep only the tag portion
    tag = tag.lower().strip()
    if "@sha256:" in tag:
        tag = tag.split("@sha256:")[0]
    # Strip registry host (contains a dot or colon before the first slash)
    parts = tag.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0]):
        tag = "/".join(parts[1:])
    # Separate image name from tag
    tag_part = tag.split(":")[-1] if ":" in tag else tag

    # ── Alpine ───────────────────────────────────────────────────────────────
    # alpine:3.17  alpine:3.17.3  *-alpine3.17  *-alpine-3.17
    # Search the full tag so "alpine:3.17" (tag_part="3.17") is also caught.
    m = re.search(r"alpine[-:v]?(\d+\.\d+)", tag)
    if m:
        return f"Alpine:v{m.group(1)}"
    if "alpine" in tag:
        return "Alpine"

    # ── Debian ────────────────────────────────────────────────────────────────
    # debian:11  debian:bullseye  *-bullseye  *-slim-bullseye  distroless/base-debian11
    for codename, ver in _DEBIAN_CODENAMES.items():
        if codename in tag_part or codename in tag:
            return f"Debian:{ver}"
    m = re.search(r"debian[-:]?(\d+)", tag)
    if m:
        return f"Debian:{m.group(1)}"

    # ── Ubuntu ────────────────────────────────────────────────────────────────
    # ubuntu:22.04  ubuntu:jammy  *-jammy  *-focal
    for codename, ver in _UBUNTU_CODENAMES.items():
        if codename in tag_part or codename in tag:
            return f"Ubuntu:{ver}"
    m = re.search(r"ubuntu[-:]?(\d{2}\.\d{2})", tag)
    if m:
        return f"Ubuntu:{m.group(1)}"

    # ── RHEL / UBI / Rocky / Alma ────────────────────────────────────────────
    if re.search(r"(?:ubi\d*|rhel)[-:/]", tag) or tag.startswith("ubi"):
        m = re.search(r"(\d+)", tag_part)
        return f"Red Hat:{m.group(1)}" if m else "Red Hat"
    if re.search(r"rockylinux|rocky(?!.*alpine)", tag):
        m = re.search(r"(\d+)", tag_part)
        return f"Rocky Linux:{m.group(1)}" if m else "Rocky Linux"
    if "almalinux" in tag:
        m = re.search(r"(\d+)", tag_part)
        return f"AlmaLinux:{m.group(1)}" if m else "AlmaLinux"

    return ""


def _os_ecosystem(pkg_type: str, namespace: str, qualifiers: dict) -> str:
    """Resolve OSV ecosystem string for OS package PURLs.

    OSV requires the distro release to avoid false positives across
    release lines, e.g. 'Debian:11' or 'Alpine:v3.17'.
    The release is taken from the PURL 'distro' qualifier when present.
    """
    distro_q = qualifiers.get("distro", "").lower()  # e.g. "bullseye", "alpine-3.17"

    if pkg_type == "deb":
        ns = namespace.lower()
        if ns == "ubuntu" or "ubuntu" in distro_q:
            for codename, ver in _UBUNTU_CODENAMES.items():
                if codename in distro_q:
                    return f"Ubuntu:{ver}"
            return "Ubuntu"
        # Debian (default for deb type)
        for codename, ver in _DEBIAN_CODENAMES.items():
            if codename in distro_q:
                return f"Debian:{ver}"
        return "Debian"

    if pkg_type == "apk":
        # distro qualifier looks like "alpine-3.17" or "3.17"
        if distro_q:
            # strip leading "alpine-" and format as "v3.17"
            ver = distro_q.replace("alpine-", "").strip()
            if ver:
                return f"Alpine:v{ver}" if not ver.startswith("v") else f"Alpine:{ver}"
        return "Alpine"

    if pkg_type == "rpm":
        ns = namespace.lower()
        if "fedora" in ns or "fedora" in distro_q:
            return "Fedora"
        if "suse" in ns or "sles" in distro_q or "opensuse" in distro_q:
            return "openSUSE"
        return "Red Hat"

    return _PURL_ECOSYSTEM.get(pkg_type, pkg_type.capitalize())


def _infer_os_ecosystem(version: str, path: str, distro_hint: str) -> str:
    """Infer OSV ecosystem for an OS package from its version string or a user hint.

    Version string patterns emitted by package managers:
      Debian  : 1.1.1n-0+deb11u4  or  2:8.2.2434-3+deb11u1  (+debNu suffix)
      Ubuntu  : 3.0.2-0ubuntu1.10  or  1.1.1f-1ubuntu2.16    (ubuntu in version)
      Alpine  : 3.17.2-r1  or  1.1.1t-r2                     (-rN suffix)
      RHEL/CentOS/Rocky : 1.1.1k-7.el9_0                     (.elN / .fcN suffix)
    """
    import re

    if distro_hint:
        return distro_hint

    v = version.lower()

    m = re.search(r'\+deb(\d+)u', v)
    if m:
        return f"Debian:{m.group(1)}"

    if "ubuntu" in v:
        # Ubuntu package versions embed the Ubuntu release in the build suffix,
        # e.g. "1ubuntu2.16~20.04" – extract the ~XX.XX part when present.
        m = re.search(r'~(\d{2}\.\d{2})', v)
        if m:
            return f"Ubuntu:{m.group(1)}"
        for codename, ver in _UBUNTU_CODENAMES.items():
            if codename in path.lower():
                return f"Ubuntu:{ver}"
        return "Ubuntu"

    if re.search(r'-r\d+$', v):
        # Alpine: try to pull release from path (e.g. /lib/apk/db/ on alpine-3.17)
        m = re.search(r'alpine[/-]v?(\d+\.\d+)', path.lower())
        if m:
            return f"Alpine:v{m.group(1)}"
        return "Alpine"

    if re.search(r'\.(el|fc)\d', v):
        # .elN suffix is shared by RHEL, CentOS, Rocky Linux, and AlmaLinux.
        # OSV's "Red Hat" ecosystem has the broadest coverage for this family;
        # use --base-image or --distro to override to "Rocky Linux" / "AlmaLinux"
        # when the specific fork is known.
        if re.search(r'\.fc\d', v):
            return "Fedora"
        return "Red Hat"

    return ""


# ─── RPM Version Comparison ───────────────────────────────────────────────────

def _el_major(version: str) -> str:
    """Extract the RHEL/Fedora major release from an RPM version string.

    '14.2-3.el9'        -> '9'
    '1:3.2.2-16.el10'   -> '10'
    '2.41-3.fc40'       -> '40'
    """
    import re
    m = re.search(r'\.(el|fc)(\d+)', version.lower())
    return m.group(2) if m else ""


def _parse_rpm_evr(evr: str) -> tuple:
    """Split 'epoch:version-release' into (epoch_int, version_str, release_str)."""
    epoch = 0
    if ':' in evr:
        ep, evr = evr.split(':', 1)
        try:
            epoch = int(ep)
        except ValueError:
            pass
    release = ""
    if '-' in evr:
        evr, release = evr.rsplit('-', 1)
    return epoch, evr, release


def _rpmvercmp_str(a: str, b: str) -> int:
    """Compare two RPM version/release strings. Returns -1, 0, or 1."""
    import re
    if a == b:
        return 0
    segs_a = re.findall(r'\d+|[a-zA-Z]+', a)
    segs_b = re.findall(r'\d+|[a-zA-Z]+', b)
    for sa, sb in zip(segs_a, segs_b):
        if sa.isdigit() and sb.isdigit():
            d = int(sa) - int(sb)
        else:
            d = (sa > sb) - (sa < sb)
        if d:
            return -1 if d < 0 else 1
    if len(segs_a) < len(segs_b): return -1
    if len(segs_a) > len(segs_b): return 1
    return 0


def _rpm_lt(v1: str, v2: str) -> bool:
    """Return True if RPM version string v1 is strictly less than v2."""
    e1, ver1, rel1 = _parse_rpm_evr(v1)
    e2, ver2, rel2 = _parse_rpm_evr(v2)
    if e1 != e2:
        return e1 < e2
    vc = _rpmvercmp_str(ver1, ver2)
    if vc != 0:
        return vc < 0
    return _rpmvercmp_str(rel1, rel2) < 0


def _rh_fixed_evr(fixed_pkg_str: str, expected_name: str) -> Optional[str]:
    """Parse a Red Hat affected_packages entry and return the EVR if name matches.

    Example: 'binutils-0:2.41-58.el9_4'  ->  '0:2.41-58.el9_4'
             'gdb-14.2-10.el9_4'          ->  '14.2-10.el9_4'
    Returns None if the package name does not match expected_name.
    """
    import re
    # With epoch:  {name}-{epoch}:{ver}-{rel}
    m = re.match(r'^(.+?)-(\d+:.+)$', fixed_pkg_str)
    if m:
        if m.group(1).lower() == expected_name.lower():
            return m.group(2)
        return None
    # No epoch:  {name}-{ver}-{rel}  (last two dash-separated fields are ver and rel)
    parts = fixed_pkg_str.rsplit('-', 2)
    if len(parts) == 3 and parts[0].lower() == expected_name.lower():
        return f"{parts[1]}-{parts[2]}"
    return None


def _maven_groupid_from_path(path: str, artifact: str) -> str:
    """Extract Maven groupId from a jar's filesystem path.

    Maven local-repository layout:
      .../repository/<group/as/dirs>/<artifact>/<version>/<artifact>-<version>.jar
    Container image layout (fat-jar or lib dir):
      /app/lib/log4j-core-2.14.1.jar  ->  no group info available
    """
    import re
    p = path.replace("\\", "/")

    # Anchor on known Maven repository directory names
    for anchor in (".m2/repository/", "/repository/", "/packages/", "/cache/"):
        idx = p.find(anchor)
        if idx == -1:
            continue
        after = p[idx + len(anchor):]
        parts = after.rstrip("/").split("/")
        # Layout: [group...] / artifact / version / artifact-version.jar
        # Find the artifact name in parts
        for i, part in enumerate(parts):
            if part == artifact and i > 0:
                group_parts = parts[:i]
                if group_parts:
                    return ".".join(group_parts)

    return ""


# Path-suffix → ecosystem heuristics for type=null packages
_PATH_ECOSYSTEM_HINTS: list = [
    ("/site-packages/",   "PyPI"),
    ("/dist-packages/",   "PyPI"),
    ("/node_modules/",    "npm"),
    ("/gems/",            "RubyGems"),
    ("/.gem/",            "RubyGems"),
    ("/nuget/",           "NuGet"),
    ("/.nuget/",          "NuGet"),
    ("/cargo/registry/",  "crates.io"),
    ("/.cargo/",          "crates.io"),
    ("/go/pkg/",          "Go"),
    ("/go/mod/",          "Go"),
    ("/composer/",        "Packagist"),
    ("/vendor/bundle/",   "RubyGems"),
    ("/elixir/",          "Hex"),
    ("/pub/cache/",       "Pub"),
]


def _parse_custom_format(data: list, distro_hint: str = "") -> list:
    """Parse the custom scanner JSON format:

      {"type": "os"|"jar"|null, "name": "...", "version": "...",
       "path": "...", "licenses": [...]}
    """
    pkgs = []
    skipped = 0

    for item in data:
        if not isinstance(item, dict):
            continue

        pkg_type = item.get("type")          # "os", "jar", or None
        name     = (item.get("name")    or "").strip()
        version  = (item.get("version") or "").strip()
        path     = (item.get("path")    or "").strip()

        if not name or not version:
            continue

        ecosystem = ""

        if pkg_type == "os":
            ecosystem = _infer_os_ecosystem(version, path, distro_hint)
            if not ecosystem:
                print(
                    f"  [SKIP] {name} {version}: cannot determine OS ecosystem. "
                    f"Use --distro (e.g. --distro debian:11).",
                    file=sys.stderr,
                )
                skipped += 1
                continue

        elif pkg_type == "jar":
            ecosystem = "Maven"
            group = _maven_groupid_from_path(path, name)
            name  = f"{group}:{name}" if group else name
            if not group:
                print(
                    f"  [WARN] {name} {version}: no Maven groupId in path '{path}'. "
                    f"Querying by artifact name only — results may be incomplete.",
                    file=sys.stderr,
                )

        else:
            # type is null or unknown — infer from install path
            p = path.lower()
            for suffix, eco in _PATH_ECOSYSTEM_HINTS:
                if suffix in p:
                    ecosystem = eco
                    break
            if not ecosystem:
                # Last resort: file extension
                if path.endswith(".jar"):
                    ecosystem = "Maven"
                    group = _maven_groupid_from_path(path, name)
                    name  = f"{group}:{name}" if group else name
                else:
                    print(
                        f"  [SKIP] {name} {version}: cannot infer ecosystem from "
                        f"path '{path}'. Add 'ecosystem' field or use --distro.",
                        file=sys.stderr,
                    )
                    skipped += 1
                    continue

        pkgs.append(Package(name=name, version=version, ecosystem=ecosystem))

    if skipped:
        print(f"  [INFO] {skipped} package(s) skipped — ecosystem could not be determined.",
              file=sys.stderr)
    return pkgs


def _is_custom_format(items: list) -> bool:
    """Return True if the list looks like the custom scanner format."""
    for item in items:
        if isinstance(item, dict) and "path" in item and "type" in item and "ecosystem" not in item:
            return True
    return False


def _parse_purl(purl: str) -> Optional[tuple]:
    """Return (ecosystem, name, version) from a Package URL string."""
    if not purl or not purl.startswith("pkg:"):
        return None
    try:
        rest = purl[4:]
        pkg_type, rest = rest.split("/", 1)
        pkg_type = pkg_type.lower()

        # Extract qualifiers (everything after '?', before '#')
        qualifiers: dict = {}
        if "?" in rest:
            rest, qs = rest.split("?", 1)
            qs = qs.split("#")[0]
            for pair in qs.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    qualifiers[unquote(k)] = unquote(v)

        version = None
        if "@" in rest:
            rest, version = rest.rsplit("@", 1)
            version = version.split("#")[0]

        # Separate namespace from name for types that use it
        namespace = ""
        name_part = unquote(rest.split("#")[0])
        if "/" in name_part:
            namespace, name_part = name_part.split("/", 1)

        name = name_part

        # Maven: group:artifact
        if pkg_type == "maven":
            name = f"{namespace}:{name_part}" if namespace else name_part

        # OS package types get distro-versioned ecosystem names
        if pkg_type in ("deb", "apk", "rpm"):
            ecosystem = _os_ecosystem(pkg_type, namespace, qualifiers)
        else:
            ecosystem = _PURL_ECOSYSTEM.get(pkg_type, pkg_type.capitalize())

        return (ecosystem, name, version)
    except Exception:
        return None


def _parse_cyclonedx(data: dict) -> list:
    pkgs = []
    for comp in data.get("components", []):
        name    = comp.get("name", "").strip()
        version = comp.get("version", "").strip()
        purl    = comp.get("purl", "").strip()
        eco     = ""
        if purl:
            parsed = _parse_purl(purl)
            if parsed:
                eco, name, version = parsed
        if not eco:
            eco = comp.get("type", "Unknown")
        if name and version:
            pkgs.append(Package(name=name, version=version, ecosystem=eco, purl=purl or None))
    return pkgs


def _parse_spdx(data: dict) -> list:
    pkgs = []
    for pkg in data.get("packages", []):
        name    = pkg.get("name", "").strip()
        version = pkg.get("versionInfo", "").strip()
        eco     = "Unknown"
        purl    = None
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator", "")
                parsed = _parse_purl(purl)
                if parsed:
                    eco, _, _ = parsed
                break
        if name and version and name not in ("NOASSERTION", ""):
            pkgs.append(Package(name=name, version=version, ecosystem=eco, purl=purl))
    return pkgs


def _parse_simple_json(data) -> list:
    items = data.get("packages", data) if isinstance(data, dict) else data
    if not isinstance(items, list):
        return []
    pkgs = []
    for item in items:
        name = item.get("name", "").strip()
        version = item.get("version", "").strip()
        eco = item.get("ecosystem", item.get("type", "")).strip()
        purl = item.get("purl", "").strip()
        if purl and not eco:
            parsed = _parse_purl(purl)
            if parsed:
                eco, name, version = parsed
        if name and version and eco:
            pkgs.append(Package(name=name, version=version, ecosystem=eco, purl=purl or None))
    return pkgs


def parse_sbom(path: Path, distro_hint: str = "") -> list:
    """Parse a SBOM file and return a list of Package objects.

    distro_hint: OSV ecosystem string to use for OS packages whose ecosystem
    cannot be inferred from the version string (e.g. 'debian:11', 'alpine:v3.17').
    Only applies to the custom scanner format.
    """
    content = path.read_text(encoding="utf-8")

    if path.suffix.lower() == ".csv":
        pkgs = []
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            name    = (row.get("name") or row.get("package") or "").strip()
            version = (row.get("version") or "").strip()
            eco     = (row.get("ecosystem") or row.get("type") or "").strip()
            purl    = (row.get("purl") or "").strip() or None
            if purl and not eco:
                parsed = _parse_purl(purl)
                if parsed:
                    eco, name, version = parsed
            if name and version and eco:
                pkgs.append(Package(name=name, version=version, ecosystem=eco, purl=purl))
        return pkgs

    data = json.loads(content)

    if isinstance(data, list):
        if _is_custom_format(data):
            return _parse_custom_format(data, distro_hint)
        return _parse_simple_json(data)
    if data.get("bomFormat", "").lower() == "cyclonedx":
        return _parse_cyclonedx(data)
    if "spdxVersion" in data or "SPDXID" in data:
        return _parse_spdx(data)
    return _parse_simple_json(data)


# ─── Scan Loading & Diff ──────────────────────────────────────────────────────

def _load_scan_json(path: Path) -> list:
    """Deserialize a previous JSON report (produced by to_json_report) into PackageReport objects."""
    data = json.loads(path.read_text(encoding="utf-8"))
    packages_data = data.get("packages", data) if isinstance(data, dict) else data
    if not isinstance(packages_data, list):
        raise ValueError(f"Cannot load scan from {path}: expected JSON with 'packages' list")

    reports = []
    for entry in packages_data:
        pkg = Package(
            name=entry.get("name", ""),
            version=entry.get("version", ""),
            ecosystem=entry.get("ecosystem", ""),
            purl=entry.get("purl"),
        )
        vulns = []
        for v in entry.get("vulnerabilities", []):
            cvss = None
            if v.get("cvss_v3"):
                c = v["cvss_v3"]
                cvss = CvssV3(
                    vector_string=c.get("vector_string", ""),
                    base_score=c.get("base_score", 0.0),
                    severity=c.get("severity", ""),
                    attack_vector=c.get("attack_vector", ""),
                    attack_complexity=c.get("attack_complexity", ""),
                    privileges_required=c.get("privileges_required", ""),
                    user_interaction=c.get("user_interaction", ""),
                    scope=c.get("scope", ""),
                    confidentiality_impact=c.get("confidentiality_impact", ""),
                    integrity_impact=c.get("integrity_impact", ""),
                    availability_impact=c.get("availability_impact", ""),
                )
            vulns.append(Vulnerability(
                id=v.get("id", ""),
                aliases=v.get("aliases", []),
                cve_ids=v.get("cve_ids", []),
                summary=v.get("summary", ""),
                details=v.get("details", ""),
                cvss_v3=cvss,
                severity_label=v.get("severity", "Unknown"),
                affected_ranges=v.get("affected_ranges", []),
                fixed_version=v.get("fixed_version"),
                published=v.get("published", ""),
                modified=v.get("modified", ""),
                references=v.get("references", []),
            ))
        reports.append(PackageReport(package=pkg, vulnerabilities=vulns, error=entry.get("error")))
    return reports


def compute_diff(baseline: list, current: list) -> dict:
    """Compare two lists of PackageReport and return a diff dict.

    Keys:
      remediated       - (report, vuln) pairs present in baseline but absent from current
      introduced       - (report, vuln) pairs absent from baseline but present in current
      persistent       - (report, vuln) pairs present in both (current-side data used)
      packages_added   - Package objects in current but not in baseline
      packages_removed - Package objects in baseline but not in current
      packages_upgraded - list of (baseline_pkg, current_pkg) where version differs
    """
    def _vkey(pkg: Package, vuln: Vulnerability) -> tuple:
        return (pkg.ecosystem.lower(), pkg.name.lower(), vuln.primary_id().lower())

    def _pkey(pkg: Package) -> tuple:
        return (pkg.ecosystem.lower(), pkg.name.lower())

    base_vulns: dict = {}
    for r in baseline:
        for v in r.vulnerabilities:
            base_vulns[_vkey(r.package, v)] = (r, v)

    cur_vulns: dict = {}
    for r in current:
        for v in r.vulnerabilities:
            cur_vulns[_vkey(r.package, v)] = (r, v)

    base_pkgs: dict = {_pkey(r.package): r.package for r in baseline}
    cur_pkgs:  dict = {_pkey(r.package): r.package for r in current}

    return {
        "remediated":        [(r, v) for k, (r, v) in base_vulns.items() if k not in cur_vulns],
        "introduced":        [(r, v) for k, (r, v) in cur_vulns.items()  if k not in base_vulns],
        "persistent":        [cur_vulns[k] for k in base_vulns if k in cur_vulns],
        "packages_added":    [p for k, p in cur_pkgs.items()  if k not in base_pkgs],
        "packages_removed":  [p for k, p in base_pkgs.items() if k not in cur_pkgs],
        "packages_upgraded": [
            (base_pkgs[k], cur_pkgs[k])
            for k in base_pkgs
            if k in cur_pkgs and base_pkgs[k].version != cur_pkgs[k].version
        ],
    }


# ─── OSV API ─────────────────────────────────────────────────────────────────

_OSV_BATCH_URL  = "https://api.osv.dev/v1/querybatch"
_OSV_VULN_URL   = "https://api.osv.dev/v1/vulns/{}"
_OSV_BATCH_SIZE = 1000


def _http_post(url: str, body: dict, headers: dict = None) -> dict:
    payload = json.dumps(body).encode()
    hdrs = {"Content-Type": "application/json", "User-Agent": "sbom-cve-checker/1.0"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=payload, headers=hdrs, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def _http_get(url: str, headers: dict = None) -> dict:
    hdrs = {"User-Agent": "sbom-cve-checker/1.0"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def _query_osv(packages: list, verbose: bool = False,
               db: Optional[CacheDB] = None) -> tuple:
    """Two-phase OSV lookup with persistent cache support.

    Phase 1: /v1/querybatch  — returns minimal {id, modified} per vuln
    Phase 2: /v1/vulns/{id}  — returns full data (severity, CVSS, ranges, fix)

    Returns (results, osv_hits, osv_misses) where results is one dict per package.
    """
    results: list = [None] * len(packages)
    to_fetch: list = []   # (original_index, pkg) for packages not in cache
    osv_hits = 0

    # ── Cache check (package level) ──
    for i, pkg in enumerate(packages):
        if db is not None:
            cached = db.get_osv(pkg)
            if cached is not _CACHE_MISS:
                results[i] = {"vulns": cached}
                osv_hits += 1
                if verbose:
                    print(f"      OSV cache hit: {pkg.display()}", file=sys.stderr)
                continue
        to_fetch.append((i, pkg))

    osv_misses = len(to_fetch)
    if not to_fetch:
        return results, osv_hits, osv_misses

    pkgs_to_fetch = [pkg for _, pkg in to_fetch]

    # ── Phase 1: batch query for vuln IDs (uncached packages only) ──
    queries = [
        {"version": p.version, "package": {"name": p.name, "ecosystem": p.ecosystem}}
        for p in pkgs_to_fetch
    ]
    batch_results: list = []
    for i in range(0, len(queries), _OSV_BATCH_SIZE):
        chunk = queries[i:i + _OSV_BATCH_SIZE]
        try:
            resp = _http_post(_OSV_BATCH_URL, {"queries": chunk})
            batch_results.extend(resp.get("results", [{}] * len(chunk)))
        except Exception as exc:
            print(f"  [WARNING] OSV batch query failed: {exc}", file=sys.stderr)
            batch_results.extend([{}] * len(chunk))
        if i + _OSV_BATCH_SIZE < len(queries):
            time.sleep(0.5)

    # ── Phase 2: fetch full vuln details for every unique ID found ──
    all_ids: set = set()
    for result in batch_results:
        for v in result.get("vulns", []):
            all_ids.add(v["id"])

    vuln_detail: dict = {}
    if all_ids:
        print(f"    Fetching full details for {len(all_ids)} unique vulnerabilities...",
              file=sys.stderr)
        for vid in sorted(all_ids):
            if verbose:
                print(f"      GET {vid}", file=sys.stderr)
            try:
                vuln_detail[vid] = _http_get(_OSV_VULN_URL.format(vid))
            except Exception as exc:
                print(f"  [WARNING] Could not fetch {vid}: {exc}", file=sys.stderr)
            time.sleep(0.05)   # 20 req/s — well within OSV's limits

    # ── Assemble, write results, and populate cache ──
    for (orig_idx, pkg), batch_result in zip(to_fetch, batch_results):
        full_vulns = [vuln_detail[v["id"]] for v in batch_result.get("vulns", [])
                      if v["id"] in vuln_detail]
        results[orig_idx] = {"vulns": full_vulns}
        if db is not None:
            db.put_osv(pkg, full_vulns)

    return results, osv_hits, osv_misses


def _extract_cvss_from_osv(severity_list: list) -> Optional[CvssV3]:
    for sev in severity_list:
        if sev.get("type") in ("CVSS_V3", "CVSS_V4"):
            vector = sev.get("score", "")
            if vector:
                m = _parse_cvss_v3_vector(vector)
                score = _compute_cvss_v3_score(vector)
                return CvssV3(
                    vector_string=vector,
                    base_score=score,
                    severity=_score_to_severity(score),
                    attack_vector=m.get("AV", ""),
                    attack_complexity=m.get("AC", ""),
                    privileges_required=m.get("PR", ""),
                    user_interaction=m.get("UI", ""),
                    scope=m.get("S", ""),
                    confidentiality_impact=m.get("C", ""),
                    integrity_impact=m.get("I", ""),
                    availability_impact=m.get("A", ""),
                )
    return None


def _extract_fixed_version(affected: list) -> Optional[str]:
    for aff in affected:
        for r in aff.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event and event["fixed"] not in ("0", ""):
                    return event["fixed"]
    return None


def _extract_ranges(affected: list) -> list:
    ranges = []
    for aff in affected:
        for r in aff.get("ranges", []):
            rtype = r.get("type", "SEMVER")
            introduced = fixed = None
            for event in r.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event:
                    fixed = event["fixed"]
            parts = []
            if introduced and introduced != "0":
                parts.append(f">= {introduced}")
            if fixed:
                parts.append(f"< {fixed}")
            if parts:
                ranges.append(f"[{rtype}] {', '.join(parts)}")
        versions = aff.get("versions", [])
        if versions and not ranges:
            sample = versions[:8]
            suffix = f" (+{len(versions) - 8} more)" if len(versions) > 8 else ""
            ranges.append("Affected: " + ", ".join(sample) + suffix)
    return ranges


def _parse_osv_result(result: dict, pkg: Package) -> list:
    vulns = []
    for vd in result.get("vulns", []):
        vuln_id  = vd.get("id", "")
        aliases  = vd.get("aliases", [])
        cve_ids  = [a for a in aliases if a.startswith("CVE-")]

        cvss = _extract_cvss_from_osv(vd.get("severity", []))
        affected = vd.get("affected", [])
        ranges = _extract_ranges(affected)
        fixed  = _extract_fixed_version(affected)

        # Severity label: prefer database_specific, fallback to computed
        db_sev = vd.get("database_specific", {}).get("severity", "")
        if db_sev:
            sev_label = db_sev.capitalize()
        elif cvss:
            sev_label = cvss.severity
        else:
            sev_label = "Unknown"

        refs = [{"type": r.get("type", ""), "url": r.get("url", "")}
                for r in vd.get("references", [])]

        vulns.append(Vulnerability(
            id=vuln_id, aliases=aliases, cve_ids=cve_ids,
            summary=vd.get("summary", ""),
            details=vd.get("details", ""),
            cvss_v3=cvss, severity_label=sev_label,
            affected_ranges=ranges, fixed_version=fixed,
            published=vd.get("published", ""),
            modified=vd.get("modified", ""),
            references=refs,
        ))
    return vulns


# ─── NVD Enrichment ──────────────────────────────────────────────────────────

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _fetch_nvd_cvss(cve_id: str, api_key: Optional[str]) -> Optional[dict]:
    headers = {"apiKey": api_key} if api_key else {}
    url = f"{_NVD_URL}?cveId={cve_id}"

    for attempt in range(5):
        try:
            data = _http_get(url, headers)
            break
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                # NVD rate-limit: back off with increasing wait, then retry
                wait = 30 * (attempt + 1)
                print(f"  [NVD] Rate limited on {cve_id}, waiting {wait}s "
                      f"(attempt {attempt + 1}/5)...", file=sys.stderr)
                time.sleep(wait)
            elif exc.code in (403, 503):
                wait = 60 * (attempt + 1)
                print(f"  [NVD] HTTP {exc.code} on {cve_id}, waiting {wait}s...",
                      file=sys.stderr)
                time.sleep(wait)
            else:
                return None
        except Exception:
            return None
    else:
        print(f"  [NVD] Giving up on {cve_id} after 5 attempts.", file=sys.stderr)
        return None

    vuln_list = data.get("vulnerabilities", [])
    if not vuln_list:
        return None

    metrics = vuln_list[0].get("cve", {}).get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        if metrics.get(key):
            entry = metrics[key][0]
            cd    = entry.get("cvssData", {})
            score  = cd.get("baseScore", 0.0)
            vector = cd.get("vectorString", "")
            sev    = entry.get("baseSeverity", _score_to_severity(score)).capitalize()
            m      = _parse_cvss_v3_vector(vector)
            return dict(
                vector_string=vector, base_score=score, severity=sev,
                attack_vector=m.get("AV", ""), attack_complexity=m.get("AC", ""),
                privileges_required=m.get("PR", ""), user_interaction=m.get("UI", ""),
                scope=m.get("S", ""), confidentiality_impact=m.get("C", ""),
                integrity_impact=m.get("I", ""), availability_impact=m.get("A", ""),
            )

    if metrics.get("cvssMetricV2"):
        entry = metrics["cvssMetricV2"][0]
        cd    = entry.get("cvssData", {})
        score = cd.get("baseScore", 0.0)
        sev   = entry.get("baseSeverity", _score_to_severity(score)).capitalize()
        return dict(
            vector_string=cd.get("vectorString", ""), base_score=score, severity=sev,
            attack_vector=cd.get("accessVector", "").capitalize(),
            attack_complexity=cd.get("accessComplexity", "").capitalize(),
            privileges_required="", user_interaction="", scope="",
            confidentiality_impact=cd.get("confidentialityImpact", "").capitalize(),
            integrity_impact=cd.get("integrityImpact", "").capitalize(),
            availability_impact=cd.get("availabilityImpact", "").capitalize(),
        )
    return None


def enrich_with_nvd(reports: list, api_key: Optional[str], verbose: bool = False,
                    db: Optional[CacheDB] = None) -> tuple:
    """Add NVD CVSS details to any vulnerability that has a CVE ID.

    Returns (nvd_hits, nvd_fetches) counts for reporting.
    """
    # NVD public limits: 5 req/30s (no key) = 6.2s gap; 50 req/30s (key) = 0.6s gap
    # Sleep before each network call (after the first) to stay within the rate limit
    # regardless of how long retries inside _fetch_nvd_cvss consumed.
    base_delay = 0.6 if api_key else 6.2
    mem: dict  = {}   # in-run dedup so we never double-fetch within one execution
    nvd_hits   = 0
    nvd_fetches = 0

    for report in reports:
        for vuln in report.vulnerabilities:
            for cve_id in vuln.cve_ids:
                if cve_id in mem:
                    nvd = mem[cve_id]
                else:
                    # 1. persistent cache
                    nvd = db.get_nvd(cve_id) if db is not None else _CACHE_MISS

                    if nvd is _CACHE_MISS:
                        # 2. live NVD fetch
                        if nvd_fetches > 0:
                            time.sleep(base_delay)
                        if verbose:
                            print(f"    NVD fetch: {cve_id}", file=sys.stderr)
                        nvd = _fetch_nvd_cvss(cve_id, api_key)
                        nvd_fetches += 1
                        if db is not None:
                            db.put_nvd(cve_id, nvd)
                    else:
                        nvd_hits += 1
                        if verbose:
                            print(f"    NVD cache hit: {cve_id}", file=sys.stderr)

                    mem[cve_id] = nvd

                if nvd:
                    vuln.cvss_v3 = CvssV3(**nvd)
                    vuln.severity_label = nvd["severity"]
                    break

    return nvd_hits, nvd_fetches


# ─── Red Hat Security API ─────────────────────────────────────────────────────

_RH_CVE_URL        = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
_RH_CVE_DETAIL_URL = "https://access.redhat.com/hydra/rest/securitydata/cve"
_RH_SEV_MAP = {
    "critical":  "Critical",
    "important": "High",
    "moderate":  "Medium",
    "low":       "Low",
}
# fix_state values that mean the package is still affected (no released fix)
_RH_UNFIXED_STATES = {"affected", "fix deferred", "will not fix"}


def _rh_package_state(cve_id: str, pkg_name: str, el: str,
                       verbose: bool = False,
                       db: Optional[CacheDB] = None) -> tuple:
    """Fetch the Red Hat detailed CVE endpoint and return the package_state entry
    for pkg_name on RHEL major version el, or None if not found / not affected.

    Caches the package_state list under key 'cve_detail:{cve_id}' in rh_pkg.

    Returns (entry_or_None, detail_hit, detail_miss) where exactly one of
    detail_hit / detail_miss is 1, indicating whether the response was served
    from the local cache or fetched from the network.
    """
    cache_key = f"cve_detail:{cve_id}"
    ps_list = _CACHE_MISS
    detail_hit = detail_miss = 0

    if db is not None:
        ps_list = db.get_rh(cache_key)
        if ps_list is not _CACHE_MISS:
            detail_hit = 1
            if verbose:
                print(f"      RH cve_detail cache hit: {cve_id}", file=sys.stderr)

    if ps_list is _CACHE_MISS:
        detail_miss = 1
        url = f"{_RH_CVE_DETAIL_URL}/{quote(cve_id)}.json"
        if verbose:
            print(f"      RH cve_detail fetch: {cve_id}", file=sys.stderr)
        try:
            obj = _http_get(url)
            ps_list = obj.get("package_state", []) if isinstance(obj, dict) else []
        except Exception as exc:
            print(f"  [WARNING] Red Hat API (detail {cve_id}): {exc}", file=sys.stderr)
            ps_list = []
        if db is not None:
            db.put_rh(cache_key, ps_list)
        time.sleep(0.2)

    for ps in ps_list:
        if ps.get("package_name", "").lower() != pkg_name.lower():
            continue
        cpe  = ps.get("cpe", "").lower()
        pnam = ps.get("product_name", "").lower()
        # Match CPE strings like cpe:/o:redhat:enterprise_linux:9 or
        # product names like "Red Hat Enterprise Linux 9"
        if (f"enterprise_linux:{el}" in cpe or f":el{el}" in cpe
                or f" {el}" in pnam or pnam.endswith(f":{el}")):
            return ps, detail_hit, detail_miss
    return None, detail_hit, detail_miss


def _query_redhat(packages: list, verbose: bool = False,
                  db: Optional[CacheDB] = None) -> tuple:
    """Supplemental Red Hat Security API lookup for packages with .el/.fc versions.

    OSV's CVE records sometimes lack package-level affected entries (only GIT
    ranges), making them invisible to OSV batch queries.  Red Hat's own security
    data API provides authoritative per-package CVE lists directly.

    For each package whose version contains an .elN or .fcN suffix, this
    function queries the Red Hat API for all CVEs affecting that package name,
    then checks whether the installed version is less than the fixed version
    listed in the advisory.

    Returns (vuln_map, pkg_hits, pkg_misses, detail_hits, detail_misses).
    pkg_hits/misses count the package-level summary queries (/cve.json?package=X).
    detail_hits/misses count the per-CVE detail queries (/cve/CVE-XXXX.json).
    """
    import re

    vuln_map: list = [[] for _ in packages]
    rh_hits = rh_misses = 0
    detail_hits = detail_misses = 0

    for i, pkg in enumerate(packages):
        if not re.search(r'\.(el|fc)\d', pkg.version.lower()):
            continue

        el = _el_major(pkg.version)
        if not el:
            continue

        cache_key = f"{el}:{pkg.name.lower()}"

        cves = _CACHE_MISS
        if db is not None:
            cves = db.get_rh(cache_key)
            if cves is not _CACHE_MISS:
                rh_hits += 1
                if verbose:
                    print(f"      RH cache hit: {cache_key}", file=sys.stderr)

        if cves is _CACHE_MISS:
            url = f"{_RH_CVE_URL}?package={quote(pkg.name)}&per_page=1000"
            if verbose:
                print(f"      RH fetch: {pkg.name} (el{el})", file=sys.stderr)
            try:
                cves = _http_get(url)
                if not isinstance(cves, list):
                    cves = []
            except Exception as exc:
                print(f"  [WARNING] Red Hat API: {pkg.name}: {exc}", file=sys.stderr)
                cves = []
            rh_misses += 1
            if db is not None:
                db.put_rh(cache_key, cves)
            time.sleep(0.2)   # gentle rate limiting

        for entry in cves:
            cve_id = entry.get("CVE", "")
            if not cve_id.startswith("CVE-"):
                continue

            # Find the fixed version for this package on this exact .elN stream
            fixed_evr = None
            for fp in entry.get("affected_packages", []):
                evr = _rh_fixed_evr(fp, pkg.name)
                if evr and f".el{el}" in evr.lower():
                    fixed_evr = evr
                    break

            if fixed_evr is None:
                # No patch released for this el stream yet.
                # Check the detailed CVE endpoint: if the package is explicitly
                # listed in package_state as still-affected, report it anyway
                # (with no fixed_version) so the user knows it is unpatched.
                ps_entry, dh, dm = _rh_package_state(
                    cve_id, pkg.name, el, verbose, db
                )
                detail_hits   += dh
                detail_misses += dm
                if ps_entry is None:
                    continue
                fix_state = ps_entry.get("fix_state", "").lower()
                if fix_state not in _RH_UNFIXED_STATES:
                    continue
                affected_ranges_val = [
                    f"Affected (fix_state: {ps_entry.get('fix_state','unknown')})"
                ]
            else:
                try:
                    if not _rpm_lt(pkg.version, fixed_evr):
                        continue   # installed version >= fixed version; already patched
                except Exception:
                    continue
                affected_ranges_val = [f"< {fixed_evr}"]

            # Build CVSS object from Red Hat's data
            vector = (entry.get("cvss3_scoring_vector") or
                      entry.get("cvss_scoring_vector") or "")
            try:
                score = float(entry.get("cvss3_score") or entry.get("cvss_score") or 0)
            except (ValueError, TypeError):
                score = 0.0

            cvss = None
            if vector or score:
                parsed_m = _parse_cvss_v3_vector(vector) if vector else {}
                computed  = _compute_cvss_v3_score(vector) if vector else score
                cvss = CvssV3(
                    vector_string=vector,
                    base_score=score or computed,
                    severity=_score_to_severity(score or computed),
                    attack_vector=parsed_m.get("AV", ""),
                    attack_complexity=parsed_m.get("AC", ""),
                    privileges_required=parsed_m.get("PR", ""),
                    user_interaction=parsed_m.get("UI", ""),
                    scope=parsed_m.get("S", ""),
                    confidentiality_impact=parsed_m.get("C", ""),
                    integrity_impact=parsed_m.get("I", ""),
                    availability_impact=parsed_m.get("A", ""),
                )

            sev_rh  = (entry.get("severity") or "").lower()
            sev_lbl = _RH_SEV_MAP.get(sev_rh, "")
            if not sev_lbl:
                sev_lbl = _score_to_severity(score or 0) if score else "Unknown"

            pub  = (entry.get("public_date") or "")[:10]
            refs = [
                {"type": "ADVISORY",
                 "url": f"https://access.redhat.com/security/cve/{cve_id}"},
                {"type": "WEB",
                 "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
            ]
            for adv in entry.get("advisories", []):
                refs.append({"type": "ADVISORY",
                             "url": f"https://access.redhat.com/errata/{adv}"})

            vuln_map[i].append(Vulnerability(
                id=cve_id,
                aliases=[cve_id],
                cve_ids=[cve_id],
                summary=entry.get("bugzilla_description", ""),
                details="",
                cvss_v3=cvss,
                severity_label=sev_lbl,
                affected_ranges=affected_ranges_val,
                fixed_version=fixed_evr,
                published=pub,
                modified=pub,
                references=refs,
            ))

    return vuln_map, rh_hits, rh_misses, detail_hits, detail_misses


# ─── Console Report ───────────────────────────────────────────────────────────

_SEV_COLOR = {
    "Critical": "\033[91m", "High": "\033[31m",
    "Medium": "\033[33m",   "Low": "\033[32m",
    "None": "\033[0m",      "Unknown": "\033[0m",
}
_RESET = "\033[0m"
_BOLD  = "\033[1m"
_GREEN = "\033[32m"


def _sev_color(label: str, text: str, use_color: bool) -> str:
    return f"{_SEV_COLOR.get(label,'')}{text}{_RESET}" if use_color else text


def _wrap(text: str, width: int, indent: str = "  ") -> str:
    words = text.split()
    lines, line = [], indent
    for w in words:
        if len(line) + len(w) + 1 > width:
            lines.append(line.rstrip())
            line = " " * len(indent) + w + " "
        else:
            line += w + " "
    lines.append(line.rstrip())
    return "\n".join(lines)


def print_console_report(reports: list, use_color: bool = True):
    total   = sum(r.vuln_count for r in reports)
    vuln_pkgs = sum(1 for r in reports if r.vuln_count > 0)
    critical  = sum(r.critical_count for r in reports)
    high      = sum(r.high_count for r in reports)
    medium    = sum(1 for r in reports for v in r.vulnerabilities if v.severity_label == "Medium")
    low_cnt   = sum(1 for r in reports for v in r.vulnerabilities if v.severity_label == "Low")

    sep = "-" * 72
    print()
    print("=" * 72)
    print(f"  SBOM CVE SCAN REPORT  --  {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 72)
    print(f"  Packages scanned  : {len(reports)}")
    print(f"  Vulnerable pkgs   : {vuln_pkgs}")
    print(f"  Total CVEs found  : {total}")
    print(f"  Critical          : {_sev_color('Critical', str(critical), use_color)}")
    print(f"  High              : {_sev_color('High',     str(high),     use_color)}")
    print(f"  Medium            : {_sev_color('Medium',   str(medium),   use_color)}")
    print(f"  Low               : {_sev_color('Low',      str(low_cnt),  use_color)}")
    print("=" * 72)
    print()

    for report in sorted(reports, key=lambda r: r.critical_count + r.high_count, reverse=True):
        if report.error:
            print(f"  [ERROR] {report.package.display()}: {report.error}")
            continue
        if not report.vulnerabilities:
            continue

        print(sep)
        hdr = (f"PACKAGE: {report.package.display()}  "
               f"({report.vuln_count} vulnerabilit{'y' if report.vuln_count == 1 else 'ies'})")
        print(f"{_BOLD}{hdr}{_RESET}" if use_color else hdr)
        print()

        for vuln in sorted(report.vulnerabilities,
                           key=lambda v: v.cvss_v3.base_score if v.cvss_v3 else 0,
                           reverse=True):
            sev  = vuln.severity_label
            score_str = f" | CVSS {vuln.cvss_v3.base_score}" if vuln.cvss_v3 and vuln.cvss_v3.base_score else ""
            label_str = _sev_color(sev, f"[{sev.upper()}]", use_color)
            print(f"  {label_str} {vuln.primary_id()}{score_str}")

            if vuln.primary_id() != vuln.id:
                print(f"  OSV ID   : {vuln.id}")
            if vuln.cve_ids:
                print(f"  CVE IDs  : {', '.join(vuln.cve_ids)}")

            if vuln.summary:
                print(_wrap(f"Summary  : {vuln.summary}", 72))

            if vuln.details and vuln.details != vuln.summary:
                snippet = vuln.details[:300].replace("\n", " ")
                if len(vuln.details) > 300:
                    snippet += "..."
                print(_wrap(f"Details  : {snippet}", 72))

            if vuln.cvss_v3:
                c = vuln.cvss_v3
                print(f"  Vector   : {c.vector_string}")
                if c.attack_vector:
                    print(f"  | Attack Vector      : {c.attack_vector}")
                    print(f"  | Attack Complexity  : {c.attack_complexity}")
                    print(f"  | Privileges Req.    : {c.privileges_required}")
                    print(f"  | User Interaction   : {c.user_interaction}")
                    if c.scope:
                        print(f"  | Scope              : {c.scope}")
                    print(f"  | Confidentiality    : {c.confidentiality_impact}")
                    print(f"  | Integrity          : {c.integrity_impact}")
                    print(f"  | Availability       : {c.availability_impact}")

            if vuln.affected_ranges:
                print(f"  Affected : {vuln.affected_ranges[0]}")

            if vuln.fixed_version:
                fix_line = f"  Fix      : Upgrade to >= {vuln.fixed_version}"
                print(f"{_GREEN}{fix_line}{_RESET}" if use_color else fix_line)
            else:
                print("  Fix      : No fix available - monitor upstream for patches")

            if vuln.published:
                pub = vuln.published[:10]
                mod = vuln.modified[:10] if vuln.modified else ""
                print(f"  Published: {pub}" + (f"  (modified {mod})" if mod != pub else ""))

            if vuln.references:
                print("  Refs     :")
                for ref in vuln.references[:6]:
                    rtype = ref.get("type", "URL")
                    url   = ref.get("url", "")
                    print(f"    [{rtype}] {url}")

            print()

    print(sep)

    if vuln_pkgs == 0:
        print("  No vulnerabilities found.")
    else:
        print(f"  REMEDIATION PRIORITY LIST")
        print()
        rows = []
        for report in reports:
            for vuln in report.vulnerabilities:
                score = vuln.cvss_v3.base_score if vuln.cvss_v3 else 0
                rows.append((score, vuln.severity_label, report.package.display(),
                             vuln.primary_id(), vuln.fixed_version))
        for score, sev, pkg, vid, fix in sorted(rows, key=lambda x: -x[0]):
            fix_str = f"upgrade to >= {fix}" if fix else "no fix available"
            badge   = _sev_color(sev, f"[{sev[:4].upper()}]", use_color)
            sc_str  = f"({score})" if score else "     "
            print(f"  {badge} {sc_str} {pkg}")
            print(f"           {vid}  =>  {fix_str}")
    print()


def print_console_diff(diff: dict, baseline_src: str, current_src: str, use_color: bool = True):
    sep    = "-" * 72
    n_rem  = len(diff["remediated"])
    n_new  = len(diff["introduced"])
    n_pers = len(diff["persistent"])
    n_add  = len(diff["packages_added"])
    n_del  = len(diff["packages_removed"])
    n_upg  = len(diff["packages_upgraded"])

    print()
    print("=" * 72)
    print(f"  SBOM CVE DIFF REPORT  --  {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 72)
    print(f"  Baseline : {baseline_src}")
    print(f"  Current  : {current_src}")
    print()
    rem_line  = f"  Remediated (fixed)        : {n_rem}"
    new_line  = f"  Introduced (new)          : {n_new}"
    print(_sev_color("Low",      rem_line, use_color) if n_rem else rem_line)
    print(_sev_color("Critical", new_line, use_color) if n_new else new_line)
    print(f"  Persistent (unchanged)    : {n_pers}")
    print()
    print(f"  Packages added            : {n_add}")
    print(f"  Packages removed          : {n_del}")
    print(f"  Packages upgraded         : {n_upg}")
    print("=" * 72)

    def _row(report, vuln):
        sev   = vuln.severity_label
        score = f" ({vuln.cvss_v3.base_score})" if vuln.cvss_v3 and vuln.cvss_v3.base_score else ""
        fix   = (f"  => upgrade to >= {vuln.fixed_version}"
                 if vuln.fixed_version else "  => no fix available")
        badge = _sev_color(sev, f"[{sev[:4].upper()}]", use_color)
        print(f"  {badge}{score}  {report.package.display()}")
        print(f"           {vuln.primary_id()}{fix}")

    def _sorted_pairs(pairs):
        return sorted(pairs,
                      key=lambda rv: rv[1].cvss_v3.base_score if rv[1].cvss_v3 else 0,
                      reverse=True)

    if diff["remediated"]:
        print()
        print(f"--- REMEDIATED ({n_rem}) ---")
        print("  These vulnerabilities were in the baseline and are no longer detected.")
        print()
        for r, v in _sorted_pairs(diff["remediated"]):
            _row(r, v)

    if diff["introduced"]:
        print()
        print(f"--- INTRODUCED ({n_new}) ---")
        print("  These vulnerabilities are newly detected and were not in the baseline.")
        print()
        for r, v in _sorted_pairs(diff["introduced"]):
            _row(r, v)

    if diff["persistent"]:
        print()
        print(f"--- PERSISTENT ({n_pers}) ---")
        print("  These vulnerabilities remain unaddressed in both scans.")
        print()
        for r, v in _sorted_pairs(diff["persistent"]):
            _row(r, v)

    if n_add or n_del or n_upg:
        print()
        print("--- PACKAGE CHANGES ---")
        for pkg in sorted(diff["packages_added"], key=lambda p: p.name.lower()):
            print(f"  ADDED   : {pkg.display()}")
        for pkg in sorted(diff["packages_removed"], key=lambda p: p.name.lower()):
            print(f"  REMOVED : {pkg.display()}")
        for bp, cp in sorted(diff["packages_upgraded"], key=lambda t: t[0].name.lower()):
            print(f"  UPGRADED: {bp.ecosystem}/{bp.name}  {bp.version} => {cp.version}")

    print()
    print(sep)
    print()


# ─── JSON Report ──────────────────────────────────────────────────────────────

def to_json_report(reports: list, asset_name: str = "", asset_version: str = "") -> str:
    def _cvss_dict(c: CvssV3) -> dict:
        return {
            "base_score": c.base_score, "severity": c.severity,
            "vector_string": c.vector_string,
            "attack_vector": c.attack_vector, "attack_complexity": c.attack_complexity,
            "privileges_required": c.privileges_required, "user_interaction": c.user_interaction,
            "scope": c.scope, "confidentiality_impact": c.confidentiality_impact,
            "integrity_impact": c.integrity_impact, "availability_impact": c.availability_impact,
        }

    out = {
        "generated_at": datetime.now().isoformat(),
        "tool": "sbom-cve-checker",
        "asset_name":    asset_name    or None,
        "asset_version": asset_version or None,
        "summary": {
            "total_packages": len(reports),
            "vulnerable_packages": sum(1 for r in reports if r.vuln_count > 0),
            "total_vulnerabilities": sum(r.vuln_count for r in reports),
            "by_severity": {
                "critical": sum(r.critical_count for r in reports),
                "high":     sum(r.high_count for r in reports),
                "medium":   sum(1 for r in reports for v in r.vulnerabilities if v.severity_label == "Medium"),
                "low":      sum(1 for r in reports for v in r.vulnerabilities if v.severity_label == "Low"),
                "unknown":  sum(1 for r in reports for v in r.vulnerabilities if v.severity_label == "Unknown"),
            },
        },
        "packages": [],
    }

    for report in reports:
        entry: dict = {
            "name": report.package.name,
            "version": report.package.version,
            "ecosystem": report.package.ecosystem,
            "purl": report.package.purl,
            "vulnerability_count": report.vuln_count,
            "error": report.error,
            "vulnerabilities": [],
        }
        for vuln in report.vulnerabilities:
            v: dict = {
                "id": vuln.id,
                "primary_id": vuln.primary_id(),
                "cve_ids": vuln.cve_ids,
                "aliases": vuln.aliases,
                "summary": vuln.summary,
                "details": vuln.details,
                "severity": vuln.severity_label,
                "cvss_v3": _cvss_dict(vuln.cvss_v3) if vuln.cvss_v3 else None,
                "affected_ranges": vuln.affected_ranges,
                "fixed_version": vuln.fixed_version,
                "remediation": f"Upgrade to >= {vuln.fixed_version}" if vuln.fixed_version else "No fix available",
                "published": vuln.published,
                "modified": vuln.modified,
                "references": vuln.references,
            }
            entry["vulnerabilities"].append(v)
        out["packages"].append(entry)

    return json.dumps(out, indent=2)


def to_json_diff(diff: dict, baseline_src: str, current_src: str) -> str:
    def _vuln_entry(report, vuln) -> dict:
        c = vuln.cvss_v3
        return {
            "package": {
                "name":      report.package.name,
                "version":   report.package.version,
                "ecosystem": report.package.ecosystem,
            },
            "id":          vuln.id,
            "primary_id":  vuln.primary_id(),
            "cve_ids":     vuln.cve_ids,
            "severity":    vuln.severity_label,
            "cvss_score":  c.base_score if c else None,
            "summary":     vuln.summary,
            "fixed_version": vuln.fixed_version,
            "remediation": (f"Upgrade to >= {vuln.fixed_version}"
                            if vuln.fixed_version else "No fix available"),
        }

    def _pkg_entry(pkg) -> dict:
        return {"name": pkg.name, "version": pkg.version, "ecosystem": pkg.ecosystem}

    out = {
        "generated_at": datetime.now().isoformat(),
        "tool": "sbom-cve-checker",
        "diff": {
            "baseline_source": baseline_src,
            "current_source":  current_src,
            "summary": {
                "remediated":        len(diff["remediated"]),
                "introduced":        len(diff["introduced"]),
                "persistent":        len(diff["persistent"]),
                "packages_added":    len(diff["packages_added"]),
                "packages_removed":  len(diff["packages_removed"]),
                "packages_upgraded": len(diff["packages_upgraded"]),
            },
            "remediated": [_vuln_entry(r, v) for r, v in diff["remediated"]],
            "introduced": [_vuln_entry(r, v) for r, v in diff["introduced"]],
            "persistent": [_vuln_entry(r, v) for r, v in diff["persistent"]],
            "packages_added":    [_pkg_entry(p) for p in diff["packages_added"]],
            "packages_removed":  [_pkg_entry(p) for p in diff["packages_removed"]],
            "packages_upgraded": [
                {
                    "name": bp.name, "ecosystem": bp.ecosystem,
                    "baseline_version": bp.version, "current_version": cp.version,
                }
                for bp, cp in diff["packages_upgraded"]
            ],
        },
    }
    return json.dumps(out, indent=2)


# ─── CSV Report ───────────────────────────────────────────────────────────────

def to_csv_report(reports: list) -> str:
    out = io.StringIO()
    fields = [
        "package_name", "package_version", "ecosystem",
        "vuln_id", "cve_ids", "severity", "cvss_score", "cvss_vector",
        "attack_vector", "attack_complexity", "privileges_required",
        "user_interaction", "scope",
        "confidentiality_impact", "integrity_impact", "availability_impact",
        "summary", "fixed_version", "remediation",
        "published", "modified", "references",
    ]
    w = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    for report in reports:
        for vuln in report.vulnerabilities:
            c = vuln.cvss_v3
            w.writerow({
                "package_name":    report.package.name,
                "package_version": report.package.version,
                "ecosystem":       report.package.ecosystem,
                "vuln_id":         vuln.id,
                "cve_ids":         "; ".join(vuln.cve_ids),
                "severity":        vuln.severity_label,
                "cvss_score":      c.base_score if c else "",
                "cvss_vector":     c.vector_string if c else "",
                "attack_vector":   c.attack_vector if c else "",
                "attack_complexity": c.attack_complexity if c else "",
                "privileges_required": c.privileges_required if c else "",
                "user_interaction": c.user_interaction if c else "",
                "scope":           c.scope if c else "",
                "confidentiality_impact": c.confidentiality_impact if c else "",
                "integrity_impact": c.integrity_impact if c else "",
                "availability_impact": c.availability_impact if c else "",
                "summary":         vuln.summary,
                "fixed_version":   vuln.fixed_version or "",
                "remediation":     f"Upgrade to >= {vuln.fixed_version}" if vuln.fixed_version else "No fix available",
                "published":       vuln.published[:10] if vuln.published else "",
                "modified":        vuln.modified[:10] if vuln.modified else "",
                "references":      "; ".join(r.get("url", "") for r in vuln.references[:5]),
            })
    return out.getvalue()


def to_csv_diff(diff: dict) -> str:
    out = io.StringIO()
    fields = [
        "change_type", "package_name", "package_version", "ecosystem",
        "vuln_id", "cve_ids", "severity", "cvss_score",
        "summary", "fixed_version", "remediation",
    ]
    w = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
    w.writeheader()

    def _write(pairs, change_type):
        for report, vuln in pairs:
            c = vuln.cvss_v3
            w.writerow({
                "change_type":     change_type,
                "package_name":    report.package.name,
                "package_version": report.package.version,
                "ecosystem":       report.package.ecosystem,
                "vuln_id":         vuln.id,
                "cve_ids":         "; ".join(vuln.cve_ids),
                "severity":        vuln.severity_label,
                "cvss_score":      c.base_score if c else "",
                "summary":         vuln.summary,
                "fixed_version":   vuln.fixed_version or "",
                "remediation":     (f"Upgrade to >= {vuln.fixed_version}"
                                    if vuln.fixed_version else "No fix available"),
            })

    _write(diff["remediated"], "REMEDIATED")
    _write(diff["introduced"], "INTRODUCED")
    _write(diff["persistent"], "PERSISTENT")
    return out.getvalue()


# ─── HTML Report ──────────────────────────────────────────────────────────────

_SEV_BADGE = {
    "Critical": "#8b0000", "High": "#dc3545",
    "Medium": "#fd7e14",   "Low":  "#ffc107",
    "None": "#28a745",     "Unknown": "#6c757d",
}


def to_html_report(reports: list) -> str:
    total     = sum(r.vuln_count for r in reports)
    vuln_pkgs = sum(1 for r in reports if r.vuln_count > 0)
    critical  = sum(r.critical_count for r in reports)
    high      = sum(r.high_count for r in reports)

    def badge(sev: str) -> str:
        color = _SEV_BADGE.get(sev, "#6c757d")
        return (f'<span style="background:{color};color:white;padding:2px 8px;'
                f'border-radius:4px;font-size:.85em;font-weight:bold">{sev.upper()}</span>')

    rows_html = []
    for report in sorted(reports, key=lambda r: r.critical_count + r.high_count, reverse=True):
        for vuln in sorted(report.vulnerabilities,
                           key=lambda v: v.cvss_v3.base_score if v.cvss_v3 else 0,
                           reverse=True):
            c = vuln.cvss_v3
            score = f"<b>{c.base_score}</b>" if c and c.base_score else "N/A"
            refs  = " ".join(
                f'<a href="{r.get("url","")}" target="_blank" rel="noopener">[{r.get("type","REF")}]</a>'
                for r in vuln.references[:5]
            )
            fix = (f'<code style="color:#155724">≥ {vuln.fixed_version}</code>'
                   if vuln.fixed_version else '<em style="color:#721c24">No fix available</em>')

            cvss_rows = ""
            if c and c.attack_vector:
                def tr(label, val):
                    return f'<tr><td style="padding:2px 8px;color:#555">{label}</td><td><b>{val}</b></td></tr>'
                cvss_rows = f"""
                <details style="margin-top:6px">
                  <summary style="cursor:pointer;color:#0066cc;font-size:.85em">CVSS Details</summary>
                  <table style="font-size:.85em;border-collapse:collapse;margin-top:4px">
                    <tr><td style="padding:2px 8px;color:#555">Vector</td>
                        <td><code style="font-size:.8em">{c.vector_string}</code></td></tr>
                    {tr("Attack Vector", c.attack_vector)}
                    {tr("Attack Complexity", c.attack_complexity)}
                    {tr("Privileges Required", c.privileges_required)}
                    {tr("User Interaction", c.user_interaction)}
                    {tr("Scope", c.scope) if c.scope else ""}
                    {tr("Confidentiality", c.confidentiality_impact)}
                    {tr("Integrity", c.integrity_impact)}
                    {tr("Availability", c.availability_impact)}
                  </table>
                </details>"""

            cve_cell = (f'<code style="font-weight:bold">{vuln.primary_id()}</code>'
                        + (f'<br><small style="color:#888">{vuln.id}</small>'
                           if vuln.primary_id() != vuln.id else ""))

            rows_html.append(f"""
              <tr>
                <td>{report.package.name}<br>
                  <small style="color:#666">{report.package.version} · {report.package.ecosystem}</small></td>
                <td>{cve_cell}</td>
                <td style="text-align:center;white-space:nowrap">{badge(vuln.severity_label)}<br>{score}</td>
                <td>{vuln.summary or "—"}{cvss_rows}</td>
                <td>{fix}</td>
                <td style="font-size:.85em">{refs}</td>
              </tr>""")

    if not rows_html:
        rows_html = ['<tr><td colspan="6" style="text-align:center;padding:24px;color:#555">No vulnerabilities found</td></tr>']

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SBOM CVE Report — {datetime.now().strftime('%Y-%m-%d')}</title>
<style>
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;margin:0;padding:20px;background:#f5f6fa}}
  .card{{max-width:1300px;margin:0 auto;background:#fff;padding:28px;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.12)}}
  h1{{margin:0 0 4px;color:#212529}}
  .meta{{color:#6c757d;font-size:.9em;margin-bottom:20px}}
  .summary{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}}
  .stat{{border:1px solid #dee2e6;border-radius:6px;padding:12px 20px;text-align:center;min-width:90px}}
  .stat .n{{font-size:2em;font-weight:700;line-height:1}}
  .stat .l{{color:#6c757d;font-size:.8em;margin-top:4px}}
  .crit .n{{color:#8b0000}} .hi .n{{color:#dc3545}}
  table{{width:100%;border-collapse:collapse;font-size:.9em}}
  thead{{background:#343a40;color:#fff}}
  thead th{{padding:10px 8px;text-align:left;font-weight:600}}
  tbody td{{padding:8px;border:1px solid #dee2e6;vertical-align:top}}
  tbody tr:hover{{background:#f8f9fa}}
  code{{background:#f1f3f5;padding:1px 4px;border-radius:3px;font-size:.85em}}
</style>
</head>
<body>
<div class="card">
  <h1>SBOM CVE Scan Report</h1>
  <p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} · Tool: sbom-cve-checker · Data: OSV.dev + NIST NVD</p>
  <div class="summary">
    <div class="stat"><div class="n">{len(reports)}</div><div class="l">Packages</div></div>
    <div class="stat"><div class="n">{vuln_pkgs}</div><div class="l">Vulnerable</div></div>
    <div class="stat"><div class="n">{total}</div><div class="l">Total CVEs</div></div>
    <div class="stat crit"><div class="n">{critical}</div><div class="l">Critical</div></div>
    <div class="stat hi"><div class="n">{high}</div><div class="l">High</div></div>
  </div>
  <table>
    <thead>
      <tr>
        <th style="width:16%">Package</th>
        <th style="width:12%">CVE / ID</th>
        <th style="width:10%">Severity</th>
        <th>Description &amp; CVSS Metrics</th>
        <th style="width:14%">Remediation</th>
        <th style="width:12%">References</th>
      </tr>
    </thead>
    <tbody>{''.join(rows_html)}</tbody>
  </table>
</div>
</body>
</html>"""


def to_html_diff(diff: dict, baseline_src: str, current_src: str) -> str:
    n_rem  = len(diff["remediated"])
    n_new  = len(diff["introduced"])
    n_pers = len(diff["persistent"])

    def badge(sev: str) -> str:
        color = _SEV_BADGE.get(sev, "#6c757d")
        return (f'<span style="background:{color};color:white;padding:2px 8px;'
                f'border-radius:4px;font-size:.85em;font-weight:bold">{sev.upper()}</span>')

    def _vuln_rows(pairs, row_bg):
        rows = []
        for report, vuln in sorted(pairs,
                                   key=lambda rv: rv[1].cvss_v3.base_score if rv[1].cvss_v3 else 0,
                                   reverse=True):
            c = vuln.cvss_v3
            score = f"<b>{c.base_score}</b>" if c and c.base_score else "N/A"
            fix   = (f'<code style="color:#155724">&ge; {vuln.fixed_version}</code>'
                     if vuln.fixed_version else '<em style="color:#721c24">No fix available</em>')
            rows.append(f"""
              <tr style="background:{row_bg}">
                <td>{report.package.name}<br>
                  <small style="color:#666">{report.package.version} &middot; {report.package.ecosystem}</small></td>
                <td><code>{vuln.primary_id()}</code></td>
                <td style="text-align:center">{badge(vuln.severity_label)}<br>{score}</td>
                <td>{vuln.summary or "&mdash;"}</td>
                <td>{fix}</td>
              </tr>""")
        return "".join(rows)

    def _section(title, pairs, bg, empty_msg):
        if not pairs:
            return (f'<h2 style="margin-top:32px">{title} (0)</h2>'
                    f'<p style="color:#6c757d">{empty_msg}</p>')
        rows = _vuln_rows(pairs, bg)
        return f"""
        <h2 style="margin-top:32px">{title} ({len(pairs)})</h2>
        <table>
          <thead>
            <tr><th style="width:18%">Package</th><th style="width:13%">CVE / ID</th>
                <th style="width:10%">Severity</th><th>Summary</th>
                <th style="width:15%">Remediation</th></tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>"""

    pkg_rows = []
    for pkg in sorted(diff["packages_added"], key=lambda p: p.name.lower()):
        pkg_rows.append(
            f'<tr style="background:#d4edda"><td><b>ADDED</b></td>'
            f'<td>{pkg.name}</td><td>{pkg.version}</td><td>{pkg.ecosystem}</td></tr>')
    for pkg in sorted(diff["packages_removed"], key=lambda p: p.name.lower()):
        pkg_rows.append(
            f'<tr style="background:#f8d7da"><td><b>REMOVED</b></td>'
            f'<td>{pkg.name}</td><td>{pkg.version}</td><td>{pkg.ecosystem}</td></tr>')
    for bp, cp in sorted(diff["packages_upgraded"], key=lambda t: t[0].name.lower()):
        pkg_rows.append(
            f'<tr style="background:#fff3cd"><td><b>UPGRADED</b></td><td>{bp.name}</td>'
            f'<td><del style="color:#721c24">{bp.version}</del>'
            f' &rarr; <b style="color:#155724">{cp.version}</b></td>'
            f'<td>{bp.ecosystem}</td></tr>')

    pkg_table = ""
    if pkg_rows:
        pkg_table = f"""
        <h2 style="margin-top:32px">Package Changes</h2>
        <table>
          <thead><tr><th>Change</th><th>Package</th><th>Version</th><th>Ecosystem</th></tr></thead>
          <tbody>{''.join(pkg_rows)}</tbody>
        </table>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SBOM CVE Diff -- {datetime.now().strftime('%Y-%m-%d')}</title>
<style>
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;margin:0;padding:20px;background:#f5f6fa}}
  .card{{max-width:1300px;margin:0 auto;background:#fff;padding:28px;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.12)}}
  h1{{margin:0 0 4px;color:#212529}}
  h2{{color:#212529;border-bottom:1px solid #dee2e6;padding-bottom:6px}}
  .meta{{color:#6c757d;font-size:.9em;margin-bottom:20px}}
  .summary{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}}
  .stat{{border:1px solid #dee2e6;border-radius:6px;padding:12px 20px;text-align:center;min-width:90px}}
  .stat .n{{font-size:2em;font-weight:700;line-height:1}}
  .stat .l{{color:#6c757d;font-size:.8em;margin-top:4px}}
  .rem .n{{color:#28a745}} .new .n{{color:#dc3545}} .pers .n{{color:#fd7e14}}
  table{{width:100%;border-collapse:collapse;font-size:.9em;margin-bottom:12px}}
  thead{{background:#343a40;color:#fff}}
  thead th{{padding:10px 8px;text-align:left;font-weight:600}}
  tbody td{{padding:8px;border:1px solid #dee2e6;vertical-align:top}}
  tbody tr:hover{{filter:brightness(.97)}}
  code{{background:#f1f3f5;padding:1px 4px;border-radius:3px;font-size:.85em}}
</style>
</head>
<body>
<div class="card">
  <h1>SBOM CVE Diff Report</h1>
  <p class="meta">
    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
    Baseline: <code>{baseline_src}</code> &rarr; Current: <code>{current_src}</code>
  </p>
  <div class="summary">
    <div class="stat rem"><div class="n">{n_rem}</div><div class="l">Remediated</div></div>
    <div class="stat new"><div class="n">{n_new}</div><div class="l">Introduced</div></div>
    <div class="stat pers"><div class="n">{n_pers}</div><div class="l">Persistent</div></div>
    <div class="stat"><div class="n">{len(diff['packages_added'])}</div><div class="l">Pkg Added</div></div>
    <div class="stat"><div class="n">{len(diff['packages_removed'])}</div><div class="l">Pkg Removed</div></div>
    <div class="stat"><div class="n">{len(diff['packages_upgraded'])}</div><div class="l">Pkg Upgraded</div></div>
  </div>
  {_section("Remediated Vulnerabilities", diff["remediated"], "#d4edda",
            "No vulnerabilities were remediated.")}
  {_section("Introduced Vulnerabilities",  diff["introduced"],  "#f8d7da",
            "No new vulnerabilities were introduced.")}
  {_section("Persistent Vulnerabilities",  diff["persistent"],  "#fff3cd",
            "No persistent vulnerabilities.")}
  {pkg_table}
</div>
</body>
</html>"""


# ─── Main ─────────────────────────────────────────────────────────────────────

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0, "unknown": 0}


def main():
    ap = argparse.ArgumentParser(
        description="Check SBOM packages against CVE vulnerability databases (OSV.dev + NVD).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --sbom sbom.json
  %(prog)s --sbom sbom.cdx.json --format html --output report.html
  %(prog)s --sbom packages.csv --nvd-api-key YOUR_KEY --format json --output report.json
  %(prog)s --sbom sbom.json --min-severity high --no-nvd
  %(prog)s --cache-info
  %(prog)s --clear-cache
        """
    )
    ap.add_argument("--sbom",        type=Path,
                    help="SBOM file (CycloneDX JSON, SPDX JSON, simple JSON, or CSV). "
                         "Not required when --baseline and --compare are both given.")
    ap.add_argument("--baseline",    type=Path, metavar="PATH",
                    help="Previous JSON scan report to use as the baseline for diff mode. "
                         "When provided, output shows remediated/introduced/persistent CVEs.")
    ap.add_argument("--compare",     type=Path, metavar="PATH",
                    help="Use this JSON scan report as the 'current' state instead of running "
                         "a live scan. Requires --baseline. Makes --sbom optional.")
    ap.add_argument("--format",      choices=["console", "json", "csv", "html"],
                    default="console", help="Output format (default: console)")
    ap.add_argument("--output",      type=Path,
                    help="Write output to this file (default: stdout)")
    ap.add_argument("--nvd-api-key", metavar="KEY",
                    help="NIST NVD API key for authoritative CVSS scores "
                         "(https://nvd.nist.gov/developers/request-an-api-key)")
    ap.add_argument("--no-nvd",      action="store_true",
                    help="Skip NVD enrichment (uses OSV CVSS data + computed scores only)")
    ap.add_argument("--no-redhat",   action="store_true",
                    help="Skip the Red Hat Security API supplemental lookup for .el/.fc packages")
    ap.add_argument("--min-severity",
                    choices=["critical", "high", "medium", "low"],
                    help="Only report at or above this severity")
    ap.add_argument("--base-image",  metavar="IMAGE",
                    help="Base container image used to build the scanned image "
                         "(e.g. 'debian:bullseye', 'python:3.9-slim-bullseye', "
                         "'node:18-alpine3.17'). Used to resolve the OS ecosystem for "
                         "packages in the custom scanner format.")
    ap.add_argument("--distro",      metavar="DISTRO",
                    help="Explicit OS ecosystem override, e.g. 'debian:11', "
                         "'ubuntu:22.04', 'alpine:v3.17'. Takes precedence over "
                         "--base-image when both are supplied.")
    ap.add_argument("--asset-name",  metavar="NAME",
                    help="Logical name of the scanned asset (e.g. 'myapp'). "
                         "Embedded in JSON output for use by sbom_portal.py.")
    ap.add_argument("--asset-version", metavar="VER",
                    help="Version of the scanned asset (e.g. '2.1.0'). "
                         "Embedded in JSON output for use by sbom_portal.py.")
    ap.add_argument("--no-color",    action="store_true",
                    help="Disable ANSI colors in console output")
    ap.add_argument("--verbose",     action="store_true",
                    help="Show per-lookup progress including cache hits")
    # ── Cache options ──
    ap.add_argument("--cache-db",    type=Path, metavar="PATH",
                    help=f"SQLite cache file (default: {_DEFAULT_CACHE_DB})")
    ap.add_argument("--cache-ttl",   type=int, default=3600, metavar="SECS",
                    help="How long cached entries are considered fresh (default: 3600 = 1 h)")
    ap.add_argument("--no-cache",    action="store_true",
                    help="Bypass the local cache entirely for this run")
    ap.add_argument("--clear-cache", action="store_true",
                    help="Wipe the cache, then exit (combine with --sbom to scan after clearing)")
    ap.add_argument("--cache-info",  action="store_true",
                    help="Print cache statistics and exit")
    args = ap.parse_args()

    # ── Open cache (unless disabled) ──
    db: Optional[CacheDB] = None
    if not args.no_cache:
        cache_path = args.cache_db or _DEFAULT_CACHE_DB
        db = CacheDB(cache_path, ttl=args.cache_ttl)

        if args.cache_info:
            info = db.info()
            print(f"Cache: {info['db_path']}")
            print(f"  TTL          : {info['ttl_seconds']} s")
            print(f"  OSV entries  : {info['osv_entries']}  (oldest: {info['oldest_osv']})")
            print(f"  NVD entries  : {info['nvd_entries']}  (oldest: {info['oldest_nvd']})")
            print(f"  RH  entries  : {info['rh_entries']}  (oldest: {info['oldest_rh']})")
            db.close()
            sys.exit(0)

        if args.clear_cache:
            db.clear()
            print(f"[*] Cache cleared: {cache_path}", file=sys.stderr)
            if not args.sbom and not (args.baseline and args.compare):
                db.close()
                sys.exit(0)

        # Prune expired entries on every startup so the DB stays lean
        pruned_osv, pruned_nvd, pruned_rh = db.prune()
        if (pruned_osv or pruned_nvd or pruned_rh) and args.verbose:
            print(f"[*] Cache pruned: {pruned_osv} OSV, {pruned_nvd} NVD, {pruned_rh} RH entries removed",
                  file=sys.stderr)
        print(f"[*] Cache: {cache_path}  (TTL={args.cache_ttl}s)", file=sys.stderr)
    elif args.cache_info or args.clear_cache:
        print("Error: --cache-info / --clear-cache require the cache to be enabled "
              "(remove --no-cache).", file=sys.stderr)
        sys.exit(1)

    # ── Validate flag combinations ──
    if args.compare and not args.baseline:
        ap.error("--compare requires --baseline")

    diff_mode = bool(args.baseline)
    need_sbom = not (args.baseline and args.compare)

    if need_sbom and not args.sbom:
        ap.error("--sbom is required (or use --baseline + --compare to diff two saved reports)")

    # ── Resolve current scan (pre-saved report, or live scan) ──
    if args.compare:
        # Both sides are saved JSON reports — no live scan needed
        print(f"[*] Loading baseline : {args.baseline}", file=sys.stderr)
        print(f"[*] Loading current  : {args.compare}",  file=sys.stderr)
        try:
            baseline_reports = _load_scan_json(args.baseline)
            current_reports  = _load_scan_json(args.compare)
        except Exception as exc:
            print(f"Error loading scan report: {exc}", file=sys.stderr)
            sys.exit(1)
        baseline_src = str(args.baseline)
        current_src  = str(args.compare)
    else:
        # Live scan from --sbom
        if not args.sbom.exists():
            print(f"Error: file not found: {args.sbom}", file=sys.stderr)
            sys.exit(1)

        # Resolve distro hint: --distro wins; fall back to --base-image parsing
        distro_hint = ""
        if args.distro:
            parts     = args.distro.split(":", 1)
            name_part = parts[0].capitalize()
            ver_part  = parts[1] if len(parts) > 1 else ""
            if name_part.lower() == "alpine" and ver_part and not ver_part.startswith("v"):
                ver_part = f"v{ver_part}"
            distro_hint = f"{name_part}:{ver_part}" if ver_part else name_part
        elif args.base_image:
            distro_hint = distro_from_image_tag(args.base_image)
            if distro_hint:
                print(f"[*] Base image '{args.base_image}' -> OS ecosystem: {distro_hint}",
                      file=sys.stderr)
            else:
                print(f"[*] WARNING: Could not infer OS ecosystem from image tag "
                      f"'{args.base_image}'. OS packages may be skipped. "
                      f"Use --distro to set it explicitly.", file=sys.stderr)

        print(f"[*] Parsing SBOM: {args.sbom}", file=sys.stderr)
        try:
            packages = parse_sbom(args.sbom, distro_hint=distro_hint)
        except Exception as exc:
            print(f"Error parsing SBOM: {exc}", file=sys.stderr)
            sys.exit(1)

        if not packages:
            print("No packages found in SBOM.", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Found {len(packages)} package(s).", file=sys.stderr)

        # ── Query OSV ──
        print("[*] Querying OSV.dev for vulnerabilities...", file=sys.stderr)
        osv_results, osv_hits, osv_misses = _query_osv(packages, verbose=args.verbose, db=db)
        if db is not None:
            print(f"    OSV cache: {osv_hits} hit(s), {osv_misses} miss(es)", file=sys.stderr)

        current_reports = []
        for pkg, result in zip(packages, osv_results):
            vulns = _parse_osv_result(result, pkg)
            current_reports.append(PackageReport(package=pkg, vulnerabilities=vulns))

        # ── NVD Enrichment ──
        if not args.no_nvd:
            cves = [cid for r in current_reports for v in r.vulnerabilities for cid in v.cve_ids]
            unique_cves = len(set(cves))
            if unique_cves:
                if not args.nvd_api_key:
                    print(
                        f"[*] Enriching {unique_cves} CVE(s) via NVD (no API key -- ~6 s/request)...",
                        file=sys.stderr,
                    )
                    if db is None:
                        print("[*] Tip: enable the cache (drop --no-cache) to avoid re-fetching "
                              "on subsequent runs.", file=sys.stderr)
                else:
                    print(f"[*] Enriching {unique_cves} CVE(s) via NVD (with API key)...",
                          file=sys.stderr)
                nvd_hits, nvd_fetches = enrich_with_nvd(
                    current_reports, args.nvd_api_key, args.verbose, db=db
                )
                if db is not None:
                    print(f"    NVD cache: {nvd_hits} hit(s), {nvd_fetches} API call(s)",
                          file=sys.stderr)

        # ── Red Hat Security API (supplemental for .el/.fc packages) ──
        if not getattr(args, "no_redhat", False):
            rh_vuln_map, rh_pkg_hits, rh_pkg_misses, rh_det_hits, rh_det_misses = \
                _query_redhat(packages, verbose=args.verbose, db=db)
            rh_added = 0
            for report, rh_vulns in zip(current_reports, rh_vuln_map):
                osv_ids = {v.id for v in report.vulnerabilities}
                osv_cve_ids = {cid for v in report.vulnerabilities for cid in v.cve_ids}
                for rv in rh_vulns:
                    if rv.id not in osv_ids and not (set(rv.cve_ids) & osv_cve_ids):
                        report.vulnerabilities.append(rv)
                        rh_added += 1
            rh_total_net = rh_pkg_misses + rh_det_misses
            rh_total_cached = rh_pkg_hits + rh_det_hits
            print(
                f"[*] Red Hat Security API: {rh_added} additional CVE(s) found "
                f"({rh_total_net} network request(s), {rh_total_cached} cached)\n"
                f"    pkg summaries : {rh_pkg_misses} fetched, {rh_pkg_hits} cached\n"
                f"    CVE details   : {rh_det_misses} fetched, {rh_det_hits} cached",
                file=sys.stderr
            )

        current_src = str(args.sbom)

        if diff_mode:
            print(f"[*] Loading baseline: {args.baseline}", file=sys.stderr)
            try:
                baseline_reports = _load_scan_json(args.baseline)
            except Exception as exc:
                print(f"Error loading baseline report: {exc}", file=sys.stderr)
                sys.exit(1)
            baseline_src = str(args.baseline)

    # ── Severity filter (applied to current scan) ──
    if args.min_severity:
        min_rank = _SEVERITY_RANK[args.min_severity]
        for report in current_reports:
            report.vulnerabilities = [
                v for v in report.vulnerabilities
                if _SEVERITY_RANK.get(v.severity_label.lower(), 0) >= min_rank
            ]

    # ── Output ──
    use_color = not args.no_color and args.format == "console" and sys.stdout.isatty()

    if diff_mode:
        diff = compute_diff(baseline_reports, current_reports)

        if args.format == "console":
            print_console_diff(diff, baseline_src, current_src, use_color=use_color)
        else:
            if args.format == "json":
                content = to_json_diff(diff, baseline_src, current_src)
            elif args.format == "csv":
                content = to_csv_diff(diff)
            else:
                content = to_html_diff(diff, baseline_src, current_src)

            if args.output:
                args.output.write_text(content, encoding="utf-8")
                print(f"[*] Report written to {args.output}", file=sys.stderr)
            else:
                print(content)

        if db is not None:
            db.close()

        # CI exit codes: fail only on newly introduced vulns (persistent are already known)
        intro_crit = sum(1 for _, v in diff["introduced"] if v.severity_label == "Critical")
        intro_high = sum(1 for _, v in diff["introduced"] if v.severity_label == "High")
        if intro_crit:
            sys.exit(2)
        elif intro_high:
            sys.exit(1)
        return

    # ── Regular (non-diff) output ──
    reports = current_reports

    if args.format == "console":
        print_console_report(reports, use_color=use_color)
    else:
        if args.format == "json":
            content = to_json_report(reports,
                                     asset_name=args.asset_name or "",
                                     asset_version=args.asset_version or "")
        elif args.format == "csv":
            content = to_csv_report(reports)
        else:
            content = to_html_report(reports)

        if args.output:
            args.output.write_text(content, encoding="utf-8")
            print(f"[*] Report written to {args.output}", file=sys.stderr)
        else:
            print(content)

    if db is not None:
        db.close()

    # Exit codes for CI integration
    critical_count = sum(r.critical_count for r in reports)
    high_count     = sum(r.high_count for r in reports)
    if critical_count:
        sys.exit(2)
    elif high_count:
        sys.exit(1)


if __name__ == "__main__":
    main()
