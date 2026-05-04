#!/usr/bin/env python3
"""
SBOM CVE Portal

Aggregates multiple JSON scan reports (produced by sbom_cve_checker.py) into
a single self-contained HTML dashboard with:

  - Searchable asset table (by name, version, ecosystem)
  - Per-asset vulnerability drill-down with NVD links
  - Version-to-version diff comparison for same-name assets
  - SBOM file association display

Usage:
  python sbom_portal.py scan1.json scan2.json --output portal.html
  python sbom_portal.py --reports-dir ./scans/ --output portal.html

To embed asset name/version metadata in scan reports at scan time:
  python sbom_cve_checker.py --sbom sbom.json --asset-name myapp \\
      --asset-version 1.0.0 --format json --output scan_myapp_v1.json
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path


_NVD_BASE = "https://nvd.nist.gov/vuln/detail/"


def _load_report(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "packages" not in data:
        raise ValueError(f"{path}: not a valid sbom_cve_checker JSON report")
    return data


def _asset_meta(report: dict, path: Path) -> tuple:
    name    = (report.get("asset_name")    or "").strip() or path.stem
    version = (report.get("asset_version") or "").strip() or (report.get("generated_at") or "")[:10] or "unknown"
    return name, version


def _compute_diff(base_pkgs: list, cur_pkgs: list) -> dict:
    def _vkey(pkg: dict, vuln: dict) -> tuple:
        return (
            (pkg.get("ecosystem") or "").lower(),
            (pkg.get("name") or "").lower(),
            (vuln.get("primary_id") or vuln.get("id") or "").lower(),
        )

    def _eco_family(eco: str) -> str:
        """Strip distro release version for cross-version package matching (e.g. Debian:11 -> debian)."""
        return (eco or "").lower().split(":")[0]

    def _pkey(pkg: dict) -> tuple:
        return (_eco_family(pkg.get("ecosystem") or ""), (pkg.get("name") or "").lower())

    base_vulns: dict = {}
    for p in base_pkgs:
        for v in p.get("vulnerabilities", []):
            base_vulns[_vkey(p, v)] = (p, v)

    cur_vulns: dict = {}
    for p in cur_pkgs:
        for v in p.get("vulnerabilities", []):
            cur_vulns[_vkey(p, v)] = (p, v)

    base_pmap: dict = {_pkey(p): p for p in base_pkgs}
    cur_pmap:  dict = {_pkey(p): p for p in cur_pkgs}

    def _compact(p, v):
        c = v.get("cvss_v3") or {}
        return {
            "pkg_name":    p.get("name", ""),
            "pkg_version": p.get("version", ""),
            "ecosystem":   p.get("ecosystem", ""),
            "id":          v.get("id", ""),
            "primary_id":  v.get("primary_id") or v.get("id", ""),
            "cve_ids":     v.get("cve_ids", []),
            "severity":    v.get("severity", "Unknown"),
            "cvss_score":  c.get("base_score"),
            "summary":     v.get("summary", ""),
            "fixed_version": v.get("fixed_version"),
        }

    return {
        "remediated": [_compact(p, v) for k, (p, v) in base_vulns.items() if k not in cur_vulns],
        "introduced": [_compact(p, v) for k, (p, v) in cur_vulns.items()  if k not in base_vulns],
        "persistent": [_compact(cur_vulns[k][0], cur_vulns[k][1]) for k in base_vulns if k in cur_vulns],
        "pkgs_added":   [{"name": p.get("name"), "version": p.get("version"),
                          "ecosystem": p.get("ecosystem")} for k, p in cur_pmap.items()  if k not in base_pmap],
        "pkgs_removed": [{"name": p.get("name"), "version": p.get("version"),
                          "ecosystem": p.get("ecosystem")} for k, p in base_pmap.items() if k not in cur_pmap],
        "pkgs_upgraded": [
            {
                "name":     base_pmap[k].get("name"),
                "from_eco": base_pmap[k].get("ecosystem"),
                "to_eco":   cur_pmap[k].get("ecosystem"),
                "from_ver": base_pmap[k].get("version"),
                "to_ver":   cur_pmap[k].get("version"),
            }
            for k in base_pmap
            if k in cur_pmap and (
                base_pmap[k].get("version") != cur_pmap[k].get("version") or
                base_pmap[k].get("ecosystem") != cur_pmap[k].get("ecosystem")
            )
        ],
    }


def build_portal_data(entries: list) -> dict:
    """
    entries: list of (asset_name, asset_version, report_dict, source_filename)
    Returns the PORTAL_DATA object to embed in HTML.
    """
    assets = []
    by_name: dict = {}

    for idx, (name, version, report, src) in enumerate(entries):
        s      = report.get("summary", {})
        by_sev = s.get("by_severity", {})
        total  = s.get("total_vulnerabilities", 0)

        # Compact vulnerability data: keep only fields needed by the portal
        compact_pkgs = []
        for pkg in report.get("packages", []):
            compact_vulns = []
            for v in pkg.get("vulnerabilities", []):
                c = v.get("cvss_v3") or {}
                cve_ids = v.get("cve_ids", [])
                compact_vulns.append({
                    "id":           v.get("id", ""),
                    "primary_id":   v.get("primary_id") or v.get("id", ""),
                    "cve_ids":      cve_ids,
                    "severity":     v.get("severity", "Unknown"),
                    "cvss_score":   c.get("base_score"),
                    "cvss_vector":  c.get("vector_string", ""),
                    "attack_vector": c.get("attack_vector", ""),
                    "summary":      v.get("summary", ""),
                    "fixed_version": v.get("fixed_version"),
                    "published":    (v.get("published") or "")[:10],
                    "references":   v.get("references", []),
                })
            if compact_vulns or pkg.get("error"):
                compact_pkgs.append({
                    "name":      pkg.get("name", ""),
                    "version":   pkg.get("version", ""),
                    "ecosystem": pkg.get("ecosystem", ""),
                    "purl":      pkg.get("purl", ""),
                    "error":     pkg.get("error"),
                    "vulnerabilities": compact_vulns,
                })

        asset = {
            "id":        idx,
            "name":      name,
            "version":   version,
            "source":    src,
            "generated": report.get("generated_at", ""),
            "sbom_file": report.get("sbom_file", ""),
            "summary": {
                "total_packages":       s.get("total_packages", 0),
                "vulnerable_packages":  s.get("vulnerable_packages", 0),
                "total_vulnerabilities": total,
                "critical": by_sev.get("critical", 0),
                "high":     by_sev.get("high", 0),
                "medium":   by_sev.get("medium", 0),
                "low":      by_sev.get("low", 0),
            },
            "packages": compact_pkgs,
        }
        assets.append(asset)
        by_name.setdefault(name.lower(), []).append(idx)

    # Pre-compute diffs between every pair of versions for same-name assets
    diffs = {}
    for name_lower, idxs in by_name.items():
        if len(idxs) < 2:
            continue
        pairs = {}
        for i in range(len(idxs)):
            for j in range(i + 1, len(idxs)):
                a, b = assets[idxs[i]], assets[idxs[j]]
                key  = f"{a['id']}_vs_{b['id']}"
                pairs[key] = _compute_diff(a["packages"], b["packages"])
        diffs[name_lower] = {"indices": idxs, "pairs": pairs}

    return {"assets": assets, "diffs": diffs, "nvd_base": _NVD_BASE}


def generate_html(portal_data: dict) -> str:
    data_js  = json.dumps(portal_data, separators=(",", ":"))
    now      = datetime.now().strftime("%Y-%m-%d %H:%M")
    n_assets = len(portal_data["assets"])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SBOM CVE Portal</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;background:#f0f2f5;color:#212529}}
.topbar{{background:#1a1d23;color:#fff;padding:14px 24px;display:flex;align-items:center;gap:16px;flex-wrap:wrap}}
.topbar h1{{font-size:1.2em;font-weight:700;letter-spacing:.5px}}
.topbar .meta{{color:#adb5bd;font-size:.85em;margin-left:auto}}
.main{{max-width:1400px;margin:24px auto;padding:0 16px}}
.card{{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.1);padding:20px;margin-bottom:20px}}
.toolbar{{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:16px}}
#search{{flex:1;min-width:200px;padding:8px 12px;border:1px solid #ced4da;border-radius:6px;font-size:.95em}}
#search:focus{{outline:none;border-color:#4a9eff;box-shadow:0 0 0 3px rgba(74,158,255,.2)}}
.filter-btn{{padding:6px 14px;border:1px solid #ced4da;border-radius:6px;background:#fff;cursor:pointer;font-size:.85em}}
.filter-btn.active{{background:#4a9eff;color:#fff;border-color:#4a9eff}}
table{{width:100%;border-collapse:collapse;font-size:.9em}}
thead{{background:#343a40;color:#fff;position:sticky;top:0;z-index:1}}
thead th{{padding:10px 8px;text-align:left;font-weight:600;white-space:nowrap}}
thead th.sortable{{cursor:pointer;user-select:none}}
thead th.sortable:hover{{background:#4a5568}}
tbody tr{{border-bottom:1px solid #f0f2f5;transition:background .1s}}
tbody tr:hover{{background:#f8f9fa}}
tbody td{{padding:8px;vertical-align:middle}}
.badge{{display:inline-block;padding:2px 7px;border-radius:4px;font-size:.78em;font-weight:700;color:#fff;white-space:nowrap}}
.badge-critical{{background:#7b0000}} .badge-high{{background:#dc3545}}
.badge-medium{{background:#e67e00}}   .badge-low{{background:#5a8a00}}
.badge-none,.badge-unknown{{background:#6c757d}}
.badge-added{{background:#155724;color:#d4edda}}
.badge-removed{{background:#7b0000;color:#f8d7da}}
.badge-upgraded{{background:#856404;color:#fff3cd}}
.count{{font-weight:700}}
.c-crit{{color:#7b0000}} .c-high{{color:#dc3545}} .c-med{{color:#e67e00}} .c-low{{color:#5a8a00}}
.btn{{padding:5px 12px;border-radius:5px;border:none;cursor:pointer;font-size:.82em;font-weight:600;transition:background .15s}}
.btn-view{{background:#4a9eff;color:#fff}} .btn-view:hover{{background:#2980e8}}
.btn-diff{{background:#7c3aed;color:#fff}} .btn-diff:hover{{background:#6322c5}}
.btn-sm{{padding:3px 9px;font-size:.78em}}
select.ver-sel{{border:1px solid #ced4da;border-radius:4px;padding:3px 6px;font-size:.82em;background:#fff}}
.detail-panel,.diff-panel{{display:none;margin-top:16px}}
.detail-panel.open,.diff-panel.open{{display:block}}
.panel-header{{display:flex;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap}}
.panel-header h2{{font-size:1em;font-weight:700}}
.panel-close{{margin-left:auto;background:#dee2e6;border:none;border-radius:4px;padding:4px 10px;cursor:pointer;font-size:.82em}}
.pkg-table td{{font-size:.85em}}
.cve-link{{color:#0066cc;text-decoration:none;font-weight:600}}
.cve-link:hover{{text-decoration:underline}}
.diff-tabs{{display:flex;gap:4px;margin-bottom:14px;flex-wrap:wrap}}
.diff-tab{{padding:6px 16px;border:1px solid #ced4da;border-radius:6px 6px 0 0;cursor:pointer;font-size:.85em;background:#f8f9fa}}
.diff-tab.active{{background:#fff;border-bottom-color:#fff;font-weight:700;margin-bottom:-1px}}
.diff-content{{border:1px solid #ced4da;border-radius:0 6px 6px 6px;padding:14px}}
.empty-msg{{color:#6c757d;font-size:.9em;padding:12px}}
.row-remediated td{{background:#f0fff4}} .row-introduced td{{background:#fff5f5}} .row-persistent td{{background:#fffdf0}}
.stat-row{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}}
.stat-box{{border:1px solid #dee2e6;border-radius:6px;padding:10px 16px;text-align:center;min-width:80px}}
.stat-box .n{{font-size:1.6em;font-weight:700;line-height:1}}
.stat-box .l{{color:#6c757d;font-size:.75em;margin-top:3px}}
.rem .n{{color:#155724}} .intro .n{{color:#7b0000}} .pers .n{{color:#856404}}
.no-results{{text-align:center;padding:40px;color:#6c757d}}
.nvd-note{{font-size:.78em;color:#6c757d}}
code{{background:#f1f3f5;padding:1px 4px;border-radius:3px;font-size:.82em}}
.ver-pill{{display:inline-block;background:#e9ecef;border-radius:12px;padding:1px 8px;font-size:.8em;margin:1px}}
</style>
</head>
<body>
<div class="topbar">
  <h1>SBOM CVE Portal</h1>
  <span class="meta">Generated: {now} &nbsp;|&nbsp; {n_assets} asset scan(s) loaded</span>
</div>
<div class="main">
  <div class="card">
    <div class="toolbar">
      <input id="search" type="text" placeholder="Search assets by name, version, or ecosystem...">
      <button class="filter-btn active" data-sev="">All</button>
      <button class="filter-btn" data-sev="critical">Critical</button>
      <button class="filter-btn" data-sev="high">High</button>
      <button class="filter-btn" data-sev="medium">Medium</button>
      <button class="filter-btn" data-sev="low">Low</button>
      <button class="filter-btn" data-sev="none">Clean</button>
    </div>
    <table id="assets-table">
      <thead>
        <tr>
          <th class="sortable" data-col="name">Asset Name &#x25B4;</th>
          <th>Versions</th>
          <th class="sortable" data-col="total">Total CVEs</th>
          <th class="sortable" data-col="critical">Critical</th>
          <th class="sortable" data-col="high">High</th>
          <th class="sortable" data-col="medium">Medium</th>
          <th class="sortable" data-col="low">Low</th>
          <th>Scanned</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="assets-body"></tbody>
    </table>
    <div class="no-results" id="no-results" style="display:none">No assets match the current filter.</div>
  </div>

  <div class="card detail-panel" id="detail-panel">
    <div class="panel-header">
      <h2 id="detail-title">Vulnerability Detail</h2>
      <select id="detail-ver-sel" class="ver-sel" style="display:none"></select>
      <button class="panel-close" onclick="closeDetail()">Close</button>
    </div>
    <div id="detail-summary" class="stat-row"></div>
    <div id="detail-meta" style="font-size:.82em;color:#6c757d;margin-bottom:10px"></div>
    <div class="toolbar" style="margin-bottom:8px">
      <input id="detail-search" type="text" placeholder="Search package, CVE ID, summary..." oninput="onDetailSearch(this.value)">
      <span id="detail-count" style="font-size:.82em;color:#6c757d;white-space:nowrap"></span>
    </div>
    <table class="pkg-table" id="detail-table">
      <thead style="background:#343a40;color:#fff">
        <tr>
          <th class="sortable" style="padding:8px" onclick="sortDetail('pkg')" id="dh-pkg">Package</th>
          <th class="sortable" style="padding:8px" onclick="sortDetail('cve')" id="dh-cve">CVE / ID</th>
          <th class="sortable" style="padding:8px;text-align:center" onclick="sortDetail('sev')" id="dh-sev">Severity</th>
          <th class="sortable" style="padding:8px;text-align:center" onclick="sortDetail('cvss')" id="dh-cvss">CVSS &#x25BE;</th>
          <th style="padding:8px">Summary</th>
          <th style="padding:8px">Fix</th>
          <th class="sortable" style="padding:8px" onclick="sortDetail('pub')" id="dh-pub">Published</th>
        </tr>
      </thead>
      <tbody id="detail-body"></tbody>
    </table>
  </div>

  <div class="card diff-panel" id="diff-panel">
    <div class="panel-header">
      <h2 id="diff-title">Version Comparison</h2>
      <span id="diff-selectors" style="display:flex;gap:8px;align-items:center;font-size:.85em"></span>
      <button class="panel-close" onclick="closeDiff()">Close</button>
    </div>
    <div id="diff-stat-row" class="stat-row"></div>
    <div class="diff-tabs" id="diff-tabs"></div>
    <div id="diff-search-bar" style="display:none;margin-bottom:8px" class="toolbar">
      <input id="diff-search" type="text" placeholder="Search package, CVE ID, summary..." oninput="onDiffSearch(this.value)">
      <span id="diff-count" style="font-size:.82em;color:#6c757d;white-space:nowrap"></span>
    </div>
    <div id="diff-content"></div>
  </div>
</div>

<script>
const D = {data_js};

// ─── Helpers ────────────────────────────────────────────────────────────────

function sev(s){{return(s||'Unknown').toLowerCase()}}
function badge(s){{return`<span class="badge badge-${{sev(s)}}">${{(s||'?').toUpperCase()}}</span>`}}
function nvdLink(cveId){{
  if(!cveId||!cveId.startsWith('CVE-'))return`<code>${{cveId}}</code>`;
  return`<a class="cve-link" href="${{D.nvd_base}}${{cveId}}" target="_blank" rel="noopener">${{cveId}}</a>`;
}}
function cveCell(v){{
  const pid=v.primary_id||v.id||'';
  const cves=(v.cve_ids||[]).filter(c=>c!==pid);
  let html=nvdLink(pid);
  if(pid!==v.id&&v.id)html+=`<br><small class="nvd-note">${{v.id}}</small>`;
  if(cves.length)html+=`<br><small class="nvd-note">${{cves.map(nvdLink).join(' ')}}</small>`;
  return html;
}}
function scoreCell(v){{return v.cvss_score!=null?`<b>${{v.cvss_score}}</b>`:'&mdash;'}}
function fixCell(fix){{
  return fix?`<code style="color:#155724">&ge; ${{fix}}</code>`:'<em style="color:#721c24">No fix</em>';
}}
function h(s){{
  if(!s)return'';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}

// Group assets by lowercase name
const byName={{}};
D.assets.forEach(a=>{{
  const k=a.name.toLowerCase();
  if(!byName[k])byName[k]=[];
  byName[k].push(a.id);
}});

// ─── Asset table ─────────────────────────────────────────────────────────────

let sortCol='name', sortAsc=true, sevFilter='', searchQ='';
const selectedVer={{}};  // nameKey -> assetId of the currently selected version

function selAsset(nameKey, versions){{
  const sid=selectedVer[nameKey];
  return(sid!=null&&D.assets.find(a=>a.id===sid))||versions[versions.length-1];
}}

function renderTable(){{
  const q=searchQ.toLowerCase();
  const rows=[];
  const grouped=new Map();

  D.assets.forEach(a=>{{
    const k=a.name.toLowerCase();
    if(!grouped.has(k))grouped.set(k,[]);
    grouped.get(k).push(a);
  }});

  grouped.forEach((versions,nameKey)=>{{
    const cur=selAsset(nameKey,versions);
    const s=cur.summary;
    const totalCrit=s.critical, totalHigh=s.high, totalMed=s.medium, totalLow=s.low;
    const totalVulns=s.total_vulnerabilities;

    // Search filter
    if(q){{
      const hit=versions.some(v=>
        v.name.toLowerCase().includes(q)||
        v.version.toLowerCase().includes(q)||
        (v.packages||[]).some(p=>p.ecosystem&&p.ecosystem.toLowerCase().includes(q))
      );
      if(!hit)return;
    }}

    // Severity filter
    if(sevFilter){{
      if(sevFilter==='none'&&totalVulns>0)return;
      if(sevFilter==='critical'&&totalCrit===0)return;
      if(sevFilter==='high'&&totalHigh===0)return;
      if(sevFilter==='medium'&&totalMed===0)return;
      if(sevFilter==='low'&&totalLow===0)return;
    }}

    rows.push({{nameKey,versions,cur,totalCrit,totalHigh,totalMed,totalLow,totalVulns}});
  }});

  // Sort
  rows.sort((a,b)=>{{
    let va,vb;
    if(sortCol==='name'){{va=a.nameKey;vb=b.nameKey;}}
    else if(sortCol==='total'){{va=a.totalVulns;vb=b.totalVulns;}}
    else if(sortCol==='critical'){{va=a.totalCrit;vb=b.totalCrit;}}
    else if(sortCol==='high'){{va=a.totalHigh;vb=b.totalHigh;}}
    else if(sortCol==='medium'){{va=a.totalMed;vb=b.totalMed;}}
    else{{va=0;vb=0;}}
    if(va<vb)return sortAsc?-1:1;
    if(va>vb)return sortAsc?1:-1;
    return 0;
  }});

  const tbody=document.getElementById('assets-body');
  const noR=document.getElementById('no-results');
  if(!rows.length){{tbody.innerHTML='';noR.style.display='';return;}}
  noR.style.display='none';

  tbody.innerHTML=rows.map(row=>{{
    const{{nameKey,versions,cur,totalCrit,totalHigh,totalMed,totalLow,totalVulns}}=row;
    const hasDiff=versions.length>1;
    const firstId=versions[0].id;

    // Version selector (if multiple); selected = cur
    const verSel=versions.length>1
      ?`<select class="ver-sel" onchange="onVerChange('${{nameKey}}',this.value)">
          ${{versions.map(v=>`<option value="${{v.id}}"${{v.id===cur.id?' selected':''}}>${{h(v.version)}}</option>`).join('')}}
        </select>`
      :`<span class="ver-pill">${{h(cur.version)}}</span>`;

    const c=(val,cls)=>val?`<span class="${{cls}}">${{val}}</span>`:'<span style="color:#aaa">0</span>';
    const scanned=(cur.generated||'').slice(0,10)||'&mdash;';
    const viewBtn=`<button class="btn btn-view btn-sm" onclick="showDetail('${{nameKey}}',${{cur.id}})">View</button>`;
    const diffBtn=hasDiff
      ?`<button class="btn btn-diff btn-sm" style="margin-left:4px" onclick="showDiff('${{nameKey}}')">Compare</button>`
      :'';

    return`<tr data-name="${{nameKey}}">
      <td><b>${{h(cur.name)}}</b></td>
      <td>${{verSel}}</td>
      <td id="rs-total-${{firstId}}">${{totalVulns||'<span style="color:#28a745">0</span>'}}</td>
      <td id="rs-crit-${{firstId}}">${{c(totalCrit,'count c-crit')}}</td>
      <td id="rs-high-${{firstId}}">${{c(totalHigh,'count c-high')}}</td>
      <td id="rs-med-${{firstId}}">${{c(totalMed,'count c-med')}}</td>
      <td id="rs-low-${{firstId}}">${{c(totalLow,'count c-low')}}</td>
      <td style="font-size:.8em;color:#6c757d">${{scanned}}</td>
      <td>${{viewBtn}}${{diffBtn}}</td>
    </tr>`;
  }}).join('');
}}

function onVerChange(nameKey, assetId){{
  const id=parseInt(assetId);
  selectedVer[nameKey]=id;
  const asset=D.assets.find(a=>a.id===id);
  if(!asset)return;
  const s=asset.summary;
  const peers=byName[nameKey]||[];
  if(peers.length){{
    const fid=peers[0];
    const c=(val,cls)=>val?`<span class="${{cls}}">${{val}}</span>`:'<span style="color:#aaa">0</span>';
    const t=document.getElementById('rs-total-'+fid);
    if(t)t.innerHTML=s.total_vulnerabilities||'<span style="color:#28a745">0</span>';
    [['crit','critical','count c-crit'],['high','high','count c-high'],['med','medium','count c-med'],['low','low','count c-low']].forEach(([k,field,cls])=>{{
      const el=document.getElementById('rs-'+k+'-'+fid);
      if(el)el.innerHTML=c(s[field]||0,cls);
    }});
  }}
  showDetail(nameKey,id);
}}

// Sort click
document.querySelectorAll('thead th.sortable').forEach(th=>{{
  th.addEventListener('click',()=>{{
    const col=th.dataset.col;
    if(sortCol===col)sortAsc=!sortAsc; else{{sortCol=col;sortAsc=col==='name';}}
    renderTable();
  }});
}});

// Search
document.getElementById('search').addEventListener('input',e=>{{
  searchQ=e.target.value;renderTable();
}});

// Severity filter buttons
document.querySelectorAll('.filter-btn').forEach(btn=>{{
  btn.addEventListener('click',()=>{{
    document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    sevFilter=btn.dataset.sev;
    renderTable();
  }});
}});

// ─── Detail panel ────────────────────────────────────────────────────────────

let currentDetailName=null;
let detailRows=[];
let detailSearch='';
let detailSortCol='cvss', detailSortAsc=false;

const _sevRank={{critical:4,high:3,medium:2,low:1}};

function applyDetailSort(){{
  const headers={{pkg:'dh-pkg',cve:'dh-cve',sev:'dh-sev',cvss:'dh-cvss',pub:'dh-pub'}};
  Object.entries(headers).forEach(([col,id])=>{{
    const el=document.getElementById(id);
    if(!el)return;
    const base=el.textContent.replace(/ [▴▾]$/,'');
    el.textContent=col===detailSortCol?base+(detailSortAsc?' ▴':' ▾'):base;
  }});
}}

function filterDetailRows(){{
  const q=detailSearch.toLowerCase();
  let rows=detailRows;
  if(q)rows=rows.filter(({{pkg,v}})=>
    (pkg.name||'').toLowerCase().includes(q)||
    (v.primary_id||v.id||'').toLowerCase().includes(q)||
    (v.summary||'').toLowerCase().includes(q)||
    (pkg.ecosystem||'').toLowerCase().includes(q)
  );
  return [...rows].sort((a,b)=>{{
    let va,vb;
    if(detailSortCol==='cvss'){{va=a.v.cvss_score||0;vb=b.v.cvss_score||0;}}
    else if(detailSortCol==='sev'){{va=_sevRank[sev(a.v.severity)]||0;vb=_sevRank[sev(b.v.severity)]||0;}}
    else if(detailSortCol==='pkg'){{va=(a.pkg.name||'').toLowerCase();vb=(b.pkg.name||'').toLowerCase();}}
    else if(detailSortCol==='cve'){{va=(a.v.primary_id||'').toLowerCase();vb=(b.v.primary_id||'').toLowerCase();}}
    else if(detailSortCol==='pub'){{va=a.v.published||'';vb=b.v.published||'';}}
    else{{va=0;vb=0;}}
    if(va<vb)return detailSortAsc?-1:1;
    if(va>vb)return detailSortAsc?1:-1;
    return 0;
  }});
}}

function renderDetailBody(){{
  const rows=filterDetailRows();
  const total=detailRows.length, shown=rows.length;
  document.getElementById('detail-count').textContent=
    detailSearch?`${{shown}} of ${{total}} shown`:`${{total}} finding${{total===1?'':'s'}}`;
  document.getElementById('detail-body').innerHTML=rows.length
    ?rows.map(({{pkg,v}})=>`<tr>
        <td>${{h(pkg.name)}}<br><small style="color:#666">${{h(pkg.version)}} &middot; ${{h(pkg.ecosystem)}}</small></td>
        <td>${{cveCell(v)}}</td>
        <td style="text-align:center">${{badge(v.severity)}}</td>
        <td style="text-align:center">${{scoreCell(v)}}</td>
        <td>${{h(v.summary)}}</td>
        <td>${{fixCell(v.fixed_version)}}</td>
        <td style="font-size:.8em;color:#6c757d">${{v.published||'&mdash;'}}</td>
      </tr>`).join('')
    :`<tr><td colspan="7" class="empty-msg">${{detailSearch?'No results match "'+h(detailSearch)+'"':'No vulnerabilities detected in this scan.'}}</td></tr>`;
}}

function sortDetail(col){{
  if(detailSortCol===col)detailSortAsc=!detailSortAsc;
  else{{detailSortCol=col;detailSortAsc=col==='pkg'||col==='cve'||col==='pub';}}
  applyDetailSort();
  renderDetailBody();
}}

function onDetailSearch(val){{
  detailSearch=val;
  renderDetailBody();
}}

function showDetail(nameKey, assetId){{
  const asset=D.assets.find(a=>a.id===assetId);
  if(!asset)return;
  currentDetailName=nameKey;

  document.getElementById('detail-title').textContent=`${{asset.name}} @ ${{asset.version}}`;

  // Version selector in panel header
  const verSel=document.getElementById('detail-ver-sel');
  const peers=byName[nameKey]||[];
  if(peers.length>1){{
    verSel.style.display='';
    verSel.innerHTML=peers.map(id=>{{
      const a=D.assets.find(x=>x.id===id);
      return`<option value="${{id}}"${{id===assetId?' selected':''}}>${{h(a.version)}}</option>`;
    }}).join('');
    verSel.onchange=()=>showDetail(nameKey,parseInt(verSel.value));
  }}else{{verSel.style.display='none';}}

  // Summary stats
  const s=asset.summary;
  document.getElementById('detail-summary').innerHTML=`
    <div class="stat-box"><div class="n">${{s.total_packages}}</div><div class="l">Packages</div></div>
    <div class="stat-box"><div class="n">${{s.vulnerable_packages}}</div><div class="l">Vulnerable</div></div>
    <div class="stat-box"><div class="n">${{s.total_vulnerabilities}}</div><div class="l">CVEs</div></div>
    <div class="stat-box"><div class="n c-crit">${{s.critical}}</div><div class="l">Critical</div></div>
    <div class="stat-box"><div class="n c-high">${{s.high}}</div><div class="l">High</div></div>
    <div class="stat-box"><div class="n c-med">${{s.medium}}</div><div class="l">Medium</div></div>
    <div class="stat-box"><div class="n c-low">${{s.low}}</div><div class="l">Low</div></div>`;

  const meta=[];
  if(asset.source)meta.push(`Source: <code>${{h(asset.source)}}</code>`);
  if(asset.sbom_file)meta.push(`SBOM: <code>${{h(asset.sbom_file)}}</code>`);
  if(asset.generated)meta.push(`Scanned: ${{asset.generated.slice(0,19).replace('T',' ')}}`);
  document.getElementById('detail-meta').innerHTML=meta.join(' &nbsp;|&nbsp; ');

  // Rebuild row data (reset search/sort state on new asset)
  detailRows=[];
  (asset.packages||[]).forEach(pkg=>{{
    (pkg.vulnerabilities||[]).forEach(v=>detailRows.push({{pkg,v}}));
  }});
  detailSearch='';
  document.getElementById('detail-search').value='';
  detailSortCol='cvss'; detailSortAsc=false;
  applyDetailSort();
  renderDetailBody();

  document.getElementById('detail-panel').classList.add('open');
  document.getElementById('detail-panel').scrollIntoView({{behavior:'smooth',block:'nearest'}});
}}

function closeDetail(){{
  document.getElementById('detail-panel').classList.remove('open');
  currentDetailName=null;
}}

// ─── Diff panel ──────────────────────────────────────────────────────────────

let currentDiffKey=null, currentDiffTab='introduced';
let diffRows=[];
let diffSearch='';
let diffSortCol='cvss', diffSortAsc=false;

function filterDiffRows(){{
  const q=diffSearch.toLowerCase();
  let rows=diffRows;
  if(q)rows=rows.filter(v=>
    (v.pkg_name||'').toLowerCase().includes(q)||
    (v.primary_id||v.id||'').toLowerCase().includes(q)||
    (v.summary||'').toLowerCase().includes(q)||
    (v.ecosystem||'').toLowerCase().includes(q)
  );
  return [...rows].sort((a,b)=>{{
    let va,vb;
    if(diffSortCol==='cvss'){{va=a.cvss_score||0;vb=b.cvss_score||0;}}
    else if(diffSortCol==='sev'){{va=_sevRank[sev(a.severity)]||0;vb=_sevRank[sev(b.severity)]||0;}}
    else if(diffSortCol==='pkg'){{va=(a.pkg_name||'').toLowerCase();vb=(b.pkg_name||'').toLowerCase();}}
    else if(diffSortCol==='cve'){{va=(a.primary_id||'').toLowerCase();vb=(b.primary_id||'').toLowerCase();}}
    else{{va=0;vb=0;}}
    if(va<vb)return diffSortAsc?-1:1;
    if(va>vb)return diffSortAsc?1:-1;
    return 0;
  }});
}}

function onDiffSearch(val){{
  diffSearch=val;
  renderDiffVulnRows();
}}

function sortDiff(col){{
  if(diffSortCol===col)diffSortAsc=!diffSortAsc;
  else{{diffSortCol=col;diffSortAsc=col==='pkg'||col==='cve';}}
  renderDiffVulnRows();
}}

function renderDiffVulnRows(){{
  const rows=filterDiffRows();
  const total=diffRows.length,shown=rows.length;
  document.getElementById('diff-count').textContent=
    diffSearch?`${{shown}} of ${{total}} shown`:`${{total}} finding${{total===1?'':'s'}}`;
  const el=document.getElementById('diff-content');
  if(!rows.length){{
    el.innerHTML=`<p class="empty-msg">${{diffSearch?'No results match "'+h(diffSearch)+'"':'None.'}}</p>`;
    return;
  }}
  const sDir=col=>col===diffSortCol?(diffSortAsc?' ▴':' ▾'):'';
  el.innerHTML=`<table>
    <thead><tr>
      <th style="padding:8px;cursor:pointer" onclick="sortDiff('pkg')">Package${{sDir('pkg')}}</th>
      <th style="padding:8px;cursor:pointer" onclick="sortDiff('cve')">CVE / ID${{sDir('cve')}}</th>
      <th style="padding:8px;text-align:center;cursor:pointer" onclick="sortDiff('sev')">Severity${{sDir('sev')}}</th>
      <th style="padding:8px;text-align:center;cursor:pointer" onclick="sortDiff('cvss')">CVSS${{sDir('cvss')}}</th>
      <th style="padding:8px">Summary</th>
      <th style="padding:8px">Fix</th>
    </tr></thead>
    <tbody>${{rows.map(v=>`<tr class="${{currentDiffTab==='introduced'?'row-introduced':currentDiffTab==='remediated'?'row-remediated':'row-persistent'}}">
      <td class="pkg-table">${{h(v.pkg_name)}}<br><small style="color:#666">${{h(v.pkg_version)}} &middot; ${{h(v.ecosystem)}}</small></td>
      <td>${{cveCell(v)}}</td>
      <td style="text-align:center">${{badge(v.severity)}}</td>
      <td style="text-align:center">${{scoreCell(v)}}</td>
      <td>${{h(v.summary)}}</td>
      <td>${{fixCell(v.fixed_version)}}</td>
    </tr>`).join('')}}</tbody></table>`;
}}

function showDiff(nameKey){{
  const diffGroup=D.diffs[nameKey];
  if(!diffGroup)return;
  currentDiffKey=nameKey;

  const idxs=diffGroup.indices;
  const versions=idxs.map(id=>D.assets.find(a=>a.id===id));

  // If only 2 versions, pick that pair; if more, default to first vs last
  const selA=document.createElement('select');
  selA.className='ver-sel';
  selA.id='diff-sel-a';
  const selB=document.createElement('select');
  selB.className='ver-sel';
  selB.id='diff-sel-b';
  versions.forEach((v,i)=>{{
    selA.innerHTML+=`<option value="${{v.id}}" ${{i===0?'selected':''}}>${{h(v.version)}}</option>`;
    selB.innerHTML+=`<option value="${{v.id}}" ${{i===versions.length-1?'selected':''}}>${{h(v.version)}}</option>`;
  }});
  selA.onchange=renderDiffContent;
  selB.onchange=renderDiffContent;

  const hdr=document.getElementById('diff-selectors');
  hdr.innerHTML='<span style="font-weight:600">'+h(versions[0].name)+'</span>&nbsp;';
  hdr.appendChild(selA);
  hdr.innerHTML+=`&nbsp;<span style="color:#6c757d">vs</span>&nbsp;`;
  hdr.appendChild(selB);

  renderDiffContent();
  document.getElementById('diff-panel').classList.add('open');
  document.getElementById('diff-panel').scrollIntoView({{behavior:'smooth',block:'nearest'}});
}}

function getDiffKey(){{
  const a=parseInt(document.getElementById('diff-sel-a').value);
  const b=parseInt(document.getElementById('diff-sel-b').value);
  if(a===b)return null;
  const lo=Math.min(a,b),hi=Math.max(a,b);
  return`${{lo}}_vs_${{hi}}`;
}}

function renderDiffContent(){{
  const nameKey=currentDiffKey;
  const dkStr=getDiffKey();
  if(!dkStr||!D.diffs[nameKey]){{
    document.getElementById('diff-content').innerHTML='<p class="empty-msg">Select two different versions to compare.</p>';
    return;
  }}
  const diff=D.diffs[nameKey].pairs[dkStr];
  if(!diff){{
    // Reversed key (b_vs_a) — try swapping
    const[lo,hi]=dkStr.split('_vs_').map(Number);
    const altKey=`${{hi}}_vs_${{lo}}`;
    const altDiff=D.diffs[nameKey].pairs[altKey];
    if(altDiff){{renderDiffWithData(invertDiff(altDiff));return;}}
    document.getElementById('diff-content').innerHTML='<p class="empty-msg">No diff data for this pair.</p>';
    return;
  }}
  renderDiffWithData(diff);
}}

function invertDiff(diff){{
  return{{
    remediated:diff.introduced,
    introduced:diff.remediated,
    persistent:diff.persistent,
    pkgs_added:diff.pkgs_removed,
    pkgs_removed:diff.pkgs_added,
    pkgs_upgraded:diff.pkgs_upgraded.map(u=>({{...u,from_eco:u.to_eco,to_eco:u.from_eco,from_ver:u.to_ver,to_ver:u.from_ver}})),
  }};
}}

function renderDiffWithData(diff){{
  const nRem=diff.remediated.length,nNew=diff.introduced.length,nPers=diff.persistent.length;
  const nAdd=(diff.pkgs_added||[]).length,nDel=(diff.pkgs_removed||[]).length,nUpg=(diff.pkgs_upgraded||[]).length;

  document.getElementById('diff-stat-row').innerHTML=`
    <div class="stat-box rem"><div class="n">${{nRem}}</div><div class="l">Remediated</div></div>
    <div class="stat-box intro"><div class="n">${{nNew}}</div><div class="l">Introduced</div></div>
    <div class="stat-box pers"><div class="n">${{nPers}}</div><div class="l">Persistent</div></div>
    <div class="stat-box"><div class="n">${{nAdd}}</div><div class="l">Pkg Added</div></div>
    <div class="stat-box"><div class="n">${{nDel}}</div><div class="l">Pkg Removed</div></div>
    <div class="stat-box"><div class="n">${{nUpg}}</div><div class="l">Pkg Upgraded</div></div>`;

  const tabs=[
    {{id:'introduced',label:`Introduced (${{nNew}})`,cls:'intro'}},
    {{id:'remediated',label:`Remediated (${{nRem}})`,cls:'rem'}},
    {{id:'persistent',label:`Persistent (${{nPers}})`,cls:'pers'}},
    {{id:'pkgchanges',label:`Pkg Changes (${{nAdd+nDel+nUpg}})`}},
  ];

  document.getElementById('diff-tabs').innerHTML=tabs.map(t=>
    `<div class="diff-tab${{currentDiffTab===t.id?' active':''}}" onclick="switchDiffTab('${{t.id}}')">${{t.label}}</div>`
  ).join('');

  renderDiffTab(diff);
}}

function switchDiffTab(tab){{
  currentDiffTab=tab;
  document.querySelectorAll('.diff-tab').forEach(t=>{{
    t.classList.toggle('active',t.textContent.startsWith(tab==='introduced'?'Intro':tab==='remediated'?'Rem':tab==='persistent'?'Per':'Pkg'));
  }});
  // Re-render with current diff data
  const nameKey=currentDiffKey;
  const dkStr=getDiffKey();
  if(!dkStr||!D.diffs[nameKey])return;
  let diff=D.diffs[nameKey].pairs[dkStr];
  if(!diff){{
    const[lo,hi]=dkStr.split('_vs_').map(Number);
    diff=D.diffs[nameKey].pairs[`${{hi}}_vs_${{lo}}`];
    if(diff)diff=invertDiff(diff);
  }}
  if(diff)renderDiffTab(diff);
}}

function renderDiffTab(diff){{
  const isCvuTab=currentDiffTab!=='pkgchanges';
  document.getElementById('diff-search-bar').style.display=isCvuTab?'':'none';

  if(currentDiffTab==='introduced'||currentDiffTab==='remediated'||currentDiffTab==='persistent'){{
    diffRows=diff[currentDiffTab]||[];
    diffSearch='';
    const si=document.getElementById('diff-search');
    if(si)si.value='';
    diffSortCol='cvss'; diffSortAsc=false;
    renderDiffVulnRows();
  }}else{{
    // Package changes
    const added   =diff.pkgs_added   ||[];
    const removed =diff.pkgs_removed ||[];
    const upgraded=diff.pkgs_upgraded||[];
    const el=document.getElementById('diff-content');
    if(!added.length&&!removed.length&&!upgraded.length){{
      el.innerHTML='<p class="empty-msg">No package additions, removals, or version changes detected.</p>';return;
    }}
    let html='<table><thead><tr>'
      +'<th style="padding:8px">Change</th><th style="padding:8px">Package</th>'
      +'<th style="padding:8px">Version</th><th style="padding:8px">Ecosystem</th>'
      +'</tr></thead><tbody>';
    added.forEach(p=>{{
      html+=`<tr><td>${{badgeChange('added')}}</td><td>${{h(p.name)}}</td><td>${{h(p.version)}}</td><td>${{h(p.ecosystem)}}</td></tr>`;
    }});
    removed.forEach(p=>{{
      html+=`<tr><td>${{badgeChange('removed')}}</td><td>${{h(p.name)}}</td><td>${{h(p.version)}}</td><td>${{h(p.ecosystem)}}</td></tr>`;
    }});
    upgraded.forEach(u=>{{
      const ecoCell=u.from_eco&&u.to_eco&&u.from_eco!==u.to_eco
        ?`<del>${{h(u.from_eco)}}</del> &rarr; <b>${{h(u.to_eco)}}</b>`
        :h(u.from_eco||u.to_eco||'');
      const verCell=u.from_ver!==u.to_ver
        ?`<del>${{h(u.from_ver)}}</del> &rarr; <b>${{h(u.to_ver)}}</b>`
        :h(u.to_ver||'');
      html+=`<tr><td>${{badgeChange('upgraded')}}</td><td>${{h(u.name)}}</td><td>${{verCell}}</td><td>${{ecoCell}}</td></tr>`;
    }});
    html+='</tbody></table>';
    el.innerHTML=html;
  }}
}}

function badgeChange(type){{
  return`<span class="badge badge-${{type}}">${{type.toUpperCase()}}</span>`;
}}

function closeDiff(){{
  document.getElementById('diff-panel').classList.remove('open');
  currentDiffKey=null;
}}

// Initial render
currentDiffTab='introduced';
renderTable();
</script>
</body>
</html>"""


def main():
    ap = argparse.ArgumentParser(
        description="Generate a self-contained HTML portal from multiple sbom_cve_checker JSON reports.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan_v1.json scan_v2.json --output portal.html
  %(prog)s --reports-dir ./scans/ --output portal.html
  %(prog)s scan_v1.json scan_v2.json --asset-name myapp --asset-versions 1.0,2.0 --output portal.html
        """
    )
    ap.add_argument("reports",          nargs="*", type=Path,
                    help="JSON scan report files (produced by sbom_cve_checker.py --format json)")
    ap.add_argument("--reports-dir",    type=Path, metavar="DIR",
                    help="Directory of JSON scan reports. All *.json files are loaded.")
    ap.add_argument("--asset-name",     metavar="NAME",
                    help="Override asset name for all reports listed on the command line "
                         "(useful when reports lack embedded asset metadata).")
    ap.add_argument("--asset-versions", metavar="V1,V2,...",
                    help="Comma-separated version strings to assign to each positional report "
                         "in order (e.g. '1.0,2.0'). Only used when --asset-name is given.")
    ap.add_argument("--output",         type=Path, default=Path("portal.html"),
                    help="Output HTML file (default: portal.html)")
    args = ap.parse_args()

    # Collect report paths
    paths: list = list(args.reports or [])
    if args.reports_dir:
        paths += sorted(args.reports_dir.glob("*.json"))

    if not paths:
        ap.error("Provide at least one JSON scan report, or use --reports-dir.")

    # Parse optional version overrides
    ver_overrides: list = []
    if args.asset_versions:
        ver_overrides = [v.strip() for v in args.asset_versions.split(",")]

    entries = []
    for i, path in enumerate(paths):
        if not path.exists():
            print(f"[SKIP] File not found: {path}", file=sys.stderr)
            continue
        try:
            report = _load_report(path)
        except Exception as exc:
            print(f"[SKIP] {path}: {exc}", file=sys.stderr)
            continue

        name, version = _asset_meta(report, path)
        if args.asset_name:
            name = args.asset_name
        if i < len(ver_overrides):
            version = ver_overrides[i]

        entries.append((name, version, report, path.name))
        print(f"  Loaded: {name} @ {version}  ({path.name})", file=sys.stderr)

    if not entries:
        print("Error: no valid reports loaded.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Building portal for {len(entries)} scan(s)...", file=sys.stderr)
    portal_data = build_portal_data(entries)
    html        = generate_html(portal_data)
    args.output.write_text(html, encoding="utf-8")
    print(f"[*] Portal written to: {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
