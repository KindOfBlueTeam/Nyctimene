# Nyctimene — Feature Roadmap & Research Notes

*Compiled for next development session. All items are implementation-ready with sourced APIs and tools.*

---

## Part 1: Ten High-Value Features for SecOps / DFIR Teams

Each feature below is rated by **value** (how much daily investigators benefit) and **implementation difficulty** on the existing Swift/SwiftUI stack.

---

### 1. Clipboard Watch Mode
**Value: ★★★★★ | Effort: Low**

Watch `NSPasteboard.general` for changes. When a new string that looks like an IP, domain, URL, or hash is copied anywhere on the system, immediately analyse it and post a macOS `UNUserNotificationCenter` notification with the risk level. A single click on the notification opens the full result.

This is the single highest-leverage UX improvement possible. Analysts working through a SIEM alert, a threat report PDF, or a raw log file spend most of their time copy-pasting. Eliminating that manual step means investigations move faster.

**Implementation sketch:**
```swift
// Poll NSPasteboard.general.changeCount every 1.5s in a background Task
// Or use DistributedNotificationCenter to observe clipboard changes
// Resolve the string with ArtifactResolver.resolve(_:)
// If artifact type is not nil, run analysis and post a notification
```

---

### 2. Bulk Import from Text / CSV
**Value: ★★★★★ | Effort: Low**

A text box (or file drop target) that accepts a newline-separated or CSV list of mixed IOCs. Nyctimene auto-detects the type of each, deduplicates, and feeds them all into `BulkAnalysisModel`. Results appear in `ScanResultsTable`.

In real incidents, threat intel comes as a list: a feed export, a vendor advisory, a SIEM search result with 50 IPs. Investigators currently have no way to process these en masse without a Python script.

**File formats to support:**
- Plain newline-separated list: one IOC per line
- Two-column CSV: `type,value` or `value,description`
- Automatic type-detection fallback if no type column

---

### 3. Certificate Transparency Lookup (crt.sh)
**Value: ★★★★★ | Effort: Low**

`crt.sh` is a free, no-auth-required Certificate Transparency log search engine run by Sectigo. For any domain, it returns every TLS certificate ever issued (by any CA) that includes that domain in its Common Name or Subject Alternative Name.

**Why this matters for DFIR:**
- Finds attacker-registered subdomains of a legitimate domain before they're deployed
- Identifies phishing infrastructure: `login-yourbank.com`, `account.yourcompany-secure.com`
- Pivoting: find every domain sharing the same certificate → maps out attacker infrastructure
- A cert issued yesterday for a domain registered last week is highly suspicious

**API (no key required):**
```
GET https://crt.sh/?q={domain}&output=json
```
Returns an array of certificate records with `id`, `logged_at`, `not_before`, `not_after`, `common_name`, `name_value` (full SAN list), `issuer_name`, `serial_number`.

**Show in:** Domain result header (like `domainInfoSection`), with "N certs issued" and a list of the 5 most recent, with dates and issuer.

---

### 4. New Provider: AbuseIPDB
**Value: ★★★★★ | Effort: Low**

The most widely-used community IP abuse database. Returns a 0–100 confidence-of-abuse score based on crowdsourced reports, total report count, ISP, usage type (datacenter / residential / VPN), and a list of report categories (port scan, brute force, DDoS, SSH, web attack, etc.).

**API:**
```
GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90
Header: Key: {api_key}
```

**Free tier:** 1,000 checks/day. Register at https://www.abuseipdb.com/register

**Returns:** `abuseConfidenceScore` (0–100), `totalReports`, `countryCode`, `usageType`, `isp`, `domain`, `isTor`, `isVpn`, `lastReportedAt`

**Add to:** IP artifact header (parallel to `ipInfoSection`), showing score as a coloured badge (0-25 green, 26-75 orange, 76-100 red).

---

### 5. New Provider: GreyNoise
**Value: ★★★★★ | Effort: Low**

Separates targeted attacks from mass internet background noise. Tags IPs as `noise` (internet-wide scanners/crawlers — background, low-priority), `riot` (known-benign infrastructure — Cloudflare, Google, etc.), or `unknown`. For malicious noise IPs, returns associated tags (e.g. "Mirai-like scanner", "Cobalt Strike C2"), first/last seen, and targeted ports.

**This is the IPInfo.io complement for threat context:** If an IP is "noise", an analyst immediately knows it's not a targeted attack. If it's "malicious" and not noise, it's a real signal.

**API (Community — free):**
```
GET https://api.greynoise.io/v3/community/{ip}
Header: key: {api_key}
```
Register at https://viz.greynoise.io/signup (Community plan is free, 50 searches/week).

**Returns:** `ip`, `noise` (bool), `riot` (bool), `classification` (`malicious`/`benign`/`unknown`), `name` (tag), `link` (report URL), `last_seen`, `message`.

**Show in:** IP artifact header, with a "NOISE", "RIOT", or "TARGETED" badge. Grey for noise, green for RIOT, red for targeted/malicious.

---

### 6. New Providers: MalwareBazaar + ThreatFox + URLhaus (abuse.ch suite)
**Value: ★★★★★ | Effort: Low (three for the price of one auth key)**

All three services from abuse.ch share the same free authentication token (obtained at https://auth.abuse.ch/). They are the gold standard for malware sample intelligence and are used by every professional SOC.

**MalwareBazaar** — hash lookup:
```
POST https://mb-api.abuse.ch/api/v1/
Body: query=get_info&hash={md5|sha1|sha256}
Header: Auth-Key: {key}
```
Returns: malware family, ClamAV signature, YARA hits, imphash, TLSH, code signing cert info, all hash formats, first seen, download count.
→ *Replaces/complements VirusTotal for hash lookups. Often has samples VT doesn't.*

**ThreatFox** — IOC lookup (IP, domain, URL, hash):
```
POST https://threatfox-api.abuse.ch/api/v1/
Body: {"query": "search_ioc", "search_term": "{ioc}"}
Header: Auth-Key: {key}
```
Returns: threat type, confidence level, malware family, first/last seen, associated hashes, MITRE ATT&CK tags.
→ *C2 infrastructure focus. If an IP/domain is in ThreatFox, it's been used as C2.*

**URLhaus** — URL + domain + IP + hash lookup:
```
POST https://urlhaus-api.abuse.ch/v2/url/    Body: url={url}
POST https://urlhaus-api.abuse.ch/v2/host/   Body: host={domain_or_ip}
POST https://urlhaus-api.abuse.ch/v2/payload/ Body: sha256_hash={hash}
```
Returns: URL status (online/offline), threat type, hosting ASN, linked payload hashes, tags, date added.
→ *Malware distribution URLs. Tells you if a URL/domain/IP has served malware.*

---

### 7. New Providers: Hybrid Analysis / ANY.RUN (Sandbox Results)
**Value: ★★★★☆ | Effort: Low**

For hash lookups, return sandbox analysis results in addition to static detections.

**Hybrid Analysis** (CrowdStrike Falcon Sandbox):
- Free tier: API access included with free account
- Register at https://www.hybrid-analysis.com/signup
```
GET https://www.hybrid-analysis.com/api/v2/search/hash
Header: api-key: {key}
Body (form): hash={sha256}
```
Returns: verdict (`malicious`/`suspicious`/`no-verdict`), threat score 0-100, malware family, MITRE ATT&CK tags, AV multi-scan results, sandbox environment used, submission date.

**ANY.RUN** (interactive sandbox):
- Lookup existing public analyses by hash (no API key needed for public reports)
```
GET https://api.any.run/v1/analysis/?hash={sha256}
Header: Authorization: API-Key {key}
```
Returns: threat level, malware family, network indicators extracted from dynamic analysis, dropped files, C2 extracted from sandbox execution.

→ *For incident responders: seeing a process tree and extracted C2 from a file found in an investigation is enormously valuable, even without running it yourself.*

---

### 8. MITRE ATT&CK Enrichment
**Value: ★★★★★ | Effort: Medium**

The MITRE ATT&CK framework is the universal language of threat intelligence. Almost every threat report, every vendor alert, and every detection rule references ATT&CK technique IDs (T1059, T1071, etc.).

**Two-part implementation:**

**Part A — Inline tagging (easy):**
OTX AlienVault already returns `attack` fields with technique IDs in its pulse data. ThreatFox and Hybrid Analysis also include ATT&CK tags. Parse these from existing API responses and display them as coloured `T####` badge chips under the relevant provider card.

**Part B — Technique lookup tab (medium):**
Download the ATT&CK STIX bundle (free, from MITRE's TAXII server or as a static JSON — updated quarterly) and ship it as a bundled resource. Add a search field where analysts can type a technique ID or name and see: technique description, tactics it belongs to, mitigations, detection guidance, and groups/software known to use it.

**MITRE TAXII endpoint (no auth required):**
```
https://attack-taxii.mitre.org/api/v21/
Collection: enterprise-attack, mobile-attack, ics-attack
```
Or download the JSON bundle: `https://github.com/mitre/cti`

---

### 9. Timeline Builder
**Value: ★★★★★ | Effort: Medium**

A `Timeline` tab where analysts can build a linear event timeline for an investigation. Each entry has:
- Timestamp (manual entry or auto-populated from lookup results)
- Artifact (linked to a full result, or free-text)
- Description/notes
- Tags (IOC, persistence, lateral movement, exfiltration, etc.)
- Attachments (screenshot links)

Entries are stored in the GRDB database (already in the project) under a case name.

**Export formats:**
- Markdown table (paste into incident reports)
- CSV (import into Excel/Google Sheets)
- HTML with embedded screenshots

This transforms Nyctimene from a lookup tool into an investigation management tool. This is the feature that makes analysts want to use it every day.

---

### 10. macOS Persistence Scanner
**Value: ★★★★★ | Effort: Medium**

A "Persistence" tab that enumerates all common macOS persistence mechanisms on the local system and shows each item's status (known-good, unknown, flagged by any provider).

**Locations to check:**
```
~/Library/LaunchAgents/               (user launch agents)
/Library/LaunchAgents/                (system-wide launch agents)
/Library/LaunchDaemons/               (root-level daemons)
~/Library/Application Support/com.apple.backgroundtaskmanagementd/   (BTMD, macOS 13+)
/Library/PrivilegedHelperTools/       (SMJobBless helpers)
/Library/Extensions/                  (kernel extensions)
~/Library/Application Support/*/     (app-specific helpers)
/etc/periodic/                        (cron-like scheduled tasks)
~/Library/Preferences/com.apple.loginitems.plist
```

For each item found: show the plist content (for LaunchAgents/Daemons), the `Program` or `ProgramArguments` path, whether the binary exists and is signed, and a one-click button to look up the binary hash or domain in all providers.

**Bonus:** Highlight items created in the last 7 days in orange — new persistence is a red flag.

---

## Part 2: Ten High-Quality OSINT / Threat Intel Sources

| # | Service | URL | Key Artifacts | Free Tier | Auth |
|---|---|---|---|---|---|
| 1 | **AbuseIPDB** | abuseipdb.com | IP | 1,000/day | API key |
| 2 | **GreyNoise** | greynoise.io | IP | 50/week (Community) | API key |
| 3 | **MalwareBazaar** | bazaar.abuse.ch | Hash | Unlimited | abuse.ch key |
| 4 | **ThreatFox** | threatfox.abuse.ch | IP, domain, URL, hash | Unlimited | abuse.ch key |
| 5 | **URLhaus** | urlhaus.abuse.ch | URL, domain, IP, hash | Unlimited | abuse.ch key |
| 6 | **Hybrid Analysis** | hybrid-analysis.com | Hash, file | Unlimited lookups | API key |
| 7 | **Censys** | search.censys.io | IP, domain, cert | 100 credits/month | API token |
| 8 | **Criminal IP** | criminalip.io | IP, domain | Limited (Starter plan) | API key |
| 9 | **crt.sh** (Sectigo) | crt.sh | Domain/cert | Unlimited | None |
| 10 | **SecurityTrails** | securitytrails.com | Domain, IP (passive DNS, WHOIS history) | 50/month | API key |

**Notes:**
- MalwareBazaar, ThreatFox, and URLhaus all use the same `auth.abuse.ch` account and key — the user registers once
- crt.sh requires no account at all — `GET https://crt.sh/?q={domain}&output=json`
- SecurityTrails is the best passive DNS source available on a free plan; shows historical DNS A/MX/NS records and WHOIS history

---

## Part 3: Static Malware / File Analysis

### Design Philosophy

Static analysis never executes the file — it is safe to run on a live system. The approach:

1. **Designated analysis directory:** `/opt/malware-analysis/` with restricted permissions. Strip execute bit from all samples on arrival.
2. **Tool invocation via `Process()`:** Call CLI tools and capture stdout/stderr into the UI.
3. **Quarantine attribute:** Apply `com.apple.quarantine` xattr to all analysed files as belt-and-suspenders.
4. **No internet access during analysis:** Tools run fully offline. Hash lookups against threat intel APIs happen separately, explicitly initiated by the analyst.

### Tool Chain (all callable via `Process()` from Swift)

| Tool | Install | What it does |
|---|---|---|
| `file` | Built-in | Magic byte file type identification |
| `strings -a` | Built-in | Extract printable strings (URLs, paths, error messages) |
| `otool -L` | Xcode CLT | List dynamically linked libraries (Mach-O) |
| `otool -l` | Xcode CLT | All Mach-O load commands, segments, sections |
| `codesign -dvvv` | Built-in | Signature validity, signer identity, Team ID, entitlements |
| `spctl -a -vvv` | Built-in | Gatekeeper/notarization status |
| `nm` | Built-in | Symbol table (imported/exported function names) |
| `yara` | `brew install yara` | YARA rule matching against any file |
| `diec` | Download: [Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) | Packer/compiler/protector detection + per-section entropy |
| `exiftool` | `brew install exiftool` | Embedded metadata (build timestamps, author strings) |

### YARA Integration

- Maintain a user-configurable rules directory (`~/Library/Application Support/Nyctimene/yara_rules/`)
- Ship built-in rules based on Apple's XProtect YARA signatures (already on every Mac at `/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara`)
- Allow user to add custom rule files or directories
- Run `yara -r /rules_dir/ /path/to/sample` on demand per file
- Show each matching rule with its meta fields (author, description, date, reference)

### Proposed "File Analysis" Tab

```
[ Drop a file here or click to browse ]

File: malware.bin
Type: Mach-O 64-bit ARM64 executable
Size: 284,312 bytes
MD5:  d41d8cd98f00b204e9800998ecf8427e
SHA256: e3b0c44298fc1c149afb...

[ Lookup hash in all providers ]  [ Run YARA ]  [ Extract strings ]

─── Signatures ────────────────────────────────────
Code signed: NO
Notarized:   NO
Quarantine:  YES (com.apple.quarantine)

─── Linked Libraries ──────────────────────────────
/usr/lib/libSystem.B.dylib
/usr/lib/libcrypto.dylib          ← unusual for a simple utility
/System/Library/Frameworks/...

─── Strings (top 50, filtered) ────────────────────
https://185.220.101.x/beacon     ← highlighted: URL-like string
/Users/admin/.ssh/id_rsa         ← highlighted: sensitive path
cmd.exe /c whoami                ← highlighted: suspicious command

─── YARA Matches ──────────────────────────────────
[MATCH] Cobalt Strike Beacon (XProtect.yara:line 142)
        Author: Apple
        Description: Matches CS beacon shellcode patterns
```

---

## Part 4: macOS FSEvents Analysis

### What FSEvents Are

The `fseventsd` daemon logs every file system operation on every mounted volume to a hidden binary log directory at `/.fseventsd/` (HFS+) or `/System/Volumes/Data/.fseventsd/` (APFS). These logs survive reboots and are invaluable for DFIR timeline reconstruction.

**What they tell you:**
- Exact file paths that were created, modified, renamed, or deleted — even if the files themselves are gone
- Whether an operation was done via CLI vs. GUI (different flag patterns)
- USB drive insertions and what files were accessed on them
- Malware persistence installation (creation in LaunchAgents, etc.)
- Archive extraction contents (every path in a zip that was extracted, even if later deleted)
- Cloud sync activity (iCloud, Dropbox) indicating potential exfiltration paths

**What they DON'T tell you:**
- Precise per-event timestamps (only inferred from the log file's mtime/ctime)
- File contents — only paths and operation types

### File Format

Files in `.fseventsd/` are gzip-compressed binary files named after hex event ID ranges. Three format versions exist:
- `1SLD` — macOS 10.5–10.12
- `2SLD` — macOS 10.13–12
- `3SLD` — macOS 13 (Ventura) and later — **requires updated parser**

### Parsing Tools

**`macos-fseventsd`** (Rust, cross-platform, handles all three versions):
- GitHub: https://github.com/puffyCid/macos-fseventsd
- Outputs JSON or CSV
- Actively maintained, works on Ventura/Sonoma
- Compile once: `cargo build --release` → ship binary with Nyctimene

**`FSEventsParser`** (Python, widely used in DFIR community):
- GitHub: https://github.com/dlcowen/FSEventsParser
- Outputs TSV and SQLite
- Nicole Ibrahim (mac4n6) fork adds `3SLD` support

### Proposed "FSEvents" Tab in Nyctimene

**Workflow:**
1. Analyst points Nyctimene at an `.fseventsd/` directory (from a mounted image or live collection)
2. Nyctimene shells out to `macos-fseventsd` or a bundled parser, captures JSON output
3. Results load into a searchable, filterable table:
   - Columns: Event ID, Path, Event Type (Created/Modified/Renamed/Deleted/Mounted), Flags
   - Filter by: path substring, event type, flag combination
   - Timeline view: entries sorted by event ID (proxy for chronological order)
4. **Key pivot:** Right-click any path → "Analyze parent domain" (if it's a downloaded file) or "Lookup hash" (if the file still exists on disk)
5. **Highlighting:** Auto-highlight paths matching known suspicious locations: `LaunchAgents/`, `LaunchDaemons/`, `/tmp/`, `Downloads/`, `.ssh/`

**Forensic image support:**
- "Open from mounted image" — point at the `/.fseventsd/` directory on a read-only mounted DMG/sparse bundle
- Warn if the volume appears to be mounted read-write (would contaminate evidence)

**Key caveats to surface in the UI:**
- "Timestamps are approximate: inferred from log file modification times"
- "Events may be coalesced: rapid sequential changes on the same path appear as one record"
- "Log coverage depends on system activity and rotation — may not extend back more than days/weeks on active systems"

---

## Part 5: SQLite Browser Forensics

### Why SQLite

Every major web browser stores its forensically significant data in SQLite databases. These files are accessible on a live system (with appropriate permissions) or from a forensic image, and they contain rich artefacts for investigations.

### Database Locations by Browser

**Google Chrome / Brave / Edge** (`~/Library/Application Support/Google/Chrome/Default/`):
```
History           → urls, visits, downloads, keyword_search_terms tables
Cookies           → cookies table (domain, name, value, creation_time, last_access_time)
Login Data        → logins table (origin_url, username_value — password is AES-GCM encrypted)
Favicons          → favicons, icon_mapping tables
Web Data          → autofill, credit_cards tables
Network Action Predictor → resource_prefetch_predictor_host_resource_table
```

**Mozilla Firefox** (`~/Library/Application Support/Firefox/Profiles/*.default*/`):
```
places.sqlite     → moz_places (url, title, visit_count, frecency),
                     moz_historyvisits (visit_date, visit_type),
                     moz_bookmarks, moz_annos (page annotations/favicons)
cookies.sqlite    → moz_cookies (host, name, value, creationTime, lastAccessed, expiry, isSecure)
formhistory.sqlite → moz_formhistory (fieldname, value, timesUsed, firstUsed, lastUsed)
downloads.sqlite  → (older Firefox; newer versions use places.sqlite)
webappsstore.sqlite → localStorage data
logins.json + key4.db → encrypted saved passwords (NSS key database)
```

**Safari** (`~/Library/Safari/`):
```
History.db        → history_items (url, visit_count, domain_expansion),
                     history_visits (visit_time, title, load_successful)
CloudTabs.db      → cloud_tabs (tab_uuid, device_uuid, url, title, position)
```

**Note on timestamps:** Chrome/Chromium stores times as microseconds since January 1, 1601 (Windows FILETIME epoch). Firefox stores times as microseconds since Unix epoch. Safari stores times as seconds since January 1, 2001 (Apple Core Data epoch). All three need conversion to display as human-readable dates.

### Proposed "Browser Forensics" Tab

**Workflow:**
1. Auto-detect browsers installed on the local system (scan known paths)
2. OR: Analyst opens a database file manually (for forensic image analysis)
3. Nyctimene copies the database to a working temp directory (never modify originals)
4. Presents a unified view across artifacts:

```
┌─────────────────────────────────────────────────────────────┐
│ Browser Forensics                    [ Open DB file... ]    │
├──────────────────────────────────────────────────────────────┤
│ Source: Chrome/Default  [History] [Cookies] [Downloads]     │
├────────────────────────────────────────────────────────────  │
│ HISTORY                                                      │
│ 2026-04-04 14:32:11  https://evil.example.com/payload.zip   │
│                      [Analyze URL] [Analyze Domain]         │
│ 2026-04-04 14:30:05  https://google.com/search?q=...        │
├──────────────────────────────────────────────────────────────│
│ DOWNLOADS                                                    │
│ 2026-04-04 14:32:45  /Users/victim/Downloads/payload.zip    │
│                      from: https://evil.example.com/        │
│                      [Analyze URL] [Lookup hash if exists]  │
└──────────────────────────────────────────────────────────────┘
```

**Key integration point:** Every URL in browser history is a potential IOC. Provide a one-click "Analyze all URLs" button that feeds every unique domain from browser history into `BulkAnalysisModel` — instantly turning a victim's browser history into a threat hunt.

**SQLite access:** Use GRDB (already in the project) or the built-in `sqlite3` framework. Copy database to a temp path before opening to avoid WAL journal issues on locked files.

**Timestamp normalization utility** (needed for all three browsers):
```swift
// Chrome (microseconds since 1601-01-01)
static func chromeTimestamp(_ t: Int64) -> Date {
    // seconds between 1601-01-01 and 1970-01-01 = 11644473600
    let unixSeconds = Double(t) / 1_000_000.0 - 11_644_473_600.0
    return Date(timeIntervalSince1970: unixSeconds)
}

// Firefox (microseconds since 1970-01-01)
static func firefoxTimestamp(_ t: Int64) -> Date {
    Date(timeIntervalSince1970: Double(t) / 1_000_000.0)
}

// Safari (seconds since 2001-01-01 = Apple epoch)
static func safariTimestamp(_ t: Double) -> Date {
    Date(timeIntervalSinceReferenceDate: t)
}
```

---

## Part 6: Bold Suggestions — Features That Would Make Nyctimene Exceptional

---

### A. Defang / Refang Toggle
**Effort: Trivial | Impact: High daily use**

Threat reports universally defang IOCs: `evil[.]com`, `hxxps://`, `1.2.3[.]4`. Currently analysts must manually refang before pasting into Nyctimene. Auto-detect defanged IOCs in the search bar (and clipboard watch mode) and silently refang before resolution:
- `[.]` → `.`
- `hxxp[s]://` / `hxxps://` → `https://`
- `1.2.3[.]4` → `1.2.3.4`
- `at[.]` prefix removal (common in some tools)

This is a 20-line addition to `ArtifactResolver.swift` with outsized daily impact.

---

### B. Email Header Analyser
**Effort: Low | Impact: High for phishing investigations**

Paste a raw email header. Nyctimene:
1. Extracts all `Received:` hop IPs
2. Checks SPF/DKIM/DMARC pass/fail from the `Authentication-Results:` header
3. Builds a visual hop chain showing the relay path from sender to recipient
4. Runs every extracted IP through all enabled providers
5. Extracts the `Reply-To:`, `Return-Path:`, and `From:` domains and looks them up

Phishing investigation is one of the most common DFIR tasks and currently requires multiple separate tools (MxToolbox, manual VT lookups, etc.). Nyctimene could collapse this into one step.

---

### C. AI-Powered Investigation Summary
**Effort: Low | Impact: Very High for report writing**

After all provider results are returned for a lookup, add a "Summarize" button that posts the structured results (risk levels, org info, pulse count, ports, CVEs, cert data) to Claude claude-sonnet-4-6 (or another LLM via API) and returns a 2–3 sentence natural language summary:

> *"This IP (185.220.101.47) is a Tor exit node operated by a German autonomous system and has been reported 847 times on AbuseIPDB for brute force and DDoS activity. GreyNoise classifies it as mass-scanning noise targeting port 22. It is unlikely to represent a targeted attack against your organisation but should be blocked at the perimeter."*

This is transformative for less experienced analysts who receive raw scores but struggle to synthesise them into an investigation narrative. Also dramatically speeds up report writing for experienced analysts.

**Implementation:** One API call per lookup, only on demand (the user clicks "Summarize"). Display below the notes section.

---

### D. Network Graph / Pivot Visualisation
**Effort: High | Impact: Very High for advanced investigations**

A force-directed graph view where investigated artifacts become nodes and relationships become edges. Built using a Swift-wrapped WebView running a JavaScript graph library (D3.js or vis.js, bundled as a local resource — no CDN).

Node types: IP (circle), Domain (rectangle), Hash (hexagon), ASN/Org (cloud), CVE (triangle)
Edges: resolves-to, hosted-on, contacted-by, same-ASN, shares-cert, related-sample

Click a node to expand it (runs lookups for connected artifacts). Shift-click to pin. Right-click to open full report.

This is the feature that makes threat intelligence work feel like detective work rather than form-filling.

---

### E. macOS Triage Report Generator
**Effort: Medium | Impact: Very High for incident response**

A single "Triage" button that collects a forensic snapshot of the local Mac and produces a structured HTML/PDF report. Collected artifacts:

- Running processes (`ps aux` parsed into a table)
- Active network connections (`lsof -i` — already in Nyctimene)
- Launch agents and daemons (all four standard locations)
- Login items (BTMD database, SMAppServiceRegistration)
- Cron jobs (`crontab -l`)
- Recently modified files in sensitive locations (last 24h in `/tmp/`, `~/Downloads/`, `~/Library/LaunchAgents/`)
- Loaded kernel extensions (`kmutil showloaded`)
- Mounted volumes
- Recently installed applications
- Environment variables

Then: automatically feed every external IP from network connections and every executable path from persistence locations through Nyctimene's provider stack. The final report is a complete "initial triage" document ready to share with a CISO.

---

### F. MISP Integration
**Effort: Medium | Impact: Very High for team environments**

MISP (Malware Information Sharing Platform) is the de-facto standard for sharing structured threat intelligence within organisations and between trusted communities. Add a MISP export/import integration:

- **Push:** After any lookup, "Push to MISP" exports the artifact + all results as a MISP event with attributes tagged to appropriate MISP categories and MITRE ATT&CK galaxies
- **Pull:** Subscribe to a MISP feed — new IOCs from the feed appear in Nyctimene's Feeds tab and can be bulk-analysed

Configuration: MISP instance URL + API key in Settings. Could work with any self-hosted or cloud MISP instance.

This makes Nyctimene a front-end for team-shared threat intelligence, not just a solo analyst tool.

---

### G. YARA Rule IDE
**Effort: Medium | Impact: High for threat hunting**

A simple in-app YARA rule editor:
- Syntax-highlighted text editor (keywords, strings, conditions in distinct colours)
- A file picker to select a sample to test against
- "Run" button that executes `yara <rule_temp_file> <sample>` and shows matches inline
- A local rule library: save and name rules, organised by family/tactic
- "Submit to VT LiveHunt" button for users with Premium VT accounts

This is the tool that malware analysts and threat hunters need but don't have in a nice macOS-native package. It collapses `vim rule.yar && yara rule.yar sample.bin` into a proper UI.

---

### H. Tor Exit Node & VPN/Proxy Detection
**Effort: Low | Impact: High as a context signal**

Add a fast, offline check against the Tor Project's official exit node list (updated daily, ~1,400 IPs) and integrate it into IP lookup results. A "TOR EXIT" badge in the artifact header immediately contextualises why an IP is appearing in logs without attributing it to a targeted actor.

**Tor exit list:** `https://check.torproject.org/torbulkexitlist` (plain text, no auth) — cache locally, refresh daily.

For VPN/datacenter detection: AbuseIPDB's `usageType` field (`VPN Service`, `Data Center/Web Hosting/Transit`, `Residential`) covers this without requiring an additional API.

---

### I. Password/Secret Pattern Detection in Strings Output
**Effort: Low | Impact: High for file analysis**

When displaying the output of `strings` in the File Analysis tab, automatically run regex patterns over the extracted strings to highlight:
- AWS access keys (`AKIA[0-9A-Z]{16}`)
- Private key headers (`-----BEGIN RSA PRIVATE KEY-----`)
- JWT tokens (`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)
- IP addresses (external, non-RFC1918)
- URLs and domain names (annotated with live lookup button)
- Windows registry paths
- Base64 blobs over 40 chars (potential encoded payloads)
- Common C2 user agents (Cobalt Strike, Meterpreter)

Highlight matches in different colours by category. This is a free win on top of the file analysis foundation.

---

### J. Passive DNS / Historical WHOIS via SecurityTrails
**Effort: Low | Impact: High for domain investigations**

SecurityTrails provides historical DNS records and WHOIS snapshots — showing what an IP pointed to last year, or what the registrant was before a domain changed hands.

**API (free tier: 50 requests/month):**
```
GET https://api.securitytrails.com/v1/domain/{domain}/history/a
GET https://api.securitytrails.com/v1/ips/nearby/{ip}
GET https://api.securitytrails.com/v1/domain/{domain}/whois
Header: apikey: {key}
```

**What it adds to Nyctimene:**
- For a domain: "This domain used to resolve to 45.33.32.156 (known malicious IP) until 3 months ago"
- For an IP: "These other domains have pointed to this IP: [list]" — classic C2 hosting pivot
- Historical WHOIS: see if a domain changed registrant or privacy protection status recently

Register at: https://securitytrails.com/signup

---

## Implementation Priority Order

Based on value/effort ratio, suggested implementation order:

1. **Defang/Refang auto-detect** (30 min, transforms daily UX)
2. **crt.sh Certificate Transparency** (2h, no API key required)
3. **AbuseIPDB provider** (2h, same pattern as existing providers)
4. **GreyNoise provider** (2h, same pattern)
5. **abuse.ch suite** — MalwareBazaar, ThreatFox, URLhaus (4h, three providers one key)
6. **Clipboard Watch Mode** (3h, killer feature)
7. **Bulk Import from text/CSV** (3h, critical for real investigations)
8. **Browser Forensics tab** (6h, high value, GRDB already in project)
9. **File Analysis (static) tab** (8h, YARA + tool chain)
10. **FSEvents tab** (6h, pivot to full forensics tool)
11. **MITRE ATT&CK inline tags** (4h, parses existing OTX/ThreatFox data)
12. **Timeline Builder** (8h, transforms case management)
13. **Persistence Scanner** (6h, high value for IR)
14. **AI Summary button** (3h, Claude API integration)
15. **Triage Report Generator** (10h, flagship feature)
16. **Email Header Analyser** (6h)
17. **MISP Integration** (10h, enterprise feature)
18. **Network Graph** (15h, powerful but complex)
19. **YARA Rule IDE** (8h)
20. **SecurityTrails Passive DNS** (3h)
