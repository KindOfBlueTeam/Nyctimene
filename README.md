# Nyctimene

**On-demand threat intelligence for investigators, IT, and blue teamers.**

Nyctimene is a macOS menubar tool for quickly looking up IP addresses, domains, URLs, and file hashes against the most widely-used open threat intelligence platforms. It also scans your live network connections and can analyse PCAP files — surfacing risky hosts before you have to hunt for them manually.

---

## Screnshots

<img width="527" height="559" alt="2" src="https://github.com/user-attachments/assets/5f6ea868-4d01-4d67-9e76-53b8ef5ce616" />


<img width="1080" height="713" alt="1" src="https://github.com/user-attachments/assets/e2f3643b-0ae2-4e91-963b-df30fff77028" />


---

## Features

| Capability | Detail |
|---|---|
| **Manual lookup** | Paste any IP, domain, URL, or hash (MD5/SHA1/SHA256/SHA512) and get results in seconds |
| **Risk Radar** | Interactive multi-source visualization — adapts between radar chart, XY scatter, and single-source gauge based on how many sources you select |
| **Nyctimene Risk Score** | Composite 1–100 score derived from VirusTotal, MalwareBazaar, ThreatFox, and URLhaus — weighted by source count and confirmation level |
| **Scan current connections** | Enumerates live sockets via `lsof` and runs every external IP through all enabled providers |
| **PCAP analysis** | Open an existing `.pcap` file or start a live capture; all IPs and DNS names are extracted and analysed automatically |
| **Domain registration** | RDAP lookup shows registrar, registration date, expiry, and status for any domain |
| **IP ownership** | IPInfo.io enrichment shows ASN and company name — catches "malicious" alerts that are actually Apple, Cloudflare, etc. |
| **Configurable VT thresholds** | Set your own detection count thresholds for Suspicious vs Malicious in Settings → Scoring |
| **Stop analysis** | Cancel in-flight queries at any time without blocking the UI (Escape key) |
| **Domain blocking** | One-click `/etc/hosts` block and unblock, with a managed list in Settings |
| **IOC feed manager** | Add any URL-based threat intel feed; community feeds for GreyNoise, URLhaus, ThreatFox, and MalwareBazaar are pre-loaded |
| **Screenshot export** | Saves a full-results PNG with case name, actor name, and notes — defanged filename included |
| **Investigation context** | Case name, actor name, and freeform notes fields travel with every result |

---

### Providers

| Provider | What it reports | Artifact types | Risk signal |
|---|---|---|---|
| [VirusTotal](https://www.virustotal.com) | Detection count across ~90 AV engines | IP, domain, URL, hash | ✅ Scored |
| [MalwareBazaar](https://bazaar.abuse.ch) | Confirmed malware sample database | Hash (MD5/SHA1/SHA256) | ✅ Scored |
| [ThreatFox](https://threatfox.abuse.ch) | C2 infrastructure and payload IOCs | IP, domain, URL, hash | ✅ Scored |
| [URLhaus](https://urlhaus.abuse.ch) | Active malware distribution URLs | IP, domain, URL, MD5/SHA256 | ✅ Scored |
| [OTX AlienVault](https://otx.alienvault.com) | Threat pulse count from the community | IP, domain, URL, hash | Context only |
| [URLScan.io](https://urlscan.io) | Scan history and malicious verdicts | Domain, URL | Context only |
| [Shodan](https://shodan.io) | Open ports and known CVEs | IP | Context only |
| [IPInfo.io](https://ipinfo.io) | ASN and company ownership | IP | Context only |

MalwareBazaar, ThreatFox, and URLhaus share a single **abuse.ch** API key.

---

## Risk Radar

The **Risk Radar** is the central visualization in every lookup result. It sits in the right panel alongside the provider cards.

### How the score is calculated

Each of the four *scored* sources (VT, MalwareBazaar, ThreatFox, URLhaus) maps to a level on a 1–5 scale:

| Level | Meaning |
|---|---|
| 1 | Not queried / N/A for this artifact type |
| 2 | Clean — no signal |
| 3 | Low signal |
| 4 | Likely malicious |
| 5 | Confirmed malicious |

The composite **1–100 score** is:

```
normalized  = (sum_of_levels - 2N) / (3N)
multiplier  = N / N_total            # N = applicable sources, N_total = 4
score       = normalized × multiplier × 99 + 1
```

- All sources clean → score near 1
- All sources confirmed malicious → score near 100
- Sources with no data (level 1) reduce the ceiling — more confirming sources are required to reach 100

### Visualization modes

Select which sources to display using the checkboxes below the chart. The visualization adapts automatically:

| Sources selected | Mode |
|---|---|
| 3 or more | Radar chart — polygon shape adapts to the number of sources |
| 2 | XY scatter — one source on each axis; the risk badge floats at the intersection |
| 1 | Arc gauge — shows raw level (0–4) and source detail |
| 0 | Prompt to select a source |

The **center badge** — a hexagon stroked in the risk accent color (red / orange / green) containing the composite score — is present in radar and XY modes. Sources that returned no data for the current artifact type appear with a grey dot and do not affect the chart shape.

---

## Requirements

- macOS 13 Ventura or later
- Xcode Command Line Tools: `xcode-select --install`
- Swift 5.9+ (included with Xcode CLT)

---

## Installation

### Option A — Build and install with one command

```bash
git clone https://github.com/KindOfBlueTeam/Nyctimene.git
cd Nyctimene
./Scripts/install.sh
```

This builds a release `.app`, copies it to `/Applications`, and launches it.

### Option B — Build only, then drag to Applications

```bash
git clone https://github.com/KindOfBlueTeam/Nyctimene.git
cd Nyctimene
./Scripts/build.sh
```

This produces `Nyctimene.app` in the project root. Drag it to `/Applications` (or anywhere you like), then double-click to launch.

> **First launch:** macOS Gatekeeper may say "Nyctimene cannot be opened because it is from an unidentified developer." Right-click the app → **Open** → **Open** to accept the ad-hoc signature once. You will not be asked again.

---

## Adding API Keys

Open the menubar icon → **Settings** → **Providers**. Each provider has a toggle and an API key field.

Keys are stored in the macOS Keychain under the service identifier `com.nyctimene`, consolidated into a single item so you are prompted at most once after installation.

### Where to get each key

| Provider | Free tier | Sign-up link |
|---|---|---|
| **VirusTotal** | 500 lookups/day, 4/min | https://www.virustotal.com/gui/join-us |
| **OTX AlienVault** | Unlimited | https://otx.alienvault.com (register → API → Copy Key) |
| **Shodan** | Limited free search | https://account.shodan.io/register |
| **URLScan.io** | 1,000 lookups/day | https://urlscan.io/user/signup |
| **IPInfo.io** | 50,000 lookups/month | https://ipinfo.io/signup |
| **abuse.ch** *(MalwareBazaar + ThreatFox + URLhaus)* | Free | https://auth.abuse.ch — one key covers all three services |

All providers are optional. Nyctimene silently skips any provider whose key is not configured.

---

## Using Nyctimene

### Manual Lookup

1. Click the owl icon in the menubar → **Analyze**
2. Optionally fill in **Case** and **Actor** fields for investigation tracking
3. Paste an IP address, domain, URL, or file hash into the search bar and press **Return**
4. Results from all enabled providers appear in parallel
5. The **Risk Radar** on the right shows the composite score and per-source risk levels
6. Press **Stop** (or Escape) at any time to cancel in-flight queries

**Supported input formats**

| Type | Example |
|---|---|
| IPv4 address | `1.2.3.4` |
| Domain | `evil.example.com` |
| URL | `https://evil.example.com/path?q=1` |
| MD5 hash | `d41d8cd98f00b204e9800998ecf8427e` |
| SHA1 hash | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| SHA256 hash | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SHA512 hash | *(128 hex characters)* |

### Configuring VirusTotal Thresholds

Go to **Settings → Scoring** to set the detection count thresholds:

- **Suspicious** — minimum VT hits to flag as suspicious (default: 1)
- **Malicious** — minimum VT hits to flag as malicious (default: 3); always at least 1 higher than suspicious

This is useful when infrastructure IPs are being over-flagged by noisy AV engines with 1–2 detections.

### Scan Current Connections

1. Click **Connections** in the tab bar
2. Click **Scan Now** — Nyctimene runs `lsof -i` to enumerate all active external connections
3. Every unique external IP is analysed in parallel; results populate the table in real time
4. Use the **Risky only** toggle to filter to suspicious or malicious hosts
5. Click any artifact name in the table to open the most relevant provider report in your browser

### PCAP Analysis

1. Click **PCAP** in the tab bar
2. To analyse an existing file: click **Open PCAP…** and select a `.pcap` file
3. To capture live traffic: click **Start Capture** (requires your password to run `tcpdump`), then **Stop Capture** when done — the capture is analysed automatically
4. All extracted IPs and domain names flow into the results table

### Saving a Screenshot

Click the **camera** icon in the top-right of any result. You will be prompted to choose a save location. The filename is automatically defanged (e.g. `Case_Actor_evil[.]com_2026-04-05.png`).

### Blocking a Domain

Click **Block in /etc/hosts** in the artifact header. This writes a `0.0.0.0` entry to `/etc/hosts` and flushes the DNS cache. The domain will fail to resolve until you click **Unblock** or remove the entry in **Settings → Block List**.

---

## IOC Feeds

The **Feeds** tab lets you maintain a list of external threat intel feed URLs for reference during investigations.

**Pre-loaded feeds**

| Name | URL |
|---|---|
| GreyNoise | https://viz.greynoise.io/query/last_seen:1d classification:"malicious" |
| URLhaus | https://urlhaus.abuse.ch/browse/ |
| ThreatFox | https://threatfox.abuse.ch/browse/ |
| MalwareBazaar | https://bazaar.abuse.ch/browse/ |

**Adding a custom feed**

1. Go to **Feeds** tab
2. Enter a name and the URL of the feed directly in the add field
3. Press **Add** — the feed is saved immediately and persists across launches

**Removing a feed**

Select a feed and click the **−** button. This removes it permanently (it will not be re-added on next launch).

---

## Data and Privacy

- All lookups are performed on demand — Nyctimene never phones home on its own.
- API keys are stored in the macOS Keychain. They are only sent to the provider's own endpoint.
- Settings and the lookup database are stored in `~/Library/Application Support/Nyctimene/`.
- Live PCAP captures are written to a temporary file and deleted when the session ends.

---

## Uninstall

To remove Nyctimene and every trace it leaves on your system:

```bash
# From inside the cloned project directory:
./Scripts/uninstall.sh

# Or run it directly from anywhere:
bash <(curl -fsSL https://raw.githubusercontent.com/KindOfBlueTeam/Nyctimene/main/Scripts/uninstall.sh)
```

The uninstaller:
- Quits the running app
- Removes `Nyctimene.app` from `/Applications` (and `~/Applications` if present)
- Deletes all API keys from the Keychain
- Removes `~/Library/Application Support/Nyctimene/` (settings, database, IOC feeds)
- Removes any `/etc/hosts` entries written by Nyctimene and flushes the DNS cache
- Removes temporary PCAP capture files

Nothing outside those locations is ever written by Nyctimene.

---

## Building from Source

```bash
# Debug build — fast iteration (kills existing instance, rebuilds, relaunches)
./Scripts/dev.sh

# Release build + assemble .app (default)
./Scripts/build.sh
./Scripts/build.sh release
```

The assembled `Nyctimene.app` is ad-hoc signed with `codesign --sign -`. If you have an Apple Developer certificate and want to sign with it instead, replace the signing step in `Scripts/build.sh` with your identity.

---

## License

MIT — see [LICENSE](LICENSE) for details.
