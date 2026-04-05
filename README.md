# Nyctimene

**On-demand threat intelligence for investigators, IT, and blue teamers.**

Nyctimene is a macOS menubar tool for quickly looking up IP addresses, domains, URLs, and file hashes against the most widely-used open threat intelligence platforms. It also scans your live network connections and can analyse PCAP files — surfacing risky hosts before you have to hunt for them manually.

---

## Features

| Capability | Detail |
|---|---|
| **Manual lookup** | Paste any IP, domain, URL, or hash (MD5/SHA1/SHA256/SHA512) and get results in seconds |
| **Scan current connections** | Enumerates live sockets via `lsof` and runs every external IP through all enabled providers |
| **PCAP analysis** | Open an existing `.pcap` file or start a live capture; all IPs and DNS names are extracted and analysed automatically |
| **Domain registration** | RDAP lookup shows registrar, registration date, expiry, and status for any domain |
| **IP ownership** | IPInfo.io enrichment shows ASN and company name — catches "malicious" alerts that are actually Apple, Cloudflare, etc. |
| **Domain blocking** | One-click `/etc/hosts` block and unblock, with a managed list in Settings |
| **IOC feed manager** | Add any URL-based threat intel feed; three community feeds are pre-loaded |
| **Screenshot export** | Saves a full-results PNG with case name, actor name, and notes — defanged filename included |
| **Investigation context** | Case name, actor name, and freeform notes fields travel with every result |

**Providers**

| Provider | What it reports | Artifact types |
|---|---|---|
| [VirusTotal](https://www.virustotal.com) | Detection count across ~90 AV engines | IP, domain, URL, hash |
| [OTX AlienVault](https://otx.alienvault.com) | Threat pulse count from the community | IP, domain, URL, hash |
| [Shodan](https://shodan.io) | Open ports and known CVEs *(exposure, not risk signal)* | IP |
| [URLScan.io](https://urlscan.io) | Scan history and malicious verdicts | Domain, URL |
| [IPInfo.io](https://ipinfo.io) | ASN and company ownership *(context only)* | IP |

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

Keys are stored in the macOS Keychain under the service identifier `com.nyctimene`. They are never sent anywhere except the provider's own API endpoint.

### Where to get each key

| Provider | Free tier | Sign-up link |
|---|---|---|
| **VirusTotal** | 500 lookups/day, 4/min | https://www.virustotal.com/gui/join-us |
| **OTX AlienVault** | Unlimited | https://otx.alienvault.com (register, then: API → Copy Key) |
| **Shodan** | Limited free search | https://account.shodan.io/register |
| **URLScan.io** | 1,000 lookups/day | https://urlscan.io/user/signup |
| **IPInfo.io** | 50,000 lookups/month | https://ipinfo.io/signup |

All five are optional. Nyctimene will silently skip any provider whose key is not configured.

> **After updating:** If you previously installed an older version of Nyctimene, re-save each API key once in Settings. This re-writes the Keychain item with an updated access policy and prevents repeated "Allow access?" dialogs on every launch.

---

## Using Nyctimene

### Manual Lookup

1. Click the owl icon in the menubar → **Analyze**
2. Optionally fill in **Case** and **Actor** fields for investigation tracking
3. Paste an IP address, domain, URL, or file hash into the search bar and press **Return**
4. Results from all enabled providers appear in parallel. The overall risk badge in the header reflects only the threat intelligence providers (VT, OTX, URLScan) — Shodan results are shown in purple as exposure context and do not affect the risk level.

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
| Bitdefender | https://github.com/bitdefender/malware-ioc |
| GitHubInfoSec | https://github.com/GithubInfosec/latest-malware-IoC |
| Bert-JanP | https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds |

**Adding a custom feed**

1. Go to **Feeds** tab
2. Click **+**
3. Enter a name and the URL of the feed (GitHub repos, pastebin lists, or any direct URL are all fine)
4. Click **Add** — the feed is saved immediately and persists across launches

**Removing a feed**

Click the **×** button next to any feed. This removes it permanently (it will not be re-added on next launch).

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
# Debug build (faster compile, more verbose output)
./Scripts/build.sh debug

# Release build + assemble .app (default)
./Scripts/build.sh
./Scripts/build.sh release
```

The assembled `Nyctimene.app` is ad-hoc signed with `codesign --sign -`. If you have an Apple Developer certificate and want to sign with it instead, replace the signing step in `Scripts/build.sh` with your identity.

---

## License

MIT — see [LICENSE](LICENSE) for details.
