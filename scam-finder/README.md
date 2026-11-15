# Scam Finder

Give it one suspicious link. It works out what the site is, then finds the other sites run by the same operation and draws the whole thing as a map.

It was built around a real case: a WhatsApp message promising a "National Heroes' Day gift" from a well-known Jamaican brand. One search on a file that page served led to more than 250 sibling domains running the same kit, with lures aimed at a dozen countries.

```bash
node scam-finder/cli.js investigate "https://suspicious.example/abc?s=wa" --html map.html
```

It needs Node 20 or newer and nothing else: no install step, no API keys.

## What it does

1. **Profiles the link.** Fetches the page as plain text (nothing is rendered or run) and reads what its scripts do: device cloaking, spoofed link previews, hidden redirects. Adds DNS, hosting, registration date and registrar, certificates, and whether public blocklists already list it.
2. **Finds what makes it distinctive.** Kit files at unusual paths, byte-identical images, the exact page title, a dedicated server, shared certificates, tracking IDs.
3. **Searches for the same fingerprints elsewhere**, mainly in the [urlscan.io](https://urlscan.io) archive of scanned pages. A fingerprint that matches thousands of sites is thrown away as too common to mean anything.
4. **Visits a sample of what it found**, to see which sites are still up and what they are showing today.
5. **Scores every site** from 0 to 100, keeping each reason alongside the number, and groups sites into campaigns (same lure) and shared infrastructure (same kit file, same registration day, same nameserver pair).
6. **Draws the map**: one self-contained HTML file with a radial tree, a network view, and the evidence for every site.

## Using it

```bash
# Investigate a link (about 30 seconds to 4 minutes, depending on how much it finds)
node scam-finder/cli.js investigate "<url or domain>"

# Go wider: search again from every campaign found, and visit every site
node scam-finder/cli.js investigate "<url>" --deep --html map.html --out result.json

# Just score one link, no searching
node scam-finder/cli.js investigate "<url>" --depth 0

# Collect fresh leads by theme, with no starting link
node scam-finder/cli.js hunt jamaica
node scam-finder/cli.js hunt lottery whatsapp-giveaway --html leads.html
node scam-finder/cli.js hunt --query 'page.title:"claim your prize"' --keyword jncb

# Re-render a saved result
node scam-finder/cli.js report result.json --md report.md
```

`node scam-finder/cli.js help` lists every option. Defanged input (`hxxps://example[.]com`) is accepted everywhere, so indicators can be pasted straight from a report.

Three ways to read a result:

| Flag | Output |
| --- | --- |
| _(none)_ | A readable summary on stdout |
| `--json` | The complete result |
| `--compact` | A short JSON digest, sized to fit in a language model's context |

`--out`, `--html` and `--md` save files as well, whichever view is printed.

### For AI agents

There are three ways in, all returning the same data.

**MCP server.** `scam-finder/mcp-server.js` speaks the Model Context Protocol over stdio with no dependencies. The repository's `.mcp.json` registers it, so Claude Code offers the tools as soon as it opens this folder. For any other client:

```json
{ "mcpServers": { "scam-finder": { "command": "node", "args": ["scam-finder/mcp-server.js"] } } }
```

| Tool | What it does |
| --- | --- |
| `investigate_url` | Profile a link and map what it is connected to |
| `hunt_scams` | Collect leads from profiles, queries or keywords |
| `get_domain_details` | Read the full record for any domain in a saved result |
| `render_report` | Write the HTML map or a Markdown report |
| `list_hunt_profiles` | Describe the saved hunts |

Each run saves the full result and the map to disk and replies with a digest, so a large investigation never floods the conversation.

**Command line.** `--compact` prints the same digest as JSON. Progress goes to stderr, results to stdout.

**HTTP.** With the web-check server running (`node server`):

```
GET /api/scam-finder?url=<link>&depth=1
```

This uses smaller limits so that it answers within the server's request timeout. The map itself is served at `/scam-finder/`, where it takes a link, calls the API and draws the result.

**Claude Code skill.** `.claude/skills/scam-finder` teaches Claude when to reach for the tool and how to report what it finds.

## Where the data comes from

Everything is public, free and needs no key.

| Source | Used for |
| --- | --- |
| The target site itself | Page content, scripts, redirects, kit signatures |
| [urlscan.io](https://urlscan.io) search | Finding other sites that served the same files, titles or addresses |
| DNS over HTTPS (Google, Cloudflare) | Addresses and nameservers, from networks that block raw DNS |
| Team Cymru | Which network an address belongs to |
| RDAP | Registration date, registrar, abuse contact |
| Cert Spotter, crt.sh | Certificates, and domains sharing one |
| ip.thc.org | Other domains on a dedicated server |
| Blocklists | OpenPhish, phishunt.io, Global Anti-Scam Org, CERT Polska, Phishing.Database and more (`cli.js feeds`) |

Optional environment variables:

| Variable | Effect |
| --- | --- |
| `URLSCAN_API_KEY` | Searches further back than 30 days, with higher rate limits |
| `CERTSPOTTER_TOKEN` | Higher Certificate Transparency limits |
| `SCAM_FINDER_CACHE_DIR` | Where lookups are cached (default: the system temp directory) |
| `SCAM_FINDER_NO_CACHE` | Set to disable the cache |
| `SCAM_FINDER_OUT_DIR` | Where the MCP server saves results |
| `NODE_USE_ENV_PROXY=1` | Makes Node honour `HTTPS_PROXY` |

Lookups are cached on disk for between 30 minutes and a week depending on how fast they go stale, and every service is rate-limited per host, so repeat runs are quick and polite.

## How to read a score

A score adds up independent pieces of evidence. Each has a weight, and they combine so that several weak signals count for something without any one of them being decisive.

| Level | Score | Read it as |
| --- | --- | --- |
| Critical | 85 to 100 | Strong direct evidence: a known kit, a blocklist entry, cloaking plus a borrowed brand |
| High | 65 to 84 | Several signals agree |
| Medium | 40 to 64 | Worth a look |
| Low | under 40 | Little or nothing against it |

**A score is a reason to look, not a verdict.** A site found by a search still has to earn its score on its own evidence, and links to a seed count for less when the seed itself looks innocent. Long-established domains are discounted. Low does not mean safe: it means nothing was found.

Things that will mislead it:

- **Shared infrastructure.** Sites behind Cloudflare or on big clouds share addresses with strangers, so those are never used as links. Nameserver pairs and same-day registration are shown as weak links for the same reason.
- **The 30-day window.** Without a urlscan.io key, only sites scanned in the last 30 days can be found.
- **Cloaking.** A site that shows scanners a blank page may be missed, or look harmless.
- **Hunts.** Profile searches return candidates. Many are honest sites that matched a word in a title.

## Hunt profiles

`cli.js profiles` lists them: `jamaica`, `whatsapp-giveaway`, `lottery`, `bank-phishing`, `delivery`, `crypto`, `tech-support`, `government-benefit`.

The `jamaica` profile looks for pages that borrow Jamaican brands (banks, telecoms, utilities, government agencies), pages pairing "Jamaica" with prize or sign-in wording, holiday giveaway lures, and copies of the WhatsApp gift kit whose lure is aimed at Jamaica. No site is treated as suspect for being Jamaican, or for where it is hosted. Leads come from what a page claims to be.

## Extending it

All of the knowledge lives in three data files, written to be edited:

- `data/signatures.js`: fingerprints of scam kits. Add one when you meet a new kit: a few odd markers and, if you know one, a search that finds more copies.
- `data/brands.js`: brands that scams borrow, with the domains the real organisations use.
- `data/profiles.js`: saved hunts.

Blocklist feeds are in `lib/sources/feeds.js`. A new data source is one module in `lib/sources/` plus a call from `lib/investigate.js`.

```bash
node --test "scam-finder/test/*.test.js"   # offline, about five seconds
node scam-finder/cli.js build-viewer       # after editing scam-finder/viewer/
```

The tests run against a canned network, so they never go online. The viewer's sources are in `viewer/`; `build-viewer` assembles them into `public/scam-finder/index.html`, the page the server hosts.

## Safety

- **Read-only.** It makes ordinary GET requests and reads public records. It never submits forms, logs in, or probes for weaknesses.
- **Suspect pages are treated as hostile.** Bodies are size-capped and parsed as text. Redirects are followed by hand, and every hop is refused if it points at a private, loopback or link-local address. That check resolves the name through public DNS just before each request, which stops ordinary cases; if you expose the API on a network with sensitive internal services, also restrict the server's outbound access.
- **No personal data.** Registrant names, emails and addresses are dropped when registration records are parsed. Only registrar, dates, organisation and country are kept.
- **Indicators are defanged** (`hxxps://example[.]com`) in every report, and the map never links to a suspect site.

If a site is a scam, report it where it can be acted on: the registrar's abuse contact (shown for each domain), [Google Safe Browsing](https://safebrowsing.google.com/safebrowsing/report_phish/), and the hosting provider. If you have lost money, contact your bank and the police.
