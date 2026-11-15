---
name: scam-finder
description: Investigate a suspicious link or domain and map the scam sites connected to it, or hunt for scam websites by theme (WhatsApp giveaways, lottery and advance-fee pitches, bank phishing, scams aimed at Jamaica). Use when the user shares a link they think is a scam, asks whether a site is safe, wants to find related scam sites, or asks for a map or report of scam infrastructure.
---

# Scam Finder

A read-only OSINT tool in `scam-finder/`. It profiles a suspect link, finds other sites sharing its fingerprints, scores each one with reasons, and draws a map. It needs only Node 20+.

## Run it

If the `scam-finder` MCP tools are available (`investigate_url`, `hunt_scams`, `get_domain_details`, `render_report`, `list_hunt_profiles`), use those. Otherwise use the command line from the repository root:

```bash
# One link: profile it and find what it is connected to
node scam-finder/cli.js investigate "<url or domain>" --compact --out result.json --html map.html

# Wider and slower: search again from every campaign found, visit every site
node scam-finder/cli.js investigate "<url>" --deep --compact --out result.json --html map.html

# Score one link only
node scam-finder/cli.js investigate "<url>" --depth 0 --compact

# Leads by theme, no starting link (profiles: node scam-finder/cli.js profiles)
node scam-finder/cli.js hunt jamaica --compact --out leads.json --html leads.html
```

`--compact` prints a JSON digest sized for your context. The full result is in the `--out` file; read parts of it with `get_domain_details`, or with `jq` on the file. Progress is on stderr. A normal run takes 30 seconds to 4 minutes; `--deep` can take 15. Pass a long timeout.

Never paste a suspect URL into a shell unquoted, and never open one in a browser tool to "check" it. The tool fetches pages safely as text.

## Report what it finds

- Lead with the headline and the seed's score, then the reasons. The reasons are the finding; the number only ranks.
- Say plainly that scores are evidence-based estimates, not proof. "Low" means nothing was found, not that a site is safe.
- Keep indicators defanged (`hxxps://example[.]com`) when you quote them.
- Separate what was confirmed by visiting a site (`state: live`, a matched kit) from what is inferred from a shared fingerprint.
- Hunt results are candidates. Many are legitimate sites that matched a search word. Only describe a lead as a likely scam when its own signals support it.
- Mention anything listed under `problems`, and `partial: true`, since both mean the picture is incomplete.
- Offer the HTML map: it is one self-contained file the user can open.
- Never present a site as suspect because of the country it is in or aimed at.

## Go further

- A new kit: add a signature to `scam-finder/data/signatures.js` (a few distinctive markers, plus a search that finds copies), then re-run.
- A brand that is being impersonated but isn't recognised: add it to `scam-finder/data/brands.js` with its real domains.
- More history than 30 days: set `URLSCAN_API_KEY`.
- After editing anything under `scam-finder/`, run `node --test "scam-finder/test/*.test.js"`.

Full documentation: `scam-finder/README.md`.
