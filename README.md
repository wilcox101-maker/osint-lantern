# Lantern

Local OSINT workstation. Give it an email, domain, public IP, username, or phone number. It reads public sources, keeps a case file on disk, and writes a Markdown report where every finding names its source.

The module list follows a passive read of the public pentester.com and OSINT Pilot pages with [REA](https://github.com/morluto/rea) 6.7.0 on 21 Oct 2026 (`list-browser-targets` and `inspect-web-page`, accessibility text only). Lantern does not call pentester.com, and it does not include the exploitation, national-ID, or password-retrieval parts of that product.

## Quick start (Windows, no prior installs)

```powershell
irm https://raw.githubusercontent.com/wilcox101-maker/osint-lantern/main/run-lantern.ps1 | iex
```

That clones the repo, downloads a portable Node.js, installs dependencies, and starts the app at http://127.0.0.1:43123.

## Manual

```bash
npm install
npm run dev
```

Open [http://127.0.0.1:43123](http://127.0.0.1:43123).

Copy `.env.example` to `.env` and set `HIBP_API_KEY` if you want breach titles. Without it, that module is skipped and the rest of an email investigation still runs.

Cases are written to `data/investigations.json`. That file is gitignored.

## What a run collects

| Target | Modules |
| --- | --- |
| Email | Mailbox shape, DNS, SPF/DMARC, RDAP, certificate names, one HTTPS header check, robots.txt and security.txt, Gravatar, breach titles if `HIBP_API_KEY` is set |
| Domain | DNS, SPF/DMARC, RDAP, certificate names, headers, robots.txt, security.txt |
| IP | Reverse DNS, RDAP, coarse location from ipwho.is |
| Username | A fixed set of public profile URLs |
| Phone | Format and region from libphonenumber. No carrier lookup |

An optional password field uses the Pwned Passwords range API. The password is hashed in this process, five characters of the SHA-1 are sent, and the password is not stored.

Private, loopback, and link-local addresses are refused. Fetches stay on ports 80 and 443, follow a few redirects, and re-check the host at each hop.

## Checks

```bash
npm test
npm run lint
```

## License

MIT
