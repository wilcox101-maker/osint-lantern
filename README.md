# Lantern

Local OSINT workstation. Give it an email, domain, public IP, username, or phone number. It reads public sources, keeps a case file on disk, and writes a Markdown report where every finding names its source.

## One-liner (Windows, no prior installs)

```powershell
irm https://raw.githubusercontent.com/wilcox101-maker/osint-lantern/main/run-lantern.ps1 | iex
```

That clones the repo, downloads a portable Node.js, installs dependencies, and starts the app at http://127.0.0.1:43123.

## Manual

```bash
npm install
npm run dev
```

Copy `.env.example` to `.env` and set `HIBP_API_KEY` if you want breach titles.
