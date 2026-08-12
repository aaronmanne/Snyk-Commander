# Snyk Commander v3.0

A full-featured **Electron + React desktop app** for managing Snyk vulnerabilities at scale — built entirely in **TypeScript and Node.js**. No Python. No external runtimes.

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  Electron App                    │
│                                                 │
│  ┌──────────────────────┐  ┌──────────────────┐ │
│  │  Renderer Process    │  │  Main Process    │ │
│  │                      │  │                  │ │
│  │  React 18            │◄─►  electron/       │ │
│  │  TypeScript          │  │  main.js         │ │
│  │  Vite 6              │  │                  │ │
│  │  Tailwind CSS 3      │  │  TypeScript      │ │
│  └──────────────────────┘  │  Backend         │ │
│     contextBridge IPC      │  dist/backend/   │ │
│                            │  index.js        │ │
│                            └──────────────────┘ │
└─────────────────────────────────────────────────┘
         │
         ▼
   https://api.snyk.io  /  http://localhost:11434 (Ollama, optional)
```

**No Python. No subprocess. No IPC bridge.**
The TypeScript backend runs directly in the Electron main process.

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| **Node.js** | v18+ (v20+ recommended) | [nodejs.org](https://nodejs.org) |
| **npm** | v8+ | Comes with Node |
| **Snyk API token** | — | [app.snyk.io/account](https://app.snyk.io/account) |
| **Ollama** _(optional)_ | any | For AI reachability analysis |

> **Note for npm v11+ users:** npm v11 requires `--include=dev` to install devDependencies and uses a new `allowScripts` security model that blocks install scripts (electron, esbuild) until approved. The `setup.sh` script handles all of this automatically.

---

## Quick Start — Run `setup.sh` (recommended)

```bash
git clone <repo-url>
cd Snyk-Commander
./setup.sh
```

Then launch:

```bash
npm start
```

That's it. `setup.sh` handles:
- Installing all root and renderer dependencies
- Approving and running electron + esbuild install scripts
- Extracting the Electron binary from cache if needed
- Building the TypeScript backend (esbuild → `dist/backend/index.js`)
- Building the React renderer (Vite → `renderer/dist/`)
- Running an IPC smoke test to confirm everything works

---

## Manual Setup (step by step)

If you prefer to run steps individually:

### 1. Install root dependencies

```bash
npm install --include=dev
```

If on **npm v11**, approve the install scripts when prompted:

```bash
npm install-scripts approve electron
npm install-scripts approve esbuild
```

If electron doesn't install correctly (common on Node 26 + Apple Silicon), run:

```bash
node node_modules/electron/install.js
# If that fails, setup.sh handles the manual extraction — just run ./setup.sh
```

### 2. Install renderer dependencies

```bash
cd renderer
npm install --include=dev
npm install-scripts approve esbuild   # if on npm v11
cd ..
```

### 3. Build

```bash
# Build TypeScript backend (~20ms via esbuild)
npm run build:backend

# Build React renderer (~3s via Vite)
npm run build:renderer
```

Or build both at once:

```bash
npm run build
```

### 4. Launch

```bash
npm start
```

---

## Development Mode

Start all three services with hot-reload:

```bash
npm run dev
```

This runs concurrently:
- **Backend watcher** — esbuild rebuilds `dist/backend/index.js` on save (~20ms)
- **Renderer dev server** — Vite HMR at `http://localhost:5173`
- **Electron** — loads from Vite dev server, opens DevTools

Or run individually:

```bash
# Terminal 1
npm run dev:backend

# Terminal 2
npm run dev:renderer

# Terminal 3 (after the above are running)
NODE_ENV=development npx electron .
```

---

## All npm Scripts

| Script | What it does |
|---|---|
| `npm run build` | Build backend + renderer |
| `npm run build:backend` | Compile TypeScript → `dist/backend/index.js` (esbuild) |
| `npm run build:renderer` | Compile React → `renderer/dist/` (Vite) |
| `npm start` | Launch in production mode |
| `npm run dev` | Launch everything with hot-reload |
| `npm run dev:backend` | Watch-mode backend build |
| `npm run dev:renderer` | Vite dev server |
| `npm run dist` | Build + package with electron-builder |
| `npm run pack` | Build + package without installer (faster) |

---

## Project Structure

```
Snyk-Commander/
├── setup.sh               ← One-command setup script (run this first)
│
├── electron/
│   ├── main.js            ← Electron main process — window, IPC, CSP, native dialogs
│   └── preload.js         ← contextBridge — exposes window.snykAPI to renderer
│
├── src/
│   └── backend/           ← TypeScript backend (compiled to dist/backend/)
│       ├── index.ts        ← IPC router — invoke() + stream() entry points
│       ├── snykApi.ts      ← Snyk REST + v1 API client (native fetch, semaphore, retry)
│       ├── cache.ts        ← JSON file cache management
│       ├── auth.ts         ← Token verification, org listing, cache summary
│       ├── scanner.ts      ← Org scanning (30 parallel project fetches)
│       ├── ignores.ts      ← Ignore analysis, Snyk API apply, .snyk file generation
│       ├── fixPr.ts        ← Fix PR triggering via Snyk HTTP endpoint
│       ├── report.ts       ← Markdown + CSV report generation
│       ├── reachability.ts ← Static codebase analysis + Ollama LLM integration
│       └── cache_handler.ts
│
├── renderer/              ← React + TypeScript frontend
│   ├── src/
│   │   ├── views/          ← 10 application views
│   │   ├── components/     ← Reusable UI components
│   │   ├── context/        ← Global app state (AppContext)
│   │   ├── api.ts          ← Typed window.snykAPI wrapper
│   │   └── types.ts        ← TypeScript interfaces
│   └── dist/               ← Built output (loaded by Electron in production)
│
├── dist/
│   └── backend/
│       └── index.js        ← Bundled backend (esbuild output, ~72 KB)
│
├── .snyk_cache/            ← Scan result cache (auto-created, gitignored)
├── reports/                ← Generated vulnerability reports (gitignored)
└── snyk-ignores/           ← Generated .snyk policy files (gitignored)
```

---

## Features

### 🔐 Authentication
- Enter Snyk API token in the GUI — "Remember token" persists across sessions
- Resume from cached scan results with one click

### 📊 Dashboard
- Org-wide stats: total vulns, critical count, fixable count, projects scanned
- SVG donut chart (no external chart library)
- Top 10 most vulnerable projects
- One-click rescan

### 🔍 Vulnerability Browser
- Filterable (severity, fixability, keyword), sortable, paginated table
- Expandable rows: full CVSS, CWE, affected versions, fix path
- "Run Reachability Analysis" button on every row

### 🚫 Ignore Manager
**API Ignores** — risk score slider → preview (ignore/update/unignore) → apply via Snyk API with streaming progress  
**Generate .snyk Files** — write per-project policy files to `snyk-ignores/`

### 🔧 Fix PRs
Trigger fix PRs per-project or in bulk via Snyk's HTTP endpoint

### 📋 Reports
Generate Markdown + CSV reports in three modes: All / Non-fixable / Non-fixable above score

### 🔬 Reachability Analysis
**"Is this vulnerable package actually called in my code?"**
1. Select a vulnerability → choose your codebase directory
2. Scans imports, require statements, and function calls across Python, JS/TS, Java, Go, Ruby, PHP, C#
3. Optional: local Ollama LLM reasoning (default model: `llama3`)
4. Verdict: **LIKELY REACHABLE** 🔴 / **LIKELY NOT REACHABLE** 🟢 / **INCONCLUSIVE** 🟡

---

## Tech Stack

| Layer | Technology | Version |
|---|---|---|
| Desktop shell | Electron | 32 |
| Frontend framework | React | 18 |
| Frontend language | TypeScript | 5.6 |
| Frontend build | Vite | 6 |
| Styling | Tailwind CSS | 3 |
| Icons | Lucide React | — |
| Backend language | TypeScript | 5.6 |
| Backend bundler | esbuild | 0.24 |
| HTTP client | Native `fetch` | Node 18 built-in |
| YAML | js-yaml | 4 |
| Snyk API | REST v1 + REST 2024-10-15 | — |
| AI analysis | Ollama (local, optional) | any |

---

## Troubleshooting

### `sh: esbuild: command not found` / `sh: tsc: command not found`
npm scripts must use `npx` to run local binaries. All scripts in this repo already use `npx`. If you see this error, make sure you're using the scripts from this repo and not manually typing the command without `npx`.

### Electron fails to install / `path.txt missing`
This happens on Node 26 + npm 11 (Apple Silicon especially). Run `./setup.sh` — it handles the manual binary extraction automatically.

### `npm install` shows "up to date, audited 1 package"
On npm v11, devDependencies are not installed by default. Always use:
```bash
npm install --include=dev
```

### `allow-scripts` warnings
npm v11 requires explicit approval for packages with install scripts. Run:
```bash
npm install-scripts approve electron
npm install-scripts approve esbuild
```
Or use `./setup.sh` which does this automatically.

### Blank white window / renderer not loading
The renderer must be built before launching in production mode:
```bash
npm run build
npm start
```
For dev mode with hot-reload use `npm run dev` instead.
