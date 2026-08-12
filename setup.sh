#!/usr/bin/env bash
# setup.sh — One-command bootstrap for Snyk Commander
# Handles Node 26 + npm 11 quirks with electron and esbuild install scripts.
set -e

RESET="\033[0m"
BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
CYAN="\033[36m"

info()    { echo -e "${CYAN}${BOLD}[setup]${RESET} $*"; }
success() { echo -e "${GREEN}${BOLD}[setup]${RESET} $*"; }
warn()    { echo -e "${YELLOW}${BOLD}[setup]${RESET} $*"; }
error()   { echo -e "${RED}${BOLD}[setup]${RESET} $*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── 1. Check Node version ────────────────────────────────────────────────────
NODE_MAJOR=$(node -e "console.log(process.versions.node.split('.')[0])")
if [ "$NODE_MAJOR" -lt 18 ]; then
  error "Node.js 18+ is required. Current: $(node --version)"
fi
info "Node $(node --version) / npm $(npm --version)"

# ── 2. Install root dependencies ─────────────────────────────────────────────
info "Installing root dependencies..."
npm install --include=dev --ignore-scripts 2>&1 | grep -v "^npm warn\|^npm notice" || true

# Approve and run install scripts for electron and esbuild
info "Running electron install script..."
node node_modules/electron/install.js 2>/dev/null || true

# If electron path.txt is missing or wrong, extract manually from cache
ELECTRON_PATH_TXT="node_modules/electron/path.txt"
ELECTRON_DIST="node_modules/electron/dist"
ELECTRON_BINARY="$ELECTRON_DIST/Electron.app/Contents/MacOS/Electron"

if [ ! -f "$ELECTRON_BINARY" ]; then
  warn "Electron binary not found after install.js — attempting manual extraction..."

  # Find the cached zip
  CACHE_DIRS=(
    "$HOME/Library/Caches/electron"
    "$HOME/.cache/electron"
    "$HOME/.cache/@electron/get/Cache"
  )
  ELECTRON_ZIP=""
  for dir in "${CACHE_DIRS[@]}"; do
    zip=$(find "$dir" -name "electron-v*.zip" 2>/dev/null | head -1)
    if [ -n "$zip" ]; then
      ELECTRON_ZIP="$zip"
      break
    fi
  done

  if [ -z "$ELECTRON_ZIP" ]; then
    warn "No cached electron zip found. Downloading via npm install-scripts..."
    npm install-scripts approve electron 2>&1 | grep -v "^npm" || true
    node node_modules/electron/install.js 2>&1 || true
  else
    info "Extracting from cache: $ELECTRON_ZIP"
    mkdir -p "$ELECTRON_DIST"
    unzip -o "$ELECTRON_ZIP" -d "$ELECTRON_DIST" > /dev/null 2>&1
  fi
fi

# Write path.txt for the electron module
if [ -f "$ELECTRON_BINARY" ]; then
  printf "Electron.app/Contents/MacOS/Electron" > "$ELECTRON_PATH_TXT"
  success "Electron binary ready: $ELECTRON_BINARY"
else
  warn "Could not locate Electron binary. Run: npm install-scripts approve electron"
fi

# Run esbuild install script
info "Running esbuild install script..."
node node_modules/esbuild/install.js 2>/dev/null || npm install-scripts approve esbuild 2>/dev/null || true

# Verify esbuild works
if node_modules/.bin/esbuild --version > /dev/null 2>&1; then
  success "esbuild $(node_modules/.bin/esbuild --version) ready"
else
  warn "esbuild may not be installed correctly. Trying npm install-scripts approve..."
  npm install-scripts approve esbuild 2>&1 || true
fi

# ── 3. Install renderer dependencies ─────────────────────────────────────────
info "Installing renderer dependencies..."
cd renderer
npm install --include=dev --ignore-scripts 2>&1 | grep -v "^npm warn\|^npm notice" || true
node node_modules/esbuild/install.js 2>/dev/null || npm install-scripts approve esbuild 2>/dev/null || true
cd ..

# ── 4. Build backend ─────────────────────────────────────────────────────────
info "Building TypeScript backend..."
npm run build:backend
success "Backend built → dist/backend/index.js"

# ── 5. Build renderer ────────────────────────────────────────────────────────
info "Building React renderer..."
npm run build:renderer
success "Renderer built → renderer/dist/"

# ── 6. Smoke test ─────────────────────────────────────────────────────────────
info "Running IPC smoke test..."
node -e "
const { invoke } = require('./dist/backend/index');
const path = require('path');
const ctx = {
  appRoot: process.cwd(),
  cacheDir: path.join(process.cwd(), '.snyk_cache'),
  reportsDir: path.join(process.cwd(), 'reports'),
  snykIgnoresDir: path.join(process.cwd(), 'snyk-ignores'),
  snykFilePath: path.join(process.cwd(), '.snyk'),
};
invoke('ping', {}, ctx).then(r => {
  if (r && r.pong) { process.exit(0); }
  else { process.stderr.write('ping returned no pong\n'); process.exit(1); }
}).catch(e => { process.stderr.write(e.message + '\n'); process.exit(1); });
" 2>/dev/null

if [ $? -eq 0 ]; then
  success "IPC smoke test passed"
else
  error "IPC smoke test failed — check dist/backend/index.js exists and is valid"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║   Snyk Commander setup complete! ✓    ║${RESET}"
echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${BOLD}Launch:${RESET}  npm start"
echo -e "  ${BOLD}Dev mode:${RESET} npm run dev"
echo ""
