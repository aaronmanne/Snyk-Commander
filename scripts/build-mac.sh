#!/usr/bin/env bash
#
# scripts/build-mac.sh — Build a distributable macOS release of Snyk Commander.
#
# Produces a universal (Apple Silicon + Intel) .dmg and .zip under dist-electron/
# by default. Handles: dependency checks, a clean build of the backend +
# renderer, optional icon generation, and (unless code-signing env vars are
# present) building unsigned/ad-hoc for local distribution/testing.
#
# Usage:
#   ./scripts/build-mac.sh                # universal dmg + zip (default)
#   ./scripts/build-mac.sh --arch arm64   # Apple Silicon only
#   ./scripts/build-mac.sh --arch x64     # Intel only
#   ./scripts/build-mac.sh --dir          # unpacked .app only (fast, for local testing)
#   ./scripts/build-mac.sh --clean        # wipe dist-electron/ first
#   ./scripts/build-mac.sh --open         # reveal output folder in Finder when done
#
# Code signing / notarization (optional):
#   Set the standard electron-builder env vars before running this script to
#   produce a signed + notarized build instead of an ad-hoc local one:
#     CSC_LINK, CSC_KEY_PASSWORD           — Developer ID Application certificate (.p12)
#     APPLE_ID, APPLE_APP_SPECIFIC_PASSWORD, APPLE_TEAM_ID  — notarization
#
set -euo pipefail

RESET="\033[0m"
BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
CYAN="\033[36m"

info()    { echo -e "${CYAN}${BOLD}[release]${RESET} $*"; }
success() { echo -e "${GREEN}${BOLD}[release]${RESET} $*"; }
warn()    { echo -e "${YELLOW}${BOLD}[release]${RESET} $*"; }
error()   { echo -e "${RED}${BOLD}[release]${RESET} $*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

# ── 0. Platform guard ────────────────────────────────────────────────────────
if [[ "$(uname -s)" != "Darwin" ]]; then
  error "This script builds a macOS app and must be run on macOS."
fi

# ── 1. Parse arguments ───────────────────────────────────────────────────────
ARCH="universal"
DIR_ONLY=false
DO_CLEAN=false
DO_OPEN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --arch)
      ARCH="${2:-universal}"
      shift 2
      ;;
    --arch=*)
      ARCH="${1#*=}"
      shift
      ;;
    --dir)
      DIR_ONLY=true
      shift
      ;;
    --clean)
      DO_CLEAN=true
      shift
      ;;
    --open)
      DO_OPEN=true
      shift
      ;;
    -h|--help)
      grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      error "Unknown argument: $1 (use --help for usage)"
      ;;
  esac
done

case "$ARCH" in
  universal|arm64|x64) ;;
  *) error "Invalid --arch '$ARCH' (expected universal, arm64, or x64)" ;;
esac

# ── 2. Node / dependency checks ──────────────────────────────────────────────
if ! command -v node >/dev/null 2>&1; then
  error "Node.js is required. Install Node 18+ and re-run."
fi

NODE_MAJOR=$(node -e "console.log(process.versions.node.split('.')[0])")
if [ "$NODE_MAJOR" -lt 18 ]; then
  error "Node.js 18+ is required. Current: $(node --version)"
fi
info "Node $(node --version) / npm $(npm --version)"

if [ ! -d "node_modules" ] || [ ! -d "renderer/node_modules" ]; then
  warn "Dependencies not installed — running ./setup.sh first..."
  ./setup.sh
fi

# ── 3. Optional: generate icon.icns from build/icon.png if present ──────────
ICONSET_SRC="build/icon.png"
ICON_ICNS="build/icon.icns"

if [ -f "$ICONSET_SRC" ] && [ ! -f "$ICON_ICNS" ]; then
  info "Generating build/icon.icns from build/icon.png..."
  ICONSET_DIR="$(mktemp -d)/icon.iconset"
  mkdir -p "$ICONSET_DIR"
  for size in 16 32 64 128 256 512; do
    sips -z "$size" "$size" "$ICONSET_SRC" --out "$ICONSET_DIR/icon_${size}x${size}.png" >/dev/null
    double=$((size * 2))
    sips -z "$double" "$double" "$ICONSET_SRC" --out "$ICONSET_DIR/icon_${size}x${size}@2x.png" >/dev/null
  done
  iconutil -c icns "$ICONSET_DIR" -o "$ICON_ICNS"
  rm -rf "$(dirname "$ICONSET_DIR")"
  success "Icon generated → $ICON_ICNS"
elif [ -f "$ICON_ICNS" ]; then
  info "Using existing icon → $ICON_ICNS"
else
  warn "No build/icon.png or build/icon.icns found — the app will ship with Electron's default icon."
  warn "To brand the app, drop a 1024x1024 build/icon.png in the repo and re-run this script."
fi

# ── 4. Code signing status ───────────────────────────────────────────────────
if [ -n "${CSC_LINK:-}" ] || [ -n "${CSC_NAME:-}" ]; then
  info "Code signing credentials detected — building a signed release."
  if [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_APP_SPECIFIC_PASSWORD:-}" ]; then
    info "Apple notarization credentials detected — build will be notarized."
  else
    warn "No notarization credentials (APPLE_ID / APPLE_APP_SPECIFIC_PASSWORD / APPLE_TEAM_ID) set."
    warn "The app will be signed but NOT notarized — Gatekeeper may still warn on first launch."
  fi
else
  warn "No code signing credentials found (CSC_LINK / CSC_NAME env vars unset)."
  warn "Building an ad-hoc, unsigned release for local distribution/testing."
  warn "Recipients will need to right-click → Open the first time (Gatekeeper)."
  export CSC_IDENTITY_AUTO_DISCOVERY=false
fi

# ── 5. Clean previous output (optional) ──────────────────────────────────────
if [ "$DO_CLEAN" = true ] && [ -d "dist-electron" ]; then
  info "Cleaning dist-electron/..."
  rm -rf dist-electron
fi

# ── 6. Build backend + renderer ──────────────────────────────────────────────
info "Building backend..."
npm run build:backend
success "Backend built → dist/backend/index.js"

info "Building renderer..."
npm run build:renderer
success "Renderer built → renderer/dist/"

# ── 7. Package with electron-builder ─────────────────────────────────────────
BUILDER_ARGS=(--mac)

if [ "$DIR_ONLY" = true ]; then
  info "Packaging unpacked .app only (--dir, no dmg/zip)..."
  BUILDER_ARGS+=(--dir)
else
  case "$ARCH" in
    universal) BUILDER_ARGS+=(--universal) ;;
    arm64)     BUILDER_ARGS+=(--arm64) ;;
    x64)       BUILDER_ARGS+=(--x64) ;;
  esac
  info "Packaging macOS release ($ARCH)..."
fi

npx electron-builder "${BUILDER_ARGS[@]}"

# ── 8. Report results ─────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║   Snyk Commander macOS build complete! ✓  ║${RESET}"
echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════╝${RESET}"
echo ""

if [ -d "dist-electron" ]; then
  info "Artifacts in dist-electron/:"
  find dist-electron -maxdepth 1 \( -name "*.dmg" -o -name "*.zip" -o -name "*.app" \) -exec ls -lh {} \; 2>/dev/null \
    | awk '{printf "  %-8s %s\n", $5, $NF}'
fi

if [ "$DO_OPEN" = true ]; then
  open "dist-electron" 2>/dev/null || true
fi

echo ""
echo -e "  ${BOLD}Next steps:${RESET}"
echo -e "  • Test the app:      open \"dist-electron/mac-universal/Snyk Commander.app\" (path varies by arch)"
echo -e "  • Distribute:        share the .dmg (or .zip) from dist-electron/"
echo -e "  • Unsigned build?    recipients must right-click → Open on first launch"
echo ""
