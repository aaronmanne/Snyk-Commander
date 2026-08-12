'use strict';

/**
 * electron/main.js — Electron main process for Snyk Commander.
 *
 * Responsibilities:
 *   1. Create the BrowserWindow (1280×900)
 *   2. Load React app (dev: http://localhost:5173 | prod: renderer/dist/index.html)
 *   3. Call the TypeScript backend directly (compiled to dist/backend/index.js)
 *   4. Register ipcMain handlers that call backend functions
 *   5. Set Content Security Policy
 *   6. Handle app lifecycle
 */

const {
  app,
  BrowserWindow,
  ipcMain,
  session,
  dialog,
  shell,
} = require('electron');
const path = require('path');

// ── Constants ──────────────────────────────────────────────────────────────
const IS_DEV = process.env.NODE_ENV === 'development';
const APP_ROOT = path.join(__dirname, '..');
const RENDERER_DEV_URL = 'http://localhost:5173';
const RENDERER_PROD_PATH = path.join(APP_ROOT, 'renderer', 'dist', 'index.html');

// ── Backend context ────────────────────────────────────────────────────────
const ctx = {
  appRoot: APP_ROOT,
  cacheDir: path.join(APP_ROOT, '.snyk_cache'),
  reportsDir: path.join(APP_ROOT, 'reports'),
  snykIgnoresDir: path.join(APP_ROOT, 'snyk-ignores'),
  snykFilePath: path.join(APP_ROOT, '.snyk'),
};

// ── Load backend ───────────────────────────────────────────────────────────
let backend = null;

function loadBackend() {
  const backendPath = path.join(APP_ROOT, 'dist', 'backend', 'index.js');
  try {
    backend = require(backendPath);
    console.log('[main] TypeScript backend loaded from', backendPath);
  } catch (err) {
    console.error('[main] Failed to load TypeScript backend:', err.message);
    console.error('[main] Run "npm run build:backend" first.');
  }
}

// ── Globals ────────────────────────────────────────────────────────────────
let mainWindow = null;

// ── Window factory ─────────────────────────────────────────────────────────
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 900,
    title: 'Snyk Commander',
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  mainWindow.on('page-title-updated', (event) => {
    event.preventDefault();
  });

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    if (IS_DEV) {
      mainWindow.webContents.openDevTools();
    }
  });

  if (IS_DEV) {
    mainWindow.loadURL(RENDERER_DEV_URL).catch((err) => {
      console.error('[main] Failed to load dev URL:', err);
    });
  } else {
    mainWindow.loadFile(RENDERER_PROD_PATH).catch((err) => {
      console.error('[main] Failed to load renderer:', err);
    });
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// ── Content Security Policy ────────────────────────────────────────────────
function setupCSP() {
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    const devSrc = IS_DEV ? "'unsafe-eval' http://localhost:5173 ws://localhost:5173" : '';
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [
          `default-src 'self' ${devSrc}; ` +
          `script-src 'self' ${devSrc}; ` +
          `style-src 'self' 'unsafe-inline' ${devSrc}; ` +
          `img-src 'self' data: https:; ` +
          `connect-src 'self' https://api.snyk.io https://app.snyk.io http://localhost:11434 ${devSrc}; ` +
          `font-src 'self' data:;`,
        ],
      },
    });
  });
}

// ── IPC Handlers ───────────────────────────────────────────────────────────

/**
 * snyk:invoke — Single-shot request forwarded to TypeScript backend.
 */
ipcMain.handle('snyk:invoke', async (_event, { method, params }) => {
  if (!backend) {
    throw new Error('Backend is not loaded. Run "npm run build:backend" first.');
  }
  return backend.invoke(method, params || {}, ctx);
});

/**
 * snyk:stream — Streaming request forwarded to TypeScript backend.
 * Progress events are sent back to the renderer via event.sender.send(streamChannel, ...).
 */
ipcMain.handle('snyk:stream', async (event, { method, params, streamChannel }) => {
  if (!backend) {
    throw new Error('Backend is not loaded. Run "npm run build:backend" first.');
  }

  return backend.stream(method, params || {}, ctx, (eventName, data) => {
    if (!event.sender.isDestroyed()) {
      event.sender.send(streamChannel, { event: eventName, data });
    }
  });
});

/**
 * dialog.openFolder — Opens a native folder picker dialog.
 */
ipcMain.handle('dialog:openFolder', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory'],
    title: 'Select Codebase Directory',
  });
  if (result.canceled || result.filePaths.length === 0) return null;
  return result.filePaths[0];
});

/**
 * shell.openPath — Open a file/folder in the OS default app.
 */
ipcMain.handle('shell:openPath', async (_event, filePath) => {
  await shell.openPath(filePath);
  return { ok: true };
});

// ── App lifecycle ──────────────────────────────────────────────────────────
app.whenReady().then(async () => {
  loadBackend();
  setupCSP();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// Prevent navigation to external URLs from the renderer
app.on('web-contents-created', (_event, contents) => {
  contents.on('will-navigate', (navigationEvent, url) => {
    const allowedOrigins = IS_DEV
      ? ['http://localhost:5173']
      : [`file://${path.dirname(RENDERER_PROD_PATH)}`];

    const isAllowed = allowedOrigins.some((origin) => url.startsWith(origin))
      || url.startsWith('file://');

    if (!isAllowed) {
      console.warn(`[main] Blocked navigation to: ${url}`);
      navigationEvent.preventDefault();
    }
  });

  contents.setWindowOpenHandler(({ url }) => {
    const { shell: shellModule } = require('electron');
    shellModule.openExternal(url).catch(() => {});
    return { action: 'deny' };
  });
});
