/**
 * src/backend/oauth.ts — Snyk OAuth2 (PKCE) + GitHub Device Flow authentication.
 */

import * as http from 'http';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { SnykOrg } from './snykApi';
import { SnykClient } from './snykApi';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const CONFIG_DIR = path.join(os.homedir(), '.snyk-commander');
const CONFIG_PATH = path.join(CONFIG_DIR, 'config.json');

export interface OAuthConfig {
  snykClientId: string;
  githubClientId: string;
  configPath: string;
}

interface StoredConfig {
  snyk_token?: string;
  github_token?: string;
  snyk_client_id?: string;
  github_client_id?: string;
  ghe_host?: string;            // GitHub Enterprise Server hostname, e.g. "github.mycompany.com"
  included_origins?: string[];  // Project origins to INCLUDE in scans (e.g., "github", "gitlab") - empty = all
  included_types?: string[];    // Project types to INCLUDE in scans (e.g., "npm", "maven") - empty = all
}

function readConfig(): StoredConfig {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')) as StoredConfig;
    }
  } catch {
    // ignore
  }
  return {};
}

function writeConfig(cfg: StoredConfig): void {
  try {
    if (!fs.existsSync(CONFIG_DIR)) fs.mkdirSync(CONFIG_DIR, { recursive: true });
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2), 'utf8');
    try { fs.chmodSync(CONFIG_PATH, 0o600); } catch { /* best-effort */ }
  } catch (err) {
    console.warn('[oauth] Failed to write config:', err);
  }
}

export function getStoredSnykToken(): string | null {
  return readConfig().snyk_token ?? null;
}

export function getStoredGitHubToken(): string | null {
  return readConfig().github_token ?? null;
}

export function getStoredGHEHost(): string | null {
  const cfg = readConfig();
  return cfg.ghe_host ?? process.env['GHE_HOST'] ?? null;
}

export function setGHEHost(host: string): void {
  const cfg = readConfig();
  // Normalise: strip protocol, trailing slashes, and any path components — hostname only
  const normalised = host
    .replace(/^https?:\/\//, '')   // strip protocol
    .replace(/\/.*$/, '')          // strip path (everything after first slash)
    .trim();
  if (!normalised) {
    delete cfg.ghe_host;
  } else {
    cfg.ghe_host = normalised;
  }
  writeConfig(cfg);
}

export function getStoredGitHubClientId(): string | null {
  const cfg = readConfig();
  return cfg.github_client_id ?? process.env['GITHUB_CLIENT_ID'] ?? null;
}

export function setGitHubClientId(clientId: string): void {
  const cfg = readConfig();
  cfg.github_client_id = clientId;
  writeConfig(cfg);
}

export function storeToken(type: 'snyk' | 'github', token: string): void {
  const cfg = readConfig();
  if (type === 'snyk') cfg.snyk_token = token;
  else cfg.github_token = token;
  writeConfig(cfg);
}

export function clearStoredToken(type: 'snyk' | 'github'): void {
  const cfg = readConfig();
  if (type === 'snyk') delete cfg.snyk_token;
  else delete cfg.github_token;
  writeConfig(cfg);
}

export function getIncludedOrigins(): string[] {
  const cfg = readConfig();
  return cfg.included_origins ?? [];
}

export function setIncludedOrigins(origins: string[]): void {
  const cfg = readConfig();
  cfg.included_origins = origins;
  writeConfig(cfg);
}

export function getIncludedTypes(): string[] {
  const cfg = readConfig();
  return cfg.included_types ?? [];
}

export function setIncludedTypes(types: string[]): void {
  const cfg = readConfig();
  cfg.included_types = types;
  writeConfig(cfg);
}

function getSnykClientId(): string {
  const cfg = readConfig();
  return cfg.snyk_client_id ?? process.env['SNYK_CLIENT_ID'] ?? 'snyk-commander';
}

function getGitHubClientId(): string {
  const cfg = readConfig();
  const id = cfg.github_client_id ?? process.env['GITHUB_CLIENT_ID'];
  if (!id) {
    throw new Error(
      'GitHub OAuth Client ID is not configured. ' +
      'Create a free GitHub OAuth App at https://github.com/settings/developers, ' +
      'set the Application name to "Snyk Commander", Homepage URL to "http://localhost", ' +
      'and paste your Client ID into the GitHub card on the auth screen.'
    );
  }
  return id;
}

// ---------------------------------------------------------------------------
// PKCE helpers
// ---------------------------------------------------------------------------

function randomPort(): number {
  return Math.floor(Math.random() * (65535 - 49152 + 1)) + 49152;
}

function generateCodeVerifier(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  const length = 96; // within 43-128
  const bytes = crypto.randomBytes(length);
  return Array.from(bytes).map((b) => chars[b % chars.length]).join('');
}

function generateCodeChallenge(verifier: string): string {
  const hash = crypto.createHash('sha256').update(verifier).digest();
  return hash.toString('base64url');
}

// ---------------------------------------------------------------------------
// Snyk OAuth2 PKCE flow
// ---------------------------------------------------------------------------

export async function startSnykOAuth(onProgress?: (msg: string) => void): Promise<{ token: string; orgs: SnykOrg[] }> {
  const clientId = getSnykClientId();
  const port = randomPort();
  const redirectUri = `http://localhost:${port}/callback`;
  const verifier = generateCodeVerifier();
  const challenge = generateCodeChallenge(verifier);
  const state = crypto.randomBytes(16).toString('hex');

  const authUrl =
    `https://app.snyk.io/oauth2/authorize` +
    `?response_type=code` +
    `&client_id=${encodeURIComponent(clientId)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&code_challenge=${encodeURIComponent(challenge)}` +
    `&code_challenge_method=S256` +
    `&state=${encodeURIComponent(state)}`;

  onProgress?.(`Opening browser for Snyk OAuth...`);

  // Open browser
  try {
    const { shell } = await import('electron');
    await shell.openExternal(authUrl);
  } catch {
    // Fallback for non-electron environments
    const { exec } = await import('child_process');
    const cmd =
      process.platform === 'darwin' ? `open "${authUrl}"`
      : process.platform === 'win32' ? `start "" "${authUrl}"`
      : `xdg-open "${authUrl}"`;
    exec(cmd);
  }

  onProgress?.(`Waiting for OAuth callback on port ${port}...`);

  return new Promise((resolve, reject) => {
    let settled = false;

    const timeout = setTimeout(() => {
      if (settled) return;
      settled = true;
      server.close();
      reject(new Error('OAuth timeout: no callback received within 5 minutes'));
    }, 5 * 60 * 1000);

    const server = http.createServer(async (req, res) => {
      if (!req.url?.startsWith('/callback')) {
        res.writeHead(404);
        res.end('Not found');
        return;
      }

      const urlObj = new URL(req.url, `http://localhost:${port}`);
      const code = urlObj.searchParams.get('code');
      const returnedState = urlObj.searchParams.get('state');
      const error = urlObj.searchParams.get('error');

      if (error) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><body><h2>OAuth error: ' + error + '</h2><p>You may close this tab.</p></body></html>');
        clearTimeout(timeout);
        server.close();
        if (!settled) { settled = true; reject(new Error(`OAuth error: ${error}`)); }
        return;
      }

      if (!code || returnedState !== state) {
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end('<html><body><h2>Bad request</h2></body></html>');
        clearTimeout(timeout);
        server.close();
        if (!settled) { settled = true; reject(new Error('Invalid OAuth callback: missing code or state mismatch')); }
        return;
      }

      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body><h2>Authentication successful!</h2><p>You may close this tab and return to Snyk Commander.</p></body></html>');
      server.close();
      clearTimeout(timeout);

      if (settled) return;
      settled = true;

      try {
        onProgress?.('Exchanging authorization code for token...');
        const token = await exchangeSnykCode(code, verifier, clientId, redirectUri);
        storeToken('snyk', token);
        onProgress?.('Token received. Fetching organizations...');
        const client = new SnykClient(token);
        const orgs = await client.listOrgs();
        resolve({ token, orgs });
      } catch (err) {
        reject(err);
      }
    });

    server.listen(port, '127.0.0.1', () => {
      onProgress?.(`Listening for OAuth callback on http://localhost:${port}/callback`);
    });

    server.on('error', (err) => {
      clearTimeout(timeout);
      if (!settled) { settled = true; reject(err); }
    });
  });
}

async function exchangeSnykCode(
  code: string,
  verifier: string,
  clientId: string,
  redirectUri: string,
): Promise<string> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: clientId,
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier,
  });

  const resp = await fetch('https://app.snyk.io/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    throw new Error(`Token exchange failed (${resp.status}): ${text}`);
  }

  const data = (await resp.json()) as { access_token?: string; token?: string };
  const token = data.access_token ?? data.token;
  if (!token) throw new Error('No token in OAuth response');
  return token;
}

// ---------------------------------------------------------------------------
// GitHub Device Flow
// ---------------------------------------------------------------------------

export async function startGitHubDeviceFlow(): Promise<{
  device_code: string;
  user_code: string;
  verification_uri: string;
  expires_in: number;
  interval: number;
}> {
  const clientId = getGitHubClientId();

  const resp = await fetch('https://github.com/login/device/code', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: new URLSearchParams({ client_id: clientId, scope: 'repo' }).toString(),
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    // GitHub returns 404 {"error":"Not Found"} for unregistered/invalid client IDs
    if (resp.status === 404 || text.includes('Not Found')) {
      throw new Error(
        `GitHub OAuth App not found. Your Client ID "${clientId}" is not a registered GitHub OAuth App. ` +
        `Go to github.com/settings/developers → OAuth Apps → New OAuth App to register one, ` +
        `then paste the Client ID into the GitHub card on the auth screen.`
      );
    }
    throw new Error(`GitHub device flow initiation failed (${resp.status}): ${text}`);
  }

  const data = (await resp.json()) as {
    device_code: string;
    user_code: string;
    verification_uri: string;
    expires_in: number;
    interval: number;
  };

  if (!data.device_code || !data.user_code) {
    throw new Error('Invalid response from GitHub device flow endpoint');
  }

  return data;
}

export async function pollGitHubToken(
  device_code: string,
  interval: number,
  onProgress?: (msg: string) => void,
): Promise<{ token: string }> {
  const clientId = getGitHubClientId();
  const pollIntervalMs = Math.max(interval * 1000, 5000);
  const deadline = Date.now() + 15 * 60 * 1000; // 15 min max

  onProgress?.('Waiting for GitHub authorization...');

  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, pollIntervalMs));

    const resp = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: new URLSearchParams({
        client_id: clientId,
        device_code,
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      }).toString(),
    });

    if (!resp.ok) {
      onProgress?.(`Poll error: HTTP ${resp.status}, retrying...`);
      continue;
    }

    const data = (await resp.json()) as {
      access_token?: string;
      error?: string;
      error_description?: string;
      interval?: number;
    };

    if (data.access_token) {
      const token = data.access_token;
      storeToken('github', token);
      onProgress?.('GitHub token received and stored.');
      return { token };
    }

    if (data.error === 'authorization_pending') {
      onProgress?.('Authorization pending, still waiting...');
      continue;
    }
    if (data.error === 'slow_down') {
      onProgress?.('Slowing down poll rate...');
      await new Promise((r) => setTimeout(r, (data.interval ?? 5) * 1000));
      continue;
    }
    if (data.error === 'expired_token') {
      throw new Error('GitHub device code expired. Please restart the flow.');
    }
    if (data.error === 'access_denied') {
      throw new Error('GitHub authorization was denied by the user.');
    }
    if (data.error) {
      throw new Error(`GitHub OAuth error: ${data.error} - ${data.error_description ?? ''}`);
    }
  }

  throw new Error('GitHub device flow timed out after 15 minutes');
}
