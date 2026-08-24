/**
 * src/backend/github.ts — GitHub repo resolution and cloning.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawn } from 'child_process';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface GitHubRepo {
  owner: string;
  name: string;
  fullName: string;
  cloneUrl: string;
  sshUrl: string;
  defaultBranch: string;
}

// ---------------------------------------------------------------------------
// Extraction helpers
// ---------------------------------------------------------------------------

/**
 * Extract GitHub owner/repo from a Snyk project name or origin string.
 *
 * Handles patterns like:
 *   - github.com/owner/repo
 *   - owner/repo(branch):path/manifest.json
 *   - owner/repo:path
 *   - owner/repo
 */
export function extractRepoFromProject(
  projectName: string,
  origin: string,
): { owner: string; repo: string } | null {
  // Try origin first (most reliable)
  const sources = [origin, projectName];

  for (const src of sources) {
    if (!src) continue;

    // github.com/owner/repo[...]
    const githubDotCom = src.match(/github\.com\/([^/\s]+)\/([^/:()\s]+)/i);
    if (githubDotCom) {
      return { owner: githubDotCom[1], repo: stripSuffix(githubDotCom[2]) };
    }

    // owner/repo(branch):path  or  owner/repo:path  or  owner/repo
    const simple = src.match(/^([^/\s]+)\/([^/(:\s]+)/);
    if (simple) {
      return { owner: simple[1], repo: stripSuffix(simple[2]) };
    }
  }

  return null;
}

function stripSuffix(s: string): string {
  return s.replace(/\.git$/, '').replace(/[():#\s].*$/, '');
}

/**
 * Extract branch from patterns like: name(branch):path
 */
export function extractBranchFromProject(projectName: string): string | null {
  const m = projectName.match(/\(([^)]+)\)/);
  return m ? m[1] : null;
}

// ---------------------------------------------------------------------------
// GitHub API
// ---------------------------------------------------------------------------

const GITHUB_API = 'https://api.github.com';
const RATE_LIMIT_RETRY_DELAY = 60_000;

async function githubApiFetch(
  url: string,
  token: string | null,
  retries = 3,
): Promise<Response> {
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'snyk-commander',
  };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  for (let attempt = 0; attempt < retries; attempt++) {
    const resp = await fetch(url, { headers });

    // Only retry on 429 (rate limit) and 500+ (server errors)
    // 403 can be OAuth App restriction or SAML — return immediately so caller can inspect the body
    if (resp.status === 429) {
      const retryAfterHeader = resp.headers.get('retry-after') ?? resp.headers.get('x-ratelimit-reset');
      let waitMs = RATE_LIMIT_RETRY_DELAY;
      if (retryAfterHeader) {
        const val = parseInt(retryAfterHeader, 10);
        waitMs = retryAfterHeader.length > 5
          ? Math.max(0, val * 1000 - Date.now()) + 1000
          : val * 1000 + 1000;
      }
      if (attempt < retries - 1) {
        await new Promise((r) => setTimeout(r, waitMs));
        continue;
      }
    }

    return resp;
  }

  throw new Error('Max retries exceeded for GitHub API request');
}

export async function getRepoInfo(
  owner: string,
  repo: string,
  githubToken: string | null,
): Promise<GitHubRepo> {
  const url = `${GITHUB_API}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
  const resp = await githubApiFetch(url, githubToken);

  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    // Parse JSON for richer error messages
    let message = '';
    try { message = (JSON.parse(text) as { message?: string }).message ?? ''; } catch { message = text; }

    if (resp.status === 404) throw new Error(`GitHub repo not found: ${owner}/${repo}`);
    if (resp.status === 401) throw new Error('GitHub authentication failed. Check your token in Settings.');

    // OAuth App access restriction — the org blocks OAuth App tokens (gho_)
    if (resp.status === 403 && message.includes('OAuth App access restrictions')) {
      throw new Error(
        `OAUTH_APP_RESTRICTED:${owner}`
      );
    }
    // SAML/SSO enforcement
    if (resp.status === 403 && (message.includes('SAML') || message.includes('SSO') || message.includes('single sign-on'))) {
      throw new Error(
        `SSO_REQUIRED:${owner}`
      );
    }

    throw new Error(`GitHub API error (${resp.status}): ${message.slice(0, 200)}`);
  }

  const data = (await resp.json()) as {
    owner: { login: string };
    name: string;
    full_name: string;
    clone_url: string;
    ssh_url: string;
    default_branch: string;
  };

  return {
    owner: data.owner.login,
    name: data.name,
    fullName: data.full_name,
    cloneUrl: data.clone_url,
    sshUrl: data.ssh_url,
    defaultBranch: data.default_branch,
  };
}

/**
 * Quick pre-flight check before attempting a clone.
 * Returns null if OK, or a human-readable error string if access is blocked.
 */
export async function checkRepoAccess(
  owner: string,
  repo: string,
  githubToken: string | null,
): Promise<string | null> {
  const url = `${GITHUB_API}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
  try {
    const resp = await githubApiFetch(url, githubToken);
    if (resp.ok) return null; // access fine

    const text = await resp.text().catch(() => '');
    let message = '';
    try { message = (JSON.parse(text) as { message?: string }).message ?? ''; } catch { message = text; }

    if (resp.status === 403 && message.includes('OAuth App access restrictions')) {
      return (
        `The '${owner}' organization has blocked OAuth App tokens.\n\n` +
        `Your current token (gho_...) is an OAuth App token from the Device Flow — ` +
        `this org disallows them.\n\n` +
        `Fix: Create a Fine-Grained Personal Access Token at ` +
        `https://github.com/settings/personal-access-tokens/new\n` +
        `  • Resource owner: ${owner}\n` +
        `  • Repository permissions → Contents: Read-only\n` +
        `  • All other permissions: No access\n\n` +
        `Then paste the token (github_pat_...) into Settings → GitHub → Personal Access Token.\n\n` +
        `If your org hasn't approved fine-grained PATs yet, use a Classic PAT (ghp_...) at ` +
        `https://github.com/settings/tokens with "repo" scope + Configure SSO for the '${owner}' org.`
      );
    }
    if (resp.status === 403 && (message.includes('SAML') || message.includes('SSO'))) {
      return (
        `SSO authorization required for the '${owner}' organization.\n\n` +
        `Go to https://github.com/settings/tokens, find your token, click "Configure SSO", ` +
        `and authorize it for the '${owner}' org.`
      );
    }
    if (resp.status === 404) {
      return `Repository ${owner}/${repo} not found. Check that the repo exists and your token has 'repo' scope.`;
    }
    if (resp.status === 401) {
      return `GitHub authentication failed. Your token may be expired or revoked. Re-connect in Settings.`;
    }
    return `GitHub API error (${resp.status}): ${message.slice(0, 200)}`;
  } catch {
    // Network error or no token — let the clone attempt proceed and fail naturally
    return null;
  }
}

// ---------------------------------------------------------------------------
// Git operations
// ---------------------------------------------------------------------------

export function repoLocalPath(owner: string, repo: string): string {
  return path.join(os.homedir(), '.snyk-commander', 'repos', owner, repo);
}

function runGit(
  args: string[],
  cwd: string | undefined,
  onProgress: (msg: string) => void,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn('git', args, {
      cwd,
      env: { ...process.env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    child.stdout.on('data', (chunk: Buffer) => {
      const lines = chunk.toString('utf8').split('\n');
      for (const line of lines) {
        if (line.trim()) onProgress(`[git] ${line.trim()}`);
      }
    });

    child.stderr.on('data', (chunk: Buffer) => {
      const lines = chunk.toString('utf8').split('\n');
      for (const line of lines) {
        if (line.trim()) onProgress(`[git] ${line.trim()}`);
      }
    });

    child.on('error', (err) => {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        reject(new Error('git is required but not found in PATH'));
      } else {
        reject(err);
      }
    });

    child.on('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`git exited with code ${code}`));
    });
  });
}

export async function cloneOrUpdateRepo(
  repo: GitHubRepo,
  githubToken: string | null,
  onProgress: (msg: string) => void,
): Promise<string> {
  return cloneOrUpdateRepoDirect(
    repo.owner,
    repo.name,
    repo.defaultBranch,
    githubToken,
    null,
    onProgress,
  );
}

/**
 * Clone or update a repo without requiring a prior GitHub API call.
 * Supports github.com and GitHub Enterprise Server (GHE).
 *
 * @param gheHost  Optional GHE host (e.g. "github.mycompany.com"). Defaults to "github.com".
 */
export async function cloneOrUpdateRepoDirect(
  owner: string,
  repoName: string,
  branch: string | null,
  githubToken: string | null,
  gheHost: string | null,
  onProgress: (msg: string) => void,
): Promise<string> {
  const localPath = repoLocalPath(owner, repoName);
  const parentDir = path.dirname(localPath);

  if (!fs.existsSync(parentDir)) {
    fs.mkdirSync(parentDir, { recursive: true });
  }

  const host = gheHost ?? 'github.com';

  // Build authenticated HTTPS clone URL
  const cloneUrl = githubToken
    ? `https://${encodeURIComponent(githubToken)}@${host}/${owner}/${repoName}.git`
    : `https://${host}/${owner}/${repoName}.git`;

  const alreadyCloned =
    fs.existsSync(localPath) && fs.existsSync(path.join(localPath, '.git'));

  if (alreadyCloned) {
    onProgress(`Updating existing repo at ${localPath}...`);
    try {
      if (githubToken) {
        await runGit(
          ['-C', localPath, 'remote', 'set-url', 'origin', cloneUrl],
          undefined,
          onProgress,
        );
      }
      await runGit(['-C', localPath, 'pull', '--ff-only'], undefined, onProgress);
      onProgress(`Repository updated: ${localPath}`);
    } catch (err) {
      onProgress(`Pull failed, trying fresh clone: ${String(err)}`);
      fs.rmSync(localPath, { recursive: true, force: true });
      await doClone(cloneUrl, branch, localPath, onProgress);
    }
  } else {
    await doClone(cloneUrl, branch, localPath, onProgress);
  }

  return localPath;
}

async function doClone(
  cloneUrl: string,
  branch: string | null,
  localPath: string,
  onProgress: (msg: string) => void,
): Promise<void> {
  onProgress(`Cloning repository to ${localPath}...`);

  // Try with the specified branch first; if no branch given or it fails, clone default
  if (branch) {
    try {
      await runGit(['clone', '--depth=1', `--branch=${branch}`, cloneUrl, localPath], undefined, onProgress);
      onProgress(`Repository cloned: ${localPath}`);
      return;
    } catch (err) {
      onProgress(`Branch "${branch}" not found, cloning default branch...`);
      if (fs.existsSync(localPath)) fs.rmSync(localPath, { recursive: true, force: true });
    }
  }

  // Clone without specifying branch (gets default branch)
  await runGit(['clone', '--depth=1', cloneUrl, localPath], undefined, onProgress);
  onProgress(`Repository cloned: ${localPath}`);
}
