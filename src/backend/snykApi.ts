/**
 * src/backend/snykApi.ts — Snyk API client using native Node.js fetch (Node 18+).
 *
 * Design:
 *  - Per-client semaphore (not global) so scanner concurrency is independently controlled
 *  - 429 responses honour Retry-After header when present
 *  - All retryable errors use exponential backoff with jitter
 *  - Timeout per request via AbortController
 */

const API_V1 = 'https://api.snyk.io/v1';
const API_REST = 'https://api.snyk.io/rest';
const REST_VERSION = '2024-10-15';
const REQUEST_TIMEOUT_MS = 60_000;
const MAX_RETRIES = 6;
const BASE_BACKOFF_MS = 1_000;
const MAX_BACKOFF_MS = 32_000;

export interface SnykOrg {
  id: string;
  name: string;
  slug: string;
}

export interface SnykProject {
  id: string;
  name: string;
  type: string;
  origin: string;
}

export interface SnykIssue {
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Semaphore — caps concurrent in-flight HTTP requests per client instance
// ---------------------------------------------------------------------------

export class Semaphore {
  private queue: Array<() => void> = [];
  private running = 0;

  constructor(private readonly max: number) {}

  acquire(): Promise<() => void> {
    return new Promise((resolve) => {
      const attempt = () => {
        if (this.running < this.max) {
          this.running++;
          resolve(() => {
            this.running--;
            if (this.queue.length > 0) this.queue.shift()!();
          });
        } else {
          this.queue.push(attempt);
        }
      };
      attempt();
    });
  }

  get pending(): number { return this.queue.length; }
  get active(): number { return this.running; }
}

// ---------------------------------------------------------------------------
// Fetch with retry + timeout + rate-limit back-off
// ---------------------------------------------------------------------------

async function fetchWithRetry(
  url: string,
  options: RequestInit,
  semaphore: Semaphore,
  retries = MAX_RETRIES,
): Promise<Response> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    const release = await semaphore.acquire();
    let resp: Response;

    try {
      resp = await fetch(url, { ...options, signal: controller.signal });
    } catch (err: unknown) {
      const isAbort = err instanceof Error &&
        (err.name === 'AbortError' || err.message.includes('abort'));

      if (attempt >= retries) throw err;

      const backoff = isAbort
        ? BASE_BACKOFF_MS                    // timeout → back off briefly then retry
        : Math.min(BASE_BACKOFF_MS * Math.pow(2, attempt) + Math.random() * 500, MAX_BACKOFF_MS);

      await sleep(backoff);
      continue;
    } finally {
      clearTimeout(timer);
      release();
    }

    // Success
    if (resp.ok) return resp;

    // Rate-limited → honour Retry-After or exponential back-off
    if (resp.status === 429) {
      if (attempt >= retries) throw new Error(`Rate limited after ${retries} retries: ${url}`);
      const retryAfter = resp.headers.get('retry-after');
      const wait = retryAfter
        ? parseInt(retryAfter, 10) * 1000
        : Math.min(BASE_BACKOFF_MS * Math.pow(2, attempt + 1) + Math.random() * 1000, MAX_BACKOFF_MS);
      await sleep(wait);
      continue;
    }

    // Server errors → retry
    if (resp.status >= 500 && attempt < retries) {
      const wait = Math.min(BASE_BACKOFF_MS * Math.pow(2, attempt) + Math.random() * 500, MAX_BACKOFF_MS);
      await sleep(wait);
      continue;
    }

    // Client error or exhausted retries → throw
    return resp;
  }

  throw new Error(`fetchWithRetry exhausted ${retries} retries for ${url}`);
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// ---------------------------------------------------------------------------
// SnykClient
// ---------------------------------------------------------------------------

export class SnykClient {
  /** Semaphore scoped to this client — tune per use-case */
  readonly semaphore: Semaphore;

  constructor(private readonly token: string, maxConcurrent = 12) {
    this.semaphore = new Semaphore(maxConcurrent);
  }

  private get headersV1(): Record<string, string> {
    return {
      Authorization: `token ${this.token}`,
      'Content-Type': 'application/json',
    };
  }

  private get headersRest(): Record<string, string> {
    return {
      Authorization: `token ${this.token}`,
      'Content-Type': 'application/vnd.api+json',
    };
  }

  // ── REST paginator ────────────────────────────────────────────────────────

  async restGetAll(path: string, params?: Record<string, string>): Promise<unknown[]> {
    const items: unknown[] = [];
    const baseParams = new URLSearchParams({
      version: REST_VERSION,
      limit: '100',
      ...(params ?? {}),
    });

    let url: string | null = `${API_REST}${path}?${baseParams}`;

    while (url) {
      const resp = await fetchWithRetry(url, {
        method: 'GET',
        headers: this.headersRest,
      }, this.semaphore);

      if (!resp.ok) {
        const body = await resp.text().catch(() => '');
        throw new Error(`Snyk REST GET ${path} → ${resp.status}: ${body.slice(0, 200)}`);
      }

      const body = (await resp.json()) as {
        data?: unknown[];
        links?: { next?: string | null };
      };
      items.push(...(body.data ?? []));

      const next = body.links?.next;
      if (!next) { url = null; continue; }
      if (next.startsWith('http')) { url = next; }
      else if (next.startsWith('/rest/')) { url = `https://api.snyk.io${next}`; }
      else { url = `${API_REST}${next}`; }
    }

    return items;
  }

  // ── Org / Project listing ─────────────────────────────────────────────────

  async listOrgs(): Promise<SnykOrg[]> {
    const data = await this.restGetAll('/orgs');
    return data.map((o) => {
      const org = o as { id: string; attributes: { name?: string; slug?: string } };
      return {
        id: org.id,
        name: org.attributes?.name ?? org.id,
        slug: org.attributes?.slug ?? org.id,
      };
    });
  }

  async listProjects(orgId: string): Promise<SnykProject[]> {
    const data = await this.restGetAll(`/orgs/${orgId}/projects`);
    return data.map((p) => {
      const proj = p as { id: string; attributes: { name?: string; type?: string; origin?: string } };
      return {
        id: proj.id,
        name: proj.attributes?.name ?? proj.id,
        type: proj.attributes?.type ?? 'unknown',
        origin: proj.attributes?.origin ?? 'unknown',
      };
    });
  }

  // ── Issues ────────────────────────────────────────────────────────────────

  async getIssues(orgId: string, projectId: string): Promise<SnykIssue[]> {
    const url = `${API_V1}/org/${orgId}/project/${projectId}/aggregated-issues`;
    const resp = await fetchWithRetry(url, {
      method: 'POST',
      headers: this.headersV1,
      body: JSON.stringify({
        filters: {
          severities: ['critical', 'high', 'medium', 'low'],
          types: ['vuln'],
          ignored: false,
          patched: false,
        },
      }),
    }, this.semaphore);

    if (!resp.ok) {
      const body = await resp.text().catch(() => '');
      throw new Error(`getIssues ${projectId} → ${resp.status}: ${body.slice(0, 200)}`);
    }

    const body = (await resp.json()) as { issues?: SnykIssue[] };
    return body.issues ?? [];
  }

  async getIgnoredIssues(orgId: string, projectId: string): Promise<SnykIssue[]> {
    const url = `${API_V1}/org/${orgId}/project/${projectId}/aggregated-issues`;
    const resp = await fetchWithRetry(url, {
      method: 'POST',
      headers: this.headersV1,
      body: JSON.stringify({
        filters: {
          severities: ['critical', 'high', 'medium', 'low'],
          types: ['vuln'],
          ignored: true,
          patched: false,
        },
      }),
    }, this.semaphore);

    if (!resp.ok) {
      const body = await resp.text().catch(() => '');
      throw new Error(`getIgnoredIssues ${projectId} → ${resp.status}: ${body.slice(0, 200)}`);
    }

    const body = (await resp.json()) as { issues?: SnykIssue[] };
    return body.issues ?? [];
  }

  async getProjectIgnores(orgId: string, projectId: string): Promise<Record<string, string>> {
    const url = `${API_V1}/org/${orgId}/project/${projectId}/ignores`;
    const resp = await fetchWithRetry(url, {
      method: 'GET',
      headers: this.headersV1,
    }, this.semaphore);

    if (!resp.ok) {
      // 404 = no ignores configured for this project — treat as empty
      if (resp.status === 404) return {};
      const body = await resp.text().catch(() => '');
      throw new Error(`getProjectIgnores ${projectId} → ${resp.status}: ${body.slice(0, 200)}`);
    }

    const data = (await resp.json()) as Record<
      string,
      Array<Record<string, Array<{ expires?: string }> | { expires?: string }>>
    >;

    const result: Record<string, string> = {};
    for (const [vulnId, pathList] of Object.entries(data)) {
      for (const pathEntry of pathList) {
        for (const [, detailsRaw] of Object.entries(pathEntry)) {
          const list = Array.isArray(detailsRaw) ? detailsRaw : [detailsRaw];
          for (const d of list) {
            const exp = (d as { expires?: string }).expires;
            if (exp && !(vulnId in result)) result[vulnId] = exp;
          }
        }
      }
    }

    return result;
  }

  // ── Mutations ─────────────────────────────────────────────────────────────

  async ignoreIssue(
    orgId: string,
    projectId: string,
    issueId: string,
    reason: string,
    expires: string,
    disregardIfFixable = true,
  ): Promise<void> {
    const url = `${API_V1}/org/${orgId}/project/${projectId}/ignore/${issueId}`;
    const resp = await fetchWithRetry(url, {
      method: 'POST',
      headers: this.headersV1,
      body: JSON.stringify({
        ignorePath: '*',
        reason,
        expires,
        disregardIfFixable,
        reasonType: 'temporary-ignore',
      }),
    }, this.semaphore);

    if (!resp.ok) {
      const body = await resp.text().catch(() => '');
      throw new Error(`ignoreIssue ${issueId} → ${resp.status}: ${body.slice(0, 200)}`);
    }
  }

  async unignoreIssue(orgId: string, projectId: string, issueId: string): Promise<void> {
    const url = `${API_V1}/org/${orgId}/project/${projectId}/ignore/${issueId}`;
    const resp = await fetchWithRetry(url, {
      method: 'DELETE',
      headers: this.headersV1,
    }, this.semaphore);

    if (!resp.ok) {
      const body = await resp.text().catch(() => '');
      throw new Error(`unignoreIssue ${issueId} → ${resp.status}: ${body.slice(0, 200)}`);
    }
  }
}
