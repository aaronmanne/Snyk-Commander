/**
 * src/backend/auth.ts — Token verification and cache check.
 */

import { SnykClient } from './snykApi';
import type { SnykOrg } from './snykApi';
import { CacheManager } from './cache';

export interface CachedOrgSummary {
  org: SnykOrg;
  timestamp: string;
  project_count: number;
  fixable_count: number;
}

export async function verifyToken(token: string): Promise<{ orgs: SnykOrg[] }> {
  if (!token?.trim()) throw new Error('token is required');
  const client = new SnykClient(token.trim());
  const orgs = await client.listOrgs();
  return { orgs };
}

export async function checkCache(cacheDir: string): Promise<{ cached_orgs: CachedOrgSummary[] }> {
  const cache = new CacheManager(cacheDir);
  const allCached = cache.loadAll();

  const result: CachedOrgSummary[] = allCached.map((entry) => {
    const results = entry.results ?? [];
    return {
      org: entry.org,
      timestamp: entry.timestamp,
      project_count: results.length,
      fixable_count: results.filter((r) => r.fixable).length,
    };
  });

  return { cached_orgs: result };
}
