/**
 * src/backend/cache_handler.ts — Cache delete operations.
 */

import { CacheManager } from './cache';

export function deleteAll(cacheDir: string): { ok: boolean } {
  try {
    const cache = new CacheManager(cacheDir);
    cache.deleteAll();
    return { ok: true };
  } catch {
    return { ok: false };
  }
}

export function deleteCache(cacheDir: string, orgId: string): { ok: boolean } {
  try {
    if (!orgId) throw new Error('orgId is required');
    const cache = new CacheManager(cacheDir);
    cache.delete(orgId);
    return { ok: true };
  } catch {
    return { ok: false };
  }
}
