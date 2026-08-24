/**
 * src/backend/cache.ts — JSON file cache stored in .snyk_cache/
 */

import * as fs from 'fs';
import * as path from 'path';
import type { SnykOrg } from './snykApi';

export interface ScanResult {
  id: string;
  name: string;
  type: string;
  origin: string;
  severity: { critical: number; high: number; medium: number; low: number };
  fixable: boolean;
  total_vulns: number;
  risk_score: number | null;
  issues: unknown[];
  _ignored_issues?: unknown[];
  _ignores_map?: Record<string, string>;
}

export interface ProjectIgnoredData {
  ignored_issues: unknown[];
  ignores_map: Record<string, string>;
}

export interface CacheEntry {
  org: SnykOrg;
  results: ScanResult[];
  timestamp: string;
}

export class CacheManager {
  constructor(private cacheDir: string) {}

  private ensureDir(): void {
    if (!fs.existsSync(this.cacheDir)) {
      fs.mkdirSync(this.cacheDir, { recursive: true });
    }
  }

  private scanFile(orgId: string): string {
    return path.join(this.cacheDir, `scan_${orgId}.json`);
  }

  private ignoredFile(orgId: string): string {
    return path.join(this.cacheDir, `ignored_${orgId}.json`);
  }

  save(org: SnykOrg, results: ScanResult[]): void {
    this.ensureDir();

    const cachedResults = results.map((r) => {
      let maxScore: number | null = null;
      for (const issue of r.issues ?? []) {
        const iss = issue as Record<string, unknown>;
        const priority = iss['priority'] as Record<string, unknown> | undefined;
        const issueData = iss['issueData'] as Record<string, unknown> | undefined;
        let score = priority?.['score'];
        if (score == null) score = issueData?.['cvssScore'];
        if (score != null) {
          const s = parseInt(String(score), 10);
          if (!isNaN(s) && (maxScore === null || s > maxScore)) maxScore = s;
        }
      }

      return {
        id: r.id,
        name: r.name,
        type: r.type,
        origin: r.origin,
        severity: r.severity,
        fixable: r.fixable,
        total_vulns: r.total_vulns,
        risk_score: maxScore,
        issues: r.issues ?? [],
      };
    });

    const payload: CacheEntry = {
      org,
      results: cachedResults as ScanResult[],
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
    };

    fs.writeFileSync(this.scanFile(org.id), JSON.stringify(payload, null, 2), 'utf8');
  }

  load(orgId: string): CacheEntry | null {
    const file = this.scanFile(orgId);
    if (!fs.existsSync(file)) return null;
    try {
      const raw = fs.readFileSync(file, 'utf8');
      const data = JSON.parse(raw) as CacheEntry;
      if (!data.org) return null;
      return data;
    } catch {
      return null;
    }
  }

  loadAll(): CacheEntry[] {
    if (!fs.existsSync(this.cacheDir)) return [];
    const entries: CacheEntry[] = [];
    const files = fs.readdirSync(this.cacheDir).filter((f) => f.startsWith('scan_') && f.endsWith('.json'));
    for (const f of files) {
      try {
        const raw = fs.readFileSync(path.join(this.cacheDir, f), 'utf8');
        const data = JSON.parse(raw) as CacheEntry;
        if (data?.org) entries.push(data);
      } catch {
        // skip corrupt files
      }
    }
    return entries;
  }

  delete(orgId: string): void {
    for (const file of [this.scanFile(orgId), this.ignoredFile(orgId)]) {
      if (fs.existsSync(file)) fs.unlinkSync(file);
    }
  }

  deleteAll(): void {
    if (!fs.existsSync(this.cacheDir)) return;
    const files = fs.readdirSync(this.cacheDir);
    for (const f of files) {
      if (f.startsWith('scan_') || f.startsWith('ignored_')) {
        fs.unlinkSync(path.join(this.cacheDir, f));
      }
    }
  }

  saveIgnoredData(orgId: string, ignoredData: Record<string, ProjectIgnoredData>): void {
    this.ensureDir();
    const payload = {
      org_id: orgId,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      projects: ignoredData,
    };
    fs.writeFileSync(this.ignoredFile(orgId), JSON.stringify(payload, null, 2), 'utf8');
  }

  loadIgnoredData(orgId: string): Record<string, ProjectIgnoredData> | null {
    const file = this.ignoredFile(orgId);
    if (!fs.existsSync(file)) return null;
    try {
      const raw = fs.readFileSync(file, 'utf8');
      const payload = JSON.parse(raw) as { projects?: Record<string, ProjectIgnoredData> };
      return payload.projects ?? null;
    } catch {
      return null;
    }
  }

  deleteIgnoredData(orgId: string): void {
    const file = this.ignoredFile(orgId);
    if (fs.existsSync(file)) fs.unlinkSync(file);
  }
}
