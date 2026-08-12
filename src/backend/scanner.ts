/**
 * src/backend/scanner.ts — Org scanning with real-time progress events.
 *
 * Progress fires AS EACH PROJECT COMPLETES, not after all are done.
 * Phases:
 *   1. "listing"   — fetching project list from Snyk
 *   2. "scanning"  — scanning projects concurrently (emits per-project progress)
 *   3. "saving"    — writing cache to disk
 */

import type { SnykClient, SnykOrg } from './snykApi';
import type { ScanResult } from './cache';

// Max projects scanned simultaneously.
// Each project makes 3 API calls; the client's semaphore (default 12) caps
// total in-flight requests, so effective concurrency = min(CONCURRENCY, semaphore/3).
const CONCURRENCY = 20;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ScanPhase = 'listing' | 'scanning' | 'saving' | 'done';

export interface ScanProgress {
  phase: ScanPhase;
  // scanning phase
  project?: string;
  status?: 'ok' | 'error' | 'retry';
  done?: number;
  total?: number;
  vulns?: number;
  error?: string;
  // rate limit info
  rateLimited?: boolean;
  retryIn?: number;
  // live counters
  criticalTotal?: number;
  highTotal?: number;
  fixableTotal?: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isFixable(issues: unknown[]): boolean {
  return issues.some((i) => {
    const issue = i as Record<string, unknown>;
    if (issue['isUpgradable'] || issue['isPatchable'] || issue['isPinnable']) return true;
    const fi = issue['fixInfo'] as Record<string, unknown> | undefined;
    return !!(fi?.['isUpgradable'] || fi?.['isPatchable'] || fi?.['isPinnable'] || fi?.['isFixable']);
  });
}

function countSeverity(issues: unknown[]): { critical: number; high: number; medium: number; low: number } {
  const sev = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const issue of issues) {
    const iss = issue as Record<string, unknown>;
    const severity = ((iss['issueData'] as Record<string, unknown>)?.['severity'] as string) ?? 'low';
    if (severity in sev) sev[severity as keyof typeof sev]++;
  }
  return sev;
}

// ---------------------------------------------------------------------------
// Main scan function
// ---------------------------------------------------------------------------

export async function scanOrg(
  client: SnykClient,
  org: SnykOrg,
  onProgress: (p: ScanProgress) => void,
  includedOrigins: string[] = [],
  includedTypes: string[] = [],
): Promise<ScanResult[]> {

  // ── Phase 1: list projects ────────────────────────────────────────────────
  onProgress({ phase: 'listing' });
  const allProjects = await client.listProjects(org.id);

  console.log(`[scanner] Total projects fetched: ${allProjects.length}`);
  console.log(`[scanner] Included origins (empty = all): ${JSON.stringify(includedOrigins)}`);
  console.log(`[scanner] Included types (empty = all): ${JSON.stringify(includedTypes)}`);

  // Log unique origins and types for debugging
  const uniqueOrigins = Array.from(new Set(allProjects.map(p => p.origin)));
  const uniqueTypes = Array.from(new Set(allProjects.map(p => p.type)));
  console.log(`[scanner] Unique origins found: ${JSON.stringify(uniqueOrigins)}`);
  console.log(`[scanner] Unique types found: ${JSON.stringify(uniqueTypes)}`);

  // Filter to ONLY include projects with selected origins/types
  // If arrays are empty, include all
  const projects = allProjects.filter(p => {
    // If no origins selected, include all origins
    const originMatch = includedOrigins.length === 0 || includedOrigins.includes(p.origin);
    // If no types selected, include all types
    const typeMatch = includedTypes.length === 0 || includedTypes.includes(p.type);
    
    // Must match BOTH filters (or filter must be empty)
    const isIncluded = originMatch && typeMatch;
    
    if (!isIncluded) {
      console.log(`[scanner] Filtering out project "${p.name}" (origin: "${p.origin}", type: "${p.type}")`);
    }
    return isIncluded;
  });

  console.log(`[scanner] Projects after filtering: ${projects.length}`);

  if (projects.length === 0) {
    onProgress({ phase: 'done', total: 0, done: 0 });
    return [];
  }

  const total = projects.length;
  const scanResults: ScanResult[] = [];

  // Running totals for live counters in the UI
  let criticalTotal = 0;
  let highTotal = 0;
  let fixableTotal = 0;
  let done = 0;

  // ── Phase 2: scan projects concurrently ───────────────────────────────────
  // Emit an initial "scanning" event so the UI shows the total immediately
  onProgress({ phase: 'scanning', done: 0, total, criticalTotal: 0, highTotal: 0, fixableTotal: 0 });

  // Pool of workers — each grabs the next project, scans it, fires progress
  let idx = 0;
  const mu = { val: 0 }; // simple mutex-free counter (JS is single-threaded for sync ops)

  async function worker(): Promise<void> {
    while (true) {
      // Grab next project index atomically (JS event loop guarantees this is safe)
      const i = idx++;
      if (i >= projects.length) break;

      const proj = projects[i];

      try {
        // Fetch active issues, ignored issues, and ignore expiry map concurrently.
        // Use Promise.allSettled so one failure doesn't abort the other two.
        const [issuesResult, ignoredResult, ignoresMapResult] = await Promise.allSettled([
          client.getIssues(org.id, proj.id),
          client.getIgnoredIssues(org.id, proj.id),
          client.getProjectIgnores(org.id, proj.id),
        ]);

        const issues       = issuesResult.status       === 'fulfilled' ? issuesResult.value       : [];
        const ignored      = ignoredResult.status      === 'fulfilled' ? ignoredResult.value      : [];
        const ignoresMap   = ignoresMapResult.status   === 'fulfilled' ? ignoresMapResult.value   : {};

        const sev     = countSeverity(issues);
        const fixable = isFixable(issues);
        const vulns   = issues.length;

        // Update running totals
        criticalTotal += sev.critical;
        highTotal     += sev.high;
        if (fixable) fixableTotal++;
        done++;

        const result: ScanResult = {
          id:          proj.id,
          name:        proj.name,
          type:        proj.type,
          origin:      proj.origin,
          severity:    sev,
          fixable,
          total_vulns: vulns,
          risk_score:  null,
          issues,
          _ignored_issues: ignored,
          _ignores_map:    ignoresMap,
        };

        scanResults.push(result);

        onProgress({
          phase:         'scanning',
          project:       proj.name,
          status:        'ok',
          done,
          total,
          vulns,
          criticalTotal,
          highTotal,
          fixableTotal,
        });

      } catch (err: unknown) {
        done++;
        const errorMsg = err instanceof Error ? err.message : String(err);

        onProgress({
          phase:   'scanning',
          project: proj.name,
          status:  'error',
          done,
          total,
          error:   errorMsg,
          criticalTotal,
          highTotal,
          fixableTotal,
        });
      }
    }
  }

  // Spawn workers — they race to consume the projects array
  const workerCount = Math.min(CONCURRENCY, projects.length);
  await Promise.all(Array.from({ length: workerCount }, () => worker()));

  // ── Phase 3: saving cache ─────────────────────────────────────────────────
  onProgress({ phase: 'saving', done: total, total });

  return scanResults;
}
