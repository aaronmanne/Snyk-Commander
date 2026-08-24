/**
 * src/backend/report.ts — Markdown + CSV report generation.
 * Ported from snyk-commander/report.py
 */

import * as fs from 'fs';
import * as path from 'path';
import type { SnykOrg } from './snykApi';
import type { ScanResult, CacheManager, ProjectIgnoredData } from './cache';
import { SnykClient } from './snykApi';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function riskRating(score: unknown): [string, string] {
  if (score == null || score === 'N/A') return ['N/A', 'N/A'];
  const s = parseInt(String(score), 10);
  if (isNaN(s)) return ['N/A', 'N/A'];
  if (s <= 200) return [String(s), 'Very Low'];
  if (s <= 400) return [String(s), 'Low'];
  if (s <= 600) return [String(s), 'Moderate'];
  if (s <= 800) return [String(s), 'High'];
  return [String(s), 'Critical'];
}

function formatExpires(expiresStr: string): string {
  if (!expiresStr) return '';
  try {
    return expiresStr.substring(0, 10);
  } catch {
    return expiresStr;
  }
}

function isFixableIssue(issue: Record<string, unknown>): boolean {
  if (issue['isUpgradable'] || issue['isPatchable'] || issue['isPinnable']) return true;
  const fi = issue['fixInfo'] as Record<string, unknown> | undefined;
  if (fi?.['isUpgradable'] || fi?.['isPatchable'] || fi?.['isPinnable']) return true;
  return false;
}

function issueRiskScore(issue: Record<string, unknown>): number | null {
  const priority = issue['priority'] as Record<string, unknown> | undefined;
  const raw = priority?.['score'] ?? (issue['issueData'] as Record<string, unknown>)?.['cvssScore'];
  if (raw == null) return null;
  const n = parseInt(String(raw), 10);
  return isNaN(n) ? null : n;
}

// ---------------------------------------------------------------------------
// Row building — 9-tuple: (#, project, type, severity, title, fix_available, score_str, rating_str, ignored_until)
// ---------------------------------------------------------------------------

type Row = [number, string, string, string, string, string, string, string, string];

function buildRows(
  results: ScanResult[],
  ignoreMap: Map<string, string> | null,
): Row[] {
  const rows: Row[] = [];
  let rowNum = 0;

  for (const r of results) {
    for (const rawIssue of r.issues ?? []) {
      rowNum++;
      const issue = rawIssue as Record<string, unknown>;
      const issueData = (issue['issueData'] as Record<string, unknown>) ?? {};
      const vulnId = (issueData['id'] as string) || (issue['id'] as string) || '';
      const title = (issueData['title'] as string) ?? 'Unknown';
      const severity =
        ((issueData['severity'] as string) ?? 'unknown').charAt(0).toUpperCase() +
        ((issueData['severity'] as string) ?? 'unknown').slice(1);
      const fixStr = isFixableIssue(issue) ? 'Yes' : 'No';
      const rawScore = issueRiskScore(issue);
      const [scoreStr, ratingStr] = riskRating(rawScore);

      let ignoredUntil = '';
      if (issue['_ignored_until']) {
        ignoredUntil = formatExpires(String(issue['_ignored_until']));
      } else if (ignoreMap) {
        const key = `${r.id}|||${vulnId}`;
        const expires = ignoreMap.get(key);
        if (expires) ignoredUntil = formatExpires(expires);
      }

      rows.push([rowNum, r.name, r.type ?? 'unknown', severity, title, fixStr, scoreStr, ratingStr, ignoredUntil]);
    }
  }

  return rows;
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

interface Stats {
  total: number;
  sev_counts: Record<string, number>;
  fixable: number;
  non_fixable: number;
  rating_counts: Record<string, number>;
  ignored_count: number;
}

function computeStats(rows: Row[]): Stats {
  const sevCounts: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  const ratingCounts: Record<string, number> = { 'Very Low': 0, Low: 0, Moderate: 0, High: 0, Critical: 0, 'N/A': 0 };
  let fixable = 0;
  let nonFixable = 0;
  let ignored = 0;

  for (const row of rows) {
    sevCounts[row[3]] = (sevCounts[row[3]] ?? 0) + 1;
    if (row[5] === 'Yes') fixable++;
    else nonFixable++;
    ratingCounts[row[7]] = (ratingCounts[row[7]] ?? 0) + 1;
    if (row[8]) ignored++;
  }

  return {
    total: rows.length,
    sev_counts: sevCounts,
    fixable,
    non_fixable: nonFixable,
    rating_counts: ratingCounts,
    ignored_count: ignored,
  };
}

// ---------------------------------------------------------------------------
// Executive summary
// ---------------------------------------------------------------------------

function buildExecutiveSummary(
  org: SnykOrg,
  stats: Stats,
  reportMode: string,
  minRiskScore: number,
  now: string,
  projectsScanned: number,
): string[] {
  const { total, sev_counts: sev, fixable, non_fixable: nonFixable, rating_counts: rating, ignored_count: ignored } = stats;

  const lowRiskNf = (rating['Very Low'] ?? 0) + (rating['Low'] ?? 0);
  const moderatePlusNf = (rating['Moderate'] ?? 0) + (rating['High'] ?? 0) + (rating['Critical'] ?? 0);

  let scopeDesc: string;
  if (reportMode === 'non_fixable') {
    scopeDesc = 'non-fixable vulnerabilities — findings for which no vendor patch or upgrade path currently exists';
  } else if (reportMode === 'non_fixable_above_score') {
    scopeDesc = `non-fixable vulnerabilities with a Snyk risk score at or above **${minRiskScore}** — findings that have no available fix but carry an elevated risk score`;
  } else {
    scopeDesc = 'all vulnerabilities detected across the scanned projects';
  }

  const lines: string[] = [];
  lines.push('## Executive Summary', '');
  lines.push(
    `This report was generated on **${now}** for the **${org.name}** organization ` +
      `and covers ${scopeDesc}. ` +
      `A total of **${total}** finding(s) were identified across **${projectsScanned}** project(s).`,
    '',
  );

  lines.push(
    '### Findings Overview', '',
    '| Metric | Count |', '|--------|-------|',
    `| Total Findings | ${total} |`,
    `| Critical Severity | ${sev['Critical'] ?? 0} |`,
    `| High Severity | ${sev['High'] ?? 0} |`,
    `| Medium Severity | ${sev['Medium'] ?? 0} |`,
    `| Low Severity | ${sev['Low'] ?? 0} |`,
    `| Fixable | ${fixable} |`,
    `| Non-Fixable (no patch available) | ${nonFixable} |`,
    `| Currently Ignored | ${ignored} |`, '',
  );

  lines.push(
    '### Snyk Risk Score Distribution', '',
    '| Risk Rating | Score Range | Count |', '|-------------|-------------|-------|',
    `| Very Low | 0 – 200 | ${rating['Very Low'] ?? 0} |`,
    `| Low | 201 – 400 | ${rating['Low'] ?? 0} |`,
    `| Moderate | 401 – 600 | ${rating['Moderate'] ?? 0} |`,
    `| High | 601 – 800 | ${rating['High'] ?? 0} |`,
    `| Critical | 801 – 1000 | ${rating['Critical'] ?? 0} |`,
    `| No Score | N/A | ${rating['N/A'] ?? 0} |`, '',
  );

  lines.push('### Likelihood of Exploitation & Impact Assessment', '');

  if (reportMode === 'all') {
    if (fixable > 0) {
      lines.push(
        `**Fixable findings (${fixable}):** These represent the primary remediation priority. ` +
          'A fix — whether a dependency upgrade, patch, or pinned version — is available and should be applied. ' +
          'Critical and High severity fixable vulnerabilities in particular carry real exploit potential and ' +
          'should be addressed as soon as possible within your normal patching cadence.',
        '',
      );
    }
    if (nonFixable > 0) {
      lines.push(
        `**Non-fixable findings (${nonFixable}):** No vendor patch or upgrade path currently exists for these ` +
          'vulnerabilities. The likelihood of successful exploitation is therefore significantly constrained.',
        '',
      );
      if (lowRiskNf > 0) {
        lines.push(
          `Of the non-fixable findings, **${lowRiskNf}** carry a Very Low or Low Snyk risk score (score ≤ 400). ` +
            'These exhibit virtually no practical exploitability. **These findings can reasonably be treated as accepted risk.**',
          '',
        );
      }
      if (moderatePlusNf > 0) {
        lines.push(
          `**${moderatePlusNf}** non-fixable finding(s) carry a Moderate or higher risk score. ` +
            'While no patch exists, the elevated score warrants monitoring.',
          '',
        );
      }
    }
    if (total === 0) {
      lines.push('No vulnerabilities matched the selected criteria. The environment is clean for this scope.', '');
    }
  } else if (reportMode === 'non_fixable') {
    lines.push(
      `This report covers **${total}** non-fixable vulnerability(ies). ` +
        'Because no vendor patch or upgrade currently exists for any of these findings, the ability for an attacker to exploit them is fundamentally limited.',
      '',
    );
    if (lowRiskNf > 0) {
      lines.push(
        `**${lowRiskNf}** finding(s) have a Very Low or Low Snyk risk score (≤ 400). ` +
          '**From an operational security standpoint these findings present negligible risk and are considered equivalent to false positives.**',
        '',
      );
    }
    if (moderatePlusNf > 0) {
      lines.push(
        `**${moderatePlusNf}** non-fixable finding(s) have a Moderate or higher risk score. ` +
          'Despite the absence of a fix these warrant closer attention.',
        '',
      );
    }
    if (total === 0) {
      lines.push('No non-fixable vulnerabilities were found. No immediate action required.', '');
    }
  } else if (reportMode === 'non_fixable_above_score') {
    lines.push(
      `This report focuses on **${total}** non-fixable vulnerability(ies) with a Snyk risk score at or above **${minRiskScore}**.`,
      '',
      'Even so, the absence of a vendor fix is a meaningful mitigating factor. ' +
        '**Recommended actions:** monitor vendor advisories closely, apply compensating controls.',
      '',
    );
    if (total === 0) {
      lines.push(`No non-fixable vulnerabilities with a risk score ≥ ${minRiskScore} were found.`, '');
    }
  }

  lines.push('### Recommendations', '');
  const recs: string[] = [];

  if (reportMode === 'all' && fixable > 0) {
    recs.push(`**Remediate fixable findings first.** ${fixable} finding(s) have an available fix.`);
  }
  if (nonFixable > 0 && lowRiskNf > 0) {
    recs.push(
      `**Accept or ignore low-risk non-fixable findings.** ${lowRiskNf} finding(s) with a Very Low or Low risk score present negligible exploitability.`,
    );
  }
  if (nonFixable > 0 && moderatePlusNf > 0) {
    recs.push(
      `**Monitor elevated non-fixable findings.** ${moderatePlusNf} non-fixable finding(s) carry a Moderate or higher risk score.`,
    );
  }
  if (ignored > 0) {
    recs.push(`**Review active ignores.** ${ignored} finding(s) are currently set to ignored in Snyk.`);
  }
  if (recs.length === 0) {
    recs.push('No findings matched the selected criteria. Continue regular scanning to maintain visibility.');
  }

  for (let i = 0; i < recs.length; i++) {
    lines.push(`${i + 1}. ${recs[i]}`, '');
  }
  lines.push('---', '');
  return lines;
}

// ---------------------------------------------------------------------------
// Ignored data loading
// ---------------------------------------------------------------------------

async function loadOrFetchIgnoredData(
  client: SnykClient,
  org: SnykOrg,
  results: ScanResult[],
  cache: CacheManager | null,
): Promise<Record<string, ProjectIgnoredData>> {
  if (cache) {
    const cached = cache.loadIgnoredData(org.id);
    if (cached) return cached;
  }

  const ignoredData: Record<string, ProjectIgnoredData> = {};
  const CONCURRENCY = 10;
  let idx = 0;

  async function worker() {
    while (idx < results.length) {
      const i = idx++;
      const proj = results[i];
      try {
        const [ignoredIssues, ignoresMap] = await Promise.all([
          client.getIgnoredIssues(org.id, proj.id).catch(() => []),
          client.getProjectIgnores(org.id, proj.id).catch(() => ({})),
        ]);
        ignoredData[proj.id] = { ignored_issues: ignoredIssues, ignores_map: ignoresMap };
      } catch {
        ignoredData[proj.id] = { ignored_issues: [], ignores_map: {} };
      }
    }
  }

  const workers = Array.from({ length: Math.min(CONCURRENCY, results.length) }, () => worker());
  await Promise.all(workers);

  if (cache) cache.saveIgnoredData(org.id, ignoredData);
  return ignoredData;
}

// ---------------------------------------------------------------------------
// Main report generator
// ---------------------------------------------------------------------------

export async function generateReport(params: {
  org: SnykOrg;
  results: ScanResult[];
  token?: string;
  reportMode: 'all' | 'non_fixable' | 'non_fixable_above_score';
  minRiskScore: number;
  reportsDir: string;
  cacheDir: string;
}): Promise<{ md_path: string; csv_path: string }> {
  const { org, results, token, reportMode, minRiskScore, reportsDir } = params;

  fs.mkdirSync(reportsDir, { recursive: true });

  const now = new Date().toISOString().replace('T', ' ').substring(0, 19);
  const timestamp = now.replace(/[: ]/g, '-').substring(0, 19);
  const modeTag =
    reportMode === 'all'
      ? 'all'
      : reportMode === 'non_fixable'
      ? 'nonfixable'
      : `nonfixable_score${minRiskScore}`;
  const baseName = `vuln_report_${org.slug ?? org.id}_${modeTag}_${timestamp}`;
  const mdPath = path.join(reportsDir, `${baseName}.md`);
  const csvPath = path.join(reportsDir, `${baseName}.csv`);

  // Enrich with ignored data if token provided
  const ignoreMap = new Map<string, string>();
  let enrichedResults = [...results];

  if (token) {
    const client = new SnykClient(token);

    // Try to load cache
    let cache: CacheManager | null = null;
    try {
      const { CacheManager: CM } = await import('./cache');
      cache = new CM(params.cacheDir);
    } catch {
      cache = null;
    }

    const ignoredData = await loadOrFetchIgnoredData(client, org, results, cache);

    for (const [projectId, projData] of Object.entries(ignoredData)) {
      for (const [vulnId, expires] of Object.entries(projData.ignores_map)) {
        ignoreMap.set(`${projectId}|||${vulnId}`, expires);
      }

      if (projData.ignored_issues.length > 0) {
        const ignoredIssues = projData.ignored_issues.map((iss) => {
          const issue = iss as Record<string, unknown>;
          const issueData = (issue['issueData'] as Record<string, unknown>) ?? {};
          const vid = (issueData['id'] as string) || (issue['id'] as string) || '';
          return { ...issue, _ignored_until: projData.ignores_map[vid] ?? '' };
        });

        enrichedResults = enrichedResults.map((r) =>
          r.id === projectId
            ? { ...r, issues: [...(r.issues ?? []), ...ignoredIssues] }
            : r,
        );
      }
    }
  }

  // Apply report-mode filter
  const filteredResults: ScanResult[] = [];
  for (const r of enrichedResults) {
    if (!r.issues?.length) continue;
    const filtered = r.issues.filter((rawIssue) => {
      const issue = rawIssue as Record<string, unknown>;
      const fixable = isFixableIssue(issue);
      const score = issueRiskScore(issue);
      if (reportMode === 'all') return true;
      if (reportMode === 'non_fixable') return !fixable;
      if (reportMode === 'non_fixable_above_score') {
        return !fixable && score != null && score >= minRiskScore;
      }
      return true;
    });
    if (filtered.length > 0) filteredResults.push({ ...r, issues: filtered });
  }

  const rows = buildRows(filteredResults, token ? ignoreMap : null);
  const stats = computeStats(rows);

  const modeTitles: Record<string, string> = {
    all: 'Full Vulnerability Report',
    non_fixable: 'Non-Fixable Vulnerability Report',
    non_fixable_above_score: `Non-Fixable Vulnerability Report (Risk Score ≥ ${minRiskScore})`,
  };
  const reportTitle = modeTitles[reportMode] ?? 'Vulnerability Report';

  const execSummary = buildExecutiveSummary(org, stats, reportMode, minRiskScore, now, results.length);

  const headerLines = [
    `# ${reportTitle}`,
    '',
    `**Organization:** ${org.name}  `,
    `**Date:** ${now}  `,
    `**Projects Scanned:** ${results.length}  `,
    '',
  ];

  const detailLines = [
    '## Vulnerability Detail',
    '',
    '| # | Project | Type | Severity | Vulnerability | Fix Available | Risk Score | Risk | Ignored Until |',
    '|---|---------|------|----------|---------------|---------------|------------|------|---------------|',
  ];
  for (const row of rows) {
    detailLines.push(
      `| ${row[0]} | ${row[1]} | ${row[2]} | ${row[3]} | ${row[4]} | ${row[5]} | ${row[6]} | ${row[7]} | ${row[8]} |`,
    );
  }
  detailLines.push('', '*Generated by Snyk Commander*');

  const allLines = [...headerLines, ...execSummary, ...detailLines];
  fs.writeFileSync(mdPath, allLines.join('\n'), 'utf8');

  // CSV
  const csvHeaders = ['#', 'Project', 'Type', 'Severity', 'Vulnerability', 'Fix Available', 'Risk Score', 'Risk', 'Ignored Until'];
  const csvLines = [csvHeaders.join(',')];
  for (const row of rows) {
    csvLines.push(row.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(','));
  }
  fs.writeFileSync(csvPath, csvLines.join('\n'), 'utf8');

  return { md_path: mdPath, csv_path: csvPath };
}
