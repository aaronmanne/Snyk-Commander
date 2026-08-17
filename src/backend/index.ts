/**
 * src/backend/index.ts — Backend router called directly from Electron main process IPC.
 */

import * as auth from './auth';
import * as cacheHandler from './cache_handler';
import * as scanner from './scanner';
import * as ignores from './ignores';
import * as fixPr from './fixPr';
import * as report from './report';
import * as reachability from './reachability';
import * as oauthModule from './oauth';
import * as ollamaModule from './ollama';
import * as githubModule from './github';
import { CacheManager } from './cache';
import { SnykClient } from './snykApi';
import type { SnykOrg } from './snykApi';
import type { ScanResult } from './cache';
import { ReachabilityJobManager } from './reachabilityJobs';
import * as path from 'path';

export interface InvokeContext {
  appRoot: string;
  cacheDir: string;
  reportsDir: string;
  snykIgnoresDir: string;
  snykFilePath: string;
}

// Global job manager instance
let jobManager: ReachabilityJobManager | null = null;

function getJobManager(ctx: InvokeContext): ReachabilityJobManager {
  if (!jobManager) {
    const storageDir = path.join(ctx.cacheDir, 'reachability');
    jobManager = new ReachabilityJobManager(storageDir);
  }
  return jobManager;
}

// ---------------------------------------------------------------------------
// Non-streaming invoke
// ---------------------------------------------------------------------------

export async function invoke(
  method: string,
  params: Record<string, unknown>,
  ctx: InvokeContext,
): Promise<unknown> {
  if (process.env.NODE_ENV === 'development') console.log(`[backend] invoke method=${method}`);

  switch (method) {
    case 'ping':
      return { pong: true };

    // ── auth ──────────────────────────────────────────────────────────────
    case 'auth.verify_token': {
      const token = String(params['token'] ?? '').trim();
      if (!token) throw new Error('token is required');
      return auth.verifyToken(token);
    }

    case 'auth.check_cache':
      return auth.checkCache(ctx.cacheDir);

    // ── cache ─────────────────────────────────────────────────────────────
    case 'cache.delete_all':
      return cacheHandler.deleteAll(ctx.cacheDir);

    case 'cache.delete': {
      const orgId = String(params['org_id'] ?? '').trim();
      if (!orgId) throw new Error('org_id is required');
      return cacheHandler.deleteCache(ctx.cacheDir, orgId);
    }

    case 'cache.load_org': {
      const orgId = String(params['org_id'] ?? '').trim();
      if (!orgId) throw new Error('org_id is required');
      const cache = new CacheManager(ctx.cacheDir);
      const entry = cache.load(orgId);
      if (!entry) return { found: false, entry: null };
      return {
        found: true,
        entry: {
          org: entry.org,
          timestamp: entry.timestamp,
          project_count: entry.results.length,
          vuln_count: entry.results.reduce((s, r) => s + (r.total_vulns ?? 0), 0),
          fixable_count: entry.results.filter(r => r.fixable).length,
          critical_count: entry.results.reduce((s, r) => s + (r.severity?.critical ?? 0), 0),
          high_count: entry.results.reduce((s, r) => s + (r.severity?.high ?? 0), 0),
          results: entry.results,
        },
      };
    }

    // ── ignores ───────────────────────────────────────────────────────────
    case 'ignores.get_non_fixable': {
      const results = (params['results'] as ScanResult[]) ?? [];
      const minRiskScore = Number(params['min_risk_score'] ?? 0);
      if (!Array.isArray(results)) throw new Error('results must be a list');
      return ignores.analyzeIgnores(results, minRiskScore, ctx.snykFilePath);
    }

    case 'ignores.generate_snyk_files': {
      const results = (params['results'] as ScanResult[]) ?? [];
      const filterMode = String(params['filter_mode'] ?? 'non_fixable');
      const minRiskScore = Number(params['min_risk_score'] ?? 0);
      if (!Array.isArray(results)) throw new Error('results must be a list');
      return ignores.generateSnykFiles(results, filterMode, minRiskScore, ctx.snykIgnoresDir);
    }

    // ── fix_pr ────────────────────────────────────────────────────────────
    case 'fix_pr.get_fixable': {
      const results = (params['results'] as ScanResult[]) ?? [];
      if (!Array.isArray(results)) throw new Error('results must be a list');
      const fixable = results
        .filter((r) => r.fixable)
        .map((r) => ({ id: r.id, name: r.name, severity: r.severity }));
      return { projects: fixable };
    }

    case 'fix_pr.trigger': {
      const orgSlug = String(params['org_slug'] ?? '').trim();
      const projectId = String(params['project_id'] ?? '').trim();
      const token = String(params['token'] ?? '').trim();
      if (!orgSlug) throw new Error('org_slug is required');
      if (!projectId) throw new Error('project_id is required');
      if (!token) throw new Error('token is required');
      return fixPr.triggerFixPr(token, orgSlug, projectId);
    }

    // ── report ────────────────────────────────────────────────────────────
    case 'report.generate': {
      const org = params['org'] as SnykOrg;
      const results = (params['results'] as ScanResult[]) ?? [];
      const token = String(params['token'] ?? '').trim();
      const reportMode = String(params['report_mode'] ?? 'all') as 'all' | 'non_fixable' | 'non_fixable_above_score';
      const minRiskScore = Number(params['min_risk_score'] ?? 0);

      if (!org || typeof org !== 'object') throw new Error('org is required');
      if (!Array.isArray(results)) throw new Error('results must be a list');

      return report.generateReport({
        org,
        results,
        token: token || undefined,
        reportMode,
        minRiskScore,
        reportsDir: ctx.reportsDir,
        cacheDir: ctx.cacheDir,
      });
    }

    // ── oauth ─────────────────────────────────────────────────────────────
    case 'oauth.get_stored_tokens':
      return {
        snyk: oauthModule.getStoredSnykToken(),
        github: oauthModule.getStoredGitHubToken(),
        github_client_id: oauthModule.getStoredGitHubClientId(),
        ghe_host: oauthModule.getStoredGHEHost(),
      };

    case 'oauth.set_ghe_host': {
      const host = String(params['host'] ?? '').trim();
      if (!host) throw new Error('host is required');
      oauthModule.setGHEHost(host);
      return { ok: true };
    }

    case 'oauth.set_github_client_id': {
      const clientId = String(params['client_id'] ?? '').trim();
      if (!clientId) throw new Error('client_id is required');
      oauthModule.setGitHubClientId(clientId);
      return { ok: true };
    }

    case 'oauth.store_token': {
      const type = String(params['type'] ?? '') as 'snyk' | 'github';
      const token = String(params['token'] ?? '').trim();
      if (type !== 'snyk' && type !== 'github') throw new Error('type must be "snyk" or "github"');
      if (!token) throw new Error('token is required');
      oauthModule.storeToken(type, token);
      return { ok: true };
    }

    case 'oauth.clear_token': {
      const type = String(params['type'] ?? '') as 'snyk' | 'github';
      if (type !== 'snyk' && type !== 'github') throw new Error('type must be "snyk" or "github"');
      oauthModule.clearStoredToken(type);
      return { ok: true };
    }

    case 'oauth.github_device_flow':
      return oauthModule.startGitHubDeviceFlow();

    case 'oauth.get_included_origins':
      return { included_origins: oauthModule.getIncludedOrigins() };

    case 'oauth.set_included_origins': {
      const origins = params['origins'] as string[];
      if (!Array.isArray(origins)) throw new Error('origins must be an array');
      oauthModule.setIncludedOrigins(origins);
      return { ok: true };
    }

    case 'oauth.get_included_types':
      return { included_types: oauthModule.getIncludedTypes() };

    case 'oauth.set_included_types': {
      const types = params['types'] as string[];
      if (!Array.isArray(types)) throw new Error('types must be an array');
      oauthModule.setIncludedTypes(types);
      return { ok: true };
    }

    // ── ollama ────────────────────────────────────────────────────────────
    case 'ollama.get_status':
      return ollamaModule.getOllamaStatus();

    // ── ignores.ignore_single ─────────────────────────────────────────────
    case 'ignores.ignore_single': {
      const orgId = String(params['org_id'] ?? '').trim();
      const token = String(params['token'] ?? '').trim();
      const projectId = String(params['project_id'] ?? '').trim();
      const issueId = String(params['issue_id'] ?? '').trim();
      const reason = String(params['reason'] ?? 'Reachability analysis determined this vulnerability is not reachable.');
      const expires =
        String(params['expires'] ?? '') ||
        new Date(Date.now() + 90 * 86400 * 1000).toISOString().replace(/\.\d+Z$/, '.000Z');

      if (!orgId) throw new Error('org_id is required');
      if (!token) throw new Error('token is required');
      if (!projectId) throw new Error('project_id is required');
      if (!issueId) throw new Error('issue_id is required');

      const client = new SnykClient(token);
      // disregardIfFixable=false: this is an explicit, manual ignore action
      // (single ignore button, reachability "not reachable" ignore, etc.).
      // If we left this true, Snyk silently SKIPS creating the ignore whenever
      // a fix happens to be available for the issue — even though reachability
      // is unrelated to fixability, so many "not reachable" vulns do have a fix.
      // The user explicitly chose to ignore this issue, so it must always stick.
      await client.ignoreIssue(orgId, projectId, issueId, reason, expires, false);
      return { ok: true };
    }

    // ── reachability.analyze (background mode) ────────────────────────────
    case 'reachability.analyze': {
      const issue = params['issue'] as Record<string, unknown>;
      const projectName = String(params['project_name'] ?? '').trim();
      const projectOrigin = String(params['project_origin'] ?? '').trim();
      const githubToken = params['github_token'] ? String(params['github_token']) : null;
      const ollamaModel = String(params['ollama_model'] ?? 'llama3');
      const codebasePath = params['codebase_path'] ? String(params['codebase_path']).trim() : undefined;
      const gheHost = params['ghe_host'] ? String(params['ghe_host']).trim() : undefined;
      const forceReclone = params['force_reclone'] === true;
      const org_id = String(params['org_id'] ?? '').trim();
      const project_id = String(params['project_id'] ?? '').trim();
      const issue_id = String(params['issue_id'] ?? '').trim();
      const background = params['background'] === true;

      if (!issue || typeof issue !== 'object') throw new Error('issue is required');

      // Background mode - start job and return immediately
      if (background && org_id && project_id && issue_id) {
        const jm = getJobManager(ctx);
        const jobId = await jm.startJob({
          org_id,
          project_id,
          issue_id,
          issue,
          projectName,
          projectOrigin,
          githubToken,
          ollamaModel,
          codebasePath,
          gheHost,
          forceReclone,
        });
        return { jobId, background: true };
      }

      // Non-background mode - this should use stream function instead
      throw new Error('Non-background reachability analysis should use stream API');
    }

    // ── reachability.get_job_status ───────────────────────────────────────
    case 'reachability.get_job_status': {
      const jobId = String(params['job_id'] ?? '').trim();
      if (!jobId) throw new Error('job_id is required');
      
      const jm = getJobManager(ctx);
      const job = jm.getJob(jobId);
      return job || { error: 'Job not found' };
    }

    // ── reachability.get_stored_result ────────────────────────────────────
    case 'reachability.get_stored_result': {
      const org_id = String(params['org_id'] ?? '').trim();
      const project_id = String(params['project_id'] ?? '').trim();
      const issue_id = String(params['issue_id'] ?? '').trim();
      
      if (!org_id || !project_id || !issue_id) {
        throw new Error('org_id, project_id, and issue_id are required');
      }
      
      const jm = getJobManager(ctx);
      return jm.getStoredResult(org_id, project_id, issue_id);
    }

    // ── reachability.get_all_stored_results ───────────────────────────────
    case 'reachability.get_all_stored_results': {
      const org_id = String(params['org_id'] ?? '').trim();
      if (!org_id) throw new Error('org_id is required');
      
      const jm = getJobManager(ctx);
      return jm.getAllStoredResults(org_id);
    }

    default:
      throw new Error(`Unknown method: ${method}`);
  }
}

// ---------------------------------------------------------------------------
// Streaming methods
// ---------------------------------------------------------------------------

export async function stream(
  method: string,
  params: Record<string, unknown>,
  ctx: InvokeContext,
  onEvent: (eventName: string, data: unknown) => void,
): Promise<unknown> {
  if (process.env.NODE_ENV === 'development') console.log(`[backend] stream method=${method}`);

  switch (method) {
    // ── scanner.scan ──────────────────────────────────────────────────────
    case 'scanner.scan': {
      const org = params['org'] as SnykOrg;
      const token = String(params['token'] ?? '').trim();
      const useCache = params['use_cache'] !== false;

      if (!org || typeof org !== 'object') throw new Error('org is required');
      if (!token) throw new Error('token is required');

      const cache = new CacheManager(ctx.cacheDir);

      // Check cache first
      if (useCache) {
        const cached = cache.load(org.id);
        if (cached) {
          // Load ignored data and merge into results
          const ignoredData = cache.loadIgnoredData(org.id);
          const resultsWithIgnored = cached.results.map(r => {
            const ignored = ignoredData?.[r.id]?.ignored_issues || [];
            const ignoredIssueIds = ignored.map((iss: any) => iss.id || iss.issueData?.id).filter(Boolean);
            return { ...r, ignoredIssueIds };
          });
          return { org, results: resultsWithIgnored, from_cache: true };
        }
      }

      const client = new SnykClient(token);

      // Get included origins and types from config
      const includedOrigins = oauthModule.getIncludedOrigins();
      const includedTypes = oauthModule.getIncludedTypes();
      console.log(`[backend] Included origins from config (empty = all): ${JSON.stringify(includedOrigins)}`);
      console.log(`[backend] Included types from config (empty = all): ${JSON.stringify(includedTypes)}`);

      const results = await scanner.scanOrg(client, org, (progress) => {
        onEvent('progress', progress);
      }, includedOrigins, includedTypes);

      // Save to cache (keeping ignored_issues for filtering in frontend)
      const cacheResults = results.map((r) => {
        const { _ignores_map, ...rest } = r;
        // Keep _ignored_issues but rename to ignoredIssues
        const ignoredIssueIds = (r._ignored_issues || []).map((iss: any) => iss.id || iss.issueData?.id).filter(Boolean);
        return { ...rest, ignoredIssueIds } as ScanResult;
      });

      // Build ignored data map for cache
      const ignoredData: Record<string, { ignored_issues: unknown[]; ignores_map: Record<string, string> }> = {};
      for (const r of results) {
        ignoredData[r.id] = {
          ignored_issues: r._ignored_issues ?? [],
          ignores_map: r._ignores_map ?? {},
        };
      }

      try {
        cache.save(org, cacheResults);
        if (Object.keys(ignoredData).some((k) => ignoredData[k].ignored_issues.length > 0 || Object.keys(ignoredData[k].ignores_map).length > 0)) {
          cache.saveIgnoredData(org.id, ignoredData);
        }
      } catch (err) {
        console.warn('[backend] Failed to save cache:', err);
      }

      return { org, results: cacheResults, from_cache: false };
    }

    // ── ignores.apply ─────────────────────────────────────────────────────
    case 'ignores.apply': {
      const orgId = String(params['org_id'] ?? '').trim();
      const token = String(params['token'] ?? '').trim();
      const operations = (params['operations'] as Array<{ action: 'ignore' | 'unignore'; vuln_id: string; project_id: string }>) ?? [];
      const reason = String(params['reason'] ?? 'No known fix available.');
      const expires =
        String(params['expires'] ?? '') ||
        new Date(Date.now() + 90 * 86400 * 1000).toISOString().replace(/\.\d+Z$/, '.000Z');
      // Defaults to true (matches the Ignore Manager's "no known fix" use case,
      // where it's a no-op anyway). Callers targeting arbitrary/filtered
      // vulnerabilities that might include fixable issues (e.g. Vulnerabilities
      // page "Ignore All") should pass disregard_if_fixable=false so the ignore
      // always sticks regardless of fix availability.
      const disregardIfFixable = params['disregard_if_fixable'] !== false;

      if (!orgId) throw new Error('org_id is required');
      if (!token) throw new Error('token is required');
      if (!Array.isArray(operations)) throw new Error('operations must be a list');

      if (operations.length === 0) return { succeeded: 0, failed: 0 };

      const client = new SnykClient(token);

      return ignores.applyIgnores(client, orgId, operations, reason, expires, (progress) => {
        onEvent('progress', progress);
      }, disregardIfFixable);
    }

    // ── reachability.analyze ──────────────────────────────────────────────
    case 'reachability.analyze': {
      const issue = params['issue'] as Record<string, unknown>;
      const codebasePath = String(params['codebase_path'] ?? '').trim();
      const ollamaModel = String(params['ollama_model'] ?? 'llama3');
      const projectName = String(params['project_name'] ?? '').trim();
      const projectOrigin = String(params['project_origin'] ?? '').trim();
      const githubToken = params['github_token'] ? String(params['github_token']) : null;
      const gheHost = params['ghe_host'] ? String(params['ghe_host']).trim() : undefined;
      const forceReclone = params['force_reclone'] === true;
      const org_id = String(params['org_id'] ?? '').trim();
      const project_id = String(params['project_id'] ?? '').trim();
      const issue_id = String(params['issue_id'] ?? '').trim();
      const background = params['background'] === true;

      if (!issue || typeof issue !== 'object') throw new Error('issue is required');

      // If background mode is enabled and we have IDs, start a background job
      if (background && org_id && project_id && issue_id) {
        const jm = getJobManager(ctx);
        const jobId = await jm.startJob({
          org_id,
          project_id,
          issue_id,
          issue,
          projectName,
          projectOrigin,
          githubToken,
          ollamaModel,
          codebasePath: codebasePath || undefined,
          gheHost,
          forceReclone,
        });
        return { jobId, background: true };
      }

      // If projectName/Origin provided, use full analysis; otherwise fall back to legacy path
      if (projectName || projectOrigin) {
        const analysisResult = await reachability.runFullAnalysis(
          { issue, projectName, projectOrigin, githubToken, ollamaModel, codebasePath: codebasePath || undefined, gheHost, forceReclone },
          (phase, message, pct) => {
            onEvent('progress', { phase, message, pct });
          },
        );
        
        // If we have IDs, save the result to storage
        if (org_id && project_id && issue_id) {
          const jm = getJobManager(ctx);
          jm.saveAnalysisResult(org_id, project_id, issue_id, analysisResult);
        }
        
        // Wrap in { result: ... } so api.ts can do res.result
        return { result: analysisResult };
      }

      // Legacy: codebasePath required
      if (!codebasePath) throw new Error('codebase_path is required');
      return reachability.analyzeReachability(issue, codebasePath, ollamaModel, (progress) => {
        onEvent('scan_progress', progress);
      });
    }

    // ── reachability.get_job_status ───────────────────────────────────────
    case 'reachability.get_job_status': {
      const jobId = String(params['job_id'] ?? '').trim();
      if (!jobId) throw new Error('job_id is required');
      
      const jm = getJobManager(ctx);
      const job = jm.getJob(jobId);
      return job || { error: 'Job not found' };
    }

    // ── reachability.get_stored_result ────────────────────────────────────
    case 'reachability.get_stored_result': {
      const org_id = String(params['org_id'] ?? '').trim();
      const project_id = String(params['project_id'] ?? '').trim();
      const issue_id = String(params['issue_id'] ?? '').trim();
      
      if (!org_id || !project_id || !issue_id) {
        throw new Error('org_id, project_id, and issue_id are required');
      }
      
      const jm = getJobManager(ctx);
      return jm.getStoredResult(org_id, project_id, issue_id);
    }

    // ── reachability.get_all_stored_results ───────────────────────────────
    case 'reachability.get_all_stored_results': {
      const org_id = String(params['org_id'] ?? '').trim();
      if (!org_id) throw new Error('org_id is required');
      
      const jm = getJobManager(ctx);
      return jm.getAllStoredResults(org_id);
    }

    // ── oauth.start_snyk_oauth ────────────────────────────────────────────
    case 'oauth.start_snyk_oauth': {
      return oauthModule.startSnykOAuth((msg) => {
        onEvent('progress', { event: 'progress', data: { msg } });
      }).then((result) => {
        return { result };
      });
    }

    // ── oauth.poll_github ─────────────────────────────────────────────────
    case 'oauth.poll_github': {
      const device_code = String(params['device_code'] ?? '').trim();
      const interval = Number(params['interval'] ?? 5);
      if (!device_code) throw new Error('device_code is required');
      return oauthModule.pollGitHubToken(device_code, interval, (msg) => {
        onEvent('progress', { event: 'progress', data: { msg } });
      }).then((result) => {
        return { result };
      });
    }

    // ── ollama.pull_model ─────────────────────────────────────────────────
    case 'ollama.pull_model': {
      const name = String(params['name'] ?? '').trim();
      if (!name) throw new Error('name is required');
      await ollamaModule.pullModel(name, (msg) => {
        onEvent('progress', { msg });
      });
      return { ok: true };
    }

    // ── github.clone_repo ─────────────────────────────────────────────────
    case 'github.clone_repo': {
      const projectName = String(params['project_name'] ?? '').trim();
      const projectOrigin = String(params['project_origin'] ?? '').trim();
      const githubToken = params['github_token'] ? String(params['github_token']) : null;

      if (!projectName && !projectOrigin) throw new Error('project_name or project_origin is required');

      const extracted = githubModule.extractRepoFromProject(projectName, projectOrigin);
      if (!extracted) throw new Error(`Cannot extract repo from project "${projectName}"`);

      const repoInfo = await githubModule.getRepoInfo(extracted.owner, extracted.repo, githubToken);
      const branch = githubModule.extractBranchFromProject(projectName);
      const repoForClone = branch ? { ...repoInfo, defaultBranch: branch } : repoInfo;

      const localPath = await githubModule.cloneOrUpdateRepo(repoForClone, githubToken, (msg) => {
        onEvent('progress', { msg });
      });

      return { path: localPath, repo: repoInfo.fullName };
    }

    default:
      // Fall through to non-streaming invoke for methods that don't need streaming
      return invoke(method, params, ctx);
  }
}
