/**
 * src/backend/reachabilityJobs.ts — Background job manager for reachability analysis
 */

import * as reachability from './reachability';
import { ReachabilityStorage, type ReachabilityResult } from './reachabilityStorage';

interface AnalysisJob {
  id: string;
  org_id: string;
  project_id: string;
  issue_id: string;
  issue: Record<string, unknown>;
  projectName: string;
  projectOrigin: string;
  githubToken: string | null;
  ollamaModel: string;
  codebasePath?: string;
  gheHost?: string;
  forceReclone: boolean;
  status: 'queued' | 'running' | 'completed' | 'failed';
  progress: { phase: string; message: string; pct: number };
  result?: unknown;
  error?: string;
  startedAt?: number;
  completedAt?: number;
}

export class ReachabilityJobManager {
  private jobs: Map<string, AnalysisJob> = new Map();
  private storage: ReachabilityStorage;

  constructor(storageDir: string) {
    this.storage = new ReachabilityStorage(storageDir);
  }

  /**
   * Start a new analysis job in the background
   */
  async startJob(params: {
    org_id: string;
    project_id: string;
    issue_id: string;
    issue: Record<string, unknown>;
    projectName: string;
    projectOrigin: string;
    githubToken: string | null;
    ollamaModel: string;
    codebasePath?: string;
    gheHost?: string;
    forceReclone: boolean;
  }): Promise<string> {
    const jobId = `${params.project_id}:${params.issue_id}`;
    
    // If job already running, return existing job ID
    if (this.jobs.has(jobId) && this.jobs.get(jobId)!.status === 'running') {
      return jobId;
    }

    const job: AnalysisJob = {
      id: jobId,
      org_id: params.org_id,
      project_id: params.project_id,
      issue_id: params.issue_id,
      issue: params.issue,
      projectName: params.projectName,
      projectOrigin: params.projectOrigin,
      githubToken: params.githubToken,
      ollamaModel: params.ollamaModel,
      codebasePath: params.codebasePath,
      gheHost: params.gheHost,
      forceReclone: params.forceReclone,
      status: 'queued',
      progress: { phase: 'queued', message: 'Queued for analysis', pct: 0 },
    };

    this.jobs.set(jobId, job);

    // Run analysis in background
    this.runJobInBackground(jobId).catch((err) => {
      console.error(`[reachability-jobs] Job ${jobId} failed:`, err);
      const j = this.jobs.get(jobId);
      if (j) {
        j.status = 'failed';
        j.error = err instanceof Error ? err.message : String(err);
        j.completedAt = Date.now();
      }
    });

    return jobId;
  }

  /**
   * Run the analysis job in the background
   */
  private async runJobInBackground(jobId: string): Promise<void> {
    const job = this.jobs.get(jobId);
    if (!job) return;

    job.status = 'running';
    job.startedAt = Date.now();

    try {
      const analysisResult = await reachability.runFullAnalysis(
        {
          issue: job.issue,
          projectName: job.projectName,
          projectOrigin: job.projectOrigin,
          githubToken: job.githubToken,
          ollamaModel: job.ollamaModel,
          codebasePath: job.codebasePath,
          gheHost: job.gheHost,
          forceReclone: job.forceReclone,
        },
        (phase, message, pct) => {
          job.progress = { phase, message, pct };
        }
      );

      job.status = 'completed';
      job.result = analysisResult;
      job.completedAt = Date.now();

      // Save to persistent storage
      this.saveResult(job.org_id, job.project_id, job.issue_id, analysisResult);
    } catch (err) {
      job.status = 'failed';
      job.error = err instanceof Error ? err.message : String(err);
      job.completedAt = Date.now();
      throw err;
    }
  }

  /**
   * Save analysis result to persistent storage
   */
  private saveResult(org_id: string, project_id: string, issue_id: string, analysisResult: any): void {
    const result: ReachabilityResult = {
      issue_id,
      project_id,
      org_id,
      verdict: analysisResult.verdict || 'UNKNOWN',
      ollama_reasoning: analysisResult.ollama_reasoning || null,
      matches: analysisResult.matches || [],
      import_count: analysisResult.import_count || 0,
      func_count: analysisResult.func_count || 0,
      repo_cloned: analysisResult.repo_cloned || false,
      repo_path: analysisResult.repo_path || '',
      repo_info: analysisResult.repo_info || null,
      error_details: analysisResult.error_details || null,
      analyzed_at: new Date().toISOString(),
    };

    this.storage.save(org_id, result);
  }

  /**
   * Public method to save analysis result (can be called from outside)
   */
  saveAnalysisResult(org_id: string, project_id: string, issue_id: string, analysisResult: any): void {
    this.saveResult(org_id, project_id, issue_id, analysisResult);
  }

  /**
   * Get job status
   */
  getJob(jobId: string): AnalysisJob | null {
    return this.jobs.get(jobId) || null;
  }

  /**
   * Get all jobs
   */
  getAllJobs(): AnalysisJob[] {
    return Array.from(this.jobs.values());
  }

  /**
   * Get stored analysis result
   */
  getStoredResult(org_id: string, project_id: string, issue_id: string): ReachabilityResult | null {
    return this.storage.load(org_id, project_id, issue_id);
  }

  /**
   * Get all stored results for an org
   */
  getAllStoredResults(org_id: string): ReachabilityResult[] {
    return this.storage.loadAll(org_id);
  }

  /**
   * Get stored results for a project
   */
  getStoredResultsByProject(org_id: string, project_id: string): ReachabilityResult[] {
    return this.storage.loadByProject(org_id, project_id);
  }

  /**
   * Clear completed jobs from memory (keeps storage)
   */
  clearCompletedJobs(): void {
    for (const [id, job] of this.jobs.entries()) {
      if (job.status === 'completed' || job.status === 'failed') {
        // Keep jobs for 5 minutes after completion
        if (job.completedAt && Date.now() - job.completedAt > 5 * 60 * 1000) {
          this.jobs.delete(id);
        }
      }
    }
  }
}
