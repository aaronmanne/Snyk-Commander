/**
 * src/backend/reachabilityStorage.ts — Persistent storage for reachability analysis results
 */

import * as fs from 'fs';
import * as path from 'path';

export interface ReachabilityResult {
  issue_id: string;
  project_id: string;
  org_id: string;
  verdict: string;
  ollama_reasoning: string | null;
  matches: Array<{
    file: string;
    line: number;
    content: string;
    match_type: string;
  }>;
  import_count: number;
  func_count: number;
  repo_cloned: boolean;
  repo_path: string;
  repo_info: { owner: string; repo: string; branch: string | null } | null;
  error_details: string | null;
  analyzed_at: string;
}

export class ReachabilityStorage {
  constructor(private storageDir: string) {}

  private ensureDir(): void {
    if (!fs.existsSync(this.storageDir)) {
      fs.mkdirSync(this.storageDir, { recursive: true });
    }
  }

  private getFilePath(org_id: string): string {
    return path.join(this.storageDir, `reachability_${org_id}.json`);
  }

  /**
   * Save or update a reachability result
   */
  save(org_id: string, result: ReachabilityResult): void {
    this.ensureDir();
    const filePath = this.getFilePath(org_id);
    
    // Load existing results
    const existing = this.loadAll(org_id);
    
    // Find and update or add new
    const key = `${result.project_id}:${result.issue_id}`;
    const index = existing.findIndex(r => `${r.project_id}:${r.issue_id}` === key);
    
    if (index >= 0) {
      existing[index] = result;
    } else {
      existing.push(result);
    }
    
    // Save back
    fs.writeFileSync(filePath, JSON.stringify(existing, null, 2), 'utf8');
  }

  /**
   * Load all reachability results for an org
   */
  loadAll(org_id: string): ReachabilityResult[] {
    const filePath = this.getFilePath(org_id);
    if (!fs.existsSync(filePath)) return [];
    
    try {
      const raw = fs.readFileSync(filePath, 'utf8');
      return JSON.parse(raw) as ReachabilityResult[];
    } catch {
      return [];
    }
  }

  /**
   * Load a specific result
   */
  load(org_id: string, project_id: string, issue_id: string): ReachabilityResult | null {
    const all = this.loadAll(org_id);
    return all.find(r => r.project_id === project_id && r.issue_id === issue_id) || null;
  }

  /**
   * Load results for a specific project
   */
  loadByProject(org_id: string, project_id: string): ReachabilityResult[] {
    const all = this.loadAll(org_id);
    return all.filter(r => r.project_id === project_id);
  }

  /**
   * Delete a specific result
   */
  delete(org_id: string, project_id: string, issue_id: string): void {
    const all = this.loadAll(org_id);
    const filtered = all.filter(r => !(r.project_id === project_id && r.issue_id === issue_id));
    
    const filePath = this.getFilePath(org_id);
    fs.writeFileSync(filePath, JSON.stringify(filtered, null, 2), 'utf8');
  }

  /**
   * Delete all results for an org
   */
  deleteAll(org_id: string): void {
    const filePath = this.getFilePath(org_id);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  }
}
