/**
 * src/backend/reachability.ts — Codebase static analysis + Ollama LLM reasoning.
 * Ported from snyk-commander/reachability.py
 */

import * as fs from 'fs';
import * as path from 'path';
import { extractRepoFromProject, extractBranchFromProject, getRepoInfo, cloneOrUpdateRepoDirect, checkRepoAccess, repoLocalPath } from './github';
import { generate as ollamaGenerate } from './ollama';
import { getStoredGHEHost } from './oauth';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const MATCH_IMPORT = 'import/require';
export const MATCH_FUNC = 'function call';

const SKIP_DIRS = new Set([
  '.git', 'node_modules', 'vendor', '.venv', 'venv', '__pycache__',
  'dist', 'build', '.idea', 'target', '.tox', '.mypy_cache', '.pytest_cache',
]);

const MAX_FILE_BYTES = 50 * 1024; // 50 KB
const OLLAMA_URL = 'http://localhost:11434/api/generate';
const OLLAMA_TIMEOUT = 120_000;

// ---------------------------------------------------------------------------
// Pattern building
// ---------------------------------------------------------------------------

export function normalisePkg(name: string): string[] {
  const variants = new Set<string>();

  // Strip version suffix: pkg@1.2.3 → pkg
  const base = name.replace(/@[\d.].*/g, '').trim();
  if (!base) return [name];

  variants.add(base);

  // strip npm scope: @scope/pkg → pkg
  if (base.startsWith('@') && base.includes('/')) {
    variants.add(base.split('/')[1]);
  }

  // hyphens ↔ underscores
  for (const v of [...variants]) {
    variants.add(v.replace(/-/g, '_'));
    variants.add(v.replace(/_/g, '-'));
  }

  // lowercase all variants
  for (const v of [...variants]) variants.add(v.toLowerCase());

  return [...variants];
}

export function buildImportPatterns(variants: string[]): RegExp[] {
  const patterns: RegExp[] = [];
  for (const v of variants) {
    const e = escapeRegex(v);
    patterns.push(
      // Python: import pkg / import pkg.sub
      new RegExp(`\\bimport\\s+${e}(\\s|$|\\.|;)`, 'i'),
      // Python: from pkg import ...
      new RegExp(`\\bfrom\\s+${e}(\\s|\\.|;)`, 'i'),
      // JS/TS: require('pkg') / require("pkg")
      new RegExp(`require\\s*\\(\\s*['"]${e}['"]\\s*\\)`, 'i'),
      // JS/TS: import ... from 'pkg'
      new RegExp(`import\\s.*from\\s+['"]${e}['"]`, 'i'),
      // JS/TS: import 'pkg'
      new RegExp(`import\\s+['"]${e}['"]`, 'i'),
      // Go: import "pkg" / "pkg/"
      new RegExp(`"${e}[/"]`, 'i'),
      // Java/C#: import pkg; / using pkg;
      new RegExp(`\\b(?:import|using)\\s+${e}(\\s|;|\\.|$)`, 'i'),
      // PHP: use Pkg\
      new RegExp(`\\buse\\s+${e}\\\\`, 'i'),
      // Ruby: require 'pkg' / require "pkg"
      new RegExp(`require(?:_relative)?\\s+['"]${e}['"]`, 'i'),
    );
  }
  return patterns;
}

export function extractFunctionNames(issue: Record<string, unknown>): string[] {
  const issueData = (issue['issueData'] as Record<string, unknown>) ?? {};
  // functions may live at issueData.functions or issue.functions
  const functionsRaw = ((issueData['functions'] ?? issue['functions']) as unknown[]) ?? [];
  const names: string[] = [];

  for (const f of functionsRaw) {
    if (typeof f === 'string') {
      names.push(f);
    } else if (typeof f === 'object' && f !== null) {
      const fObj = f as Record<string, unknown>;
      const fnId = fObj['functionId'];
      if (typeof fnId === 'string' && fnId) {
        names.push(fnId);
      } else if (typeof fnId === 'object' && fnId !== null) {
        const fnIdObj = fnId as Record<string, unknown>;
        const name = fnIdObj['functionName'];
        if (typeof name === 'string' && name) names.push(name);
      }
      // Also handle { functionName: '...' } directly on the object
      const directName = fObj['functionName'];
      if (typeof directName === 'string' && directName) names.push(directName);
    }
  }

  return [...new Set(names.filter(Boolean))];
}

export function buildFunctionPatterns(names: string[]): RegExp[] {
  return names.map((name) => {
    const bare = name.split('.').pop() ?? name;
    return new RegExp(`\\b${escapeRegex(bare)}\\s*\\(`, 'i');
  });
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ---------------------------------------------------------------------------
// File walker
// ---------------------------------------------------------------------------

function shouldSkipDir(d: string): boolean {
  return SKIP_DIRS.has(d) || d.startsWith('.');
}

export function* walkFiles(dir: string): Generator<string> {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!shouldSkipDir(entry.name)) yield* walkFiles(fullPath);
    } else if (entry.isFile()) {
      yield fullPath;
    }
  }
}

// ---------------------------------------------------------------------------
// File scanner
// ---------------------------------------------------------------------------

export interface ReachabilityMatch {
  file: string;
  line: number;
  content: string;
  match_type: string;
}

export function scanFile(
  filepath: string,
  importPatterns: RegExp[],
  funcPatterns: RegExp[],
  _variants: string[],
): ReachabilityMatch[] {
  const matches: ReachabilityMatch[] = [];
  let raw: string;

  try {
    const buf = Buffer.alloc(MAX_FILE_BYTES);
    const fd = fs.openSync(filepath, 'r');
    const bytesRead = fs.readSync(fd, buf, 0, MAX_FILE_BYTES, 0);
    fs.closeSync(fd);
    raw = buf.slice(0, bytesRead).toString('utf8');
  } catch {
    return matches;
  }

  const lines = raw.split('\n');
  const matchedImportLines = new Set<number>();

  for (let i = 0; i < lines.length; i++) {
    const lineno = i + 1;
    const line = lines[i];
    const stripped = line.trim();
    if (!stripped || stripped.startsWith('#') || stripped.startsWith('//')) continue;

    // --- import / require ---
    let importMatched = false;
    for (const pat of importPatterns) {
      if (pat.test(line)) {
        matches.push({ file: filepath, line: lineno, content: stripped.substring(0, 200), match_type: MATCH_IMPORT });
        matchedImportLines.add(lineno);
        importMatched = true;
        break;
      }
    }
    if (importMatched) continue;

    // --- function calls ---
    for (const pat of funcPatterns) {
      if (pat.test(line)) {
        matches.push({ file: filepath, line: lineno, content: stripped.substring(0, 200), match_type: MATCH_FUNC });
        break;
      }
    }
  }

  return matches;
}

// ---------------------------------------------------------------------------
// Ollama
// ---------------------------------------------------------------------------

export async function queryOllama(model: string, prompt: string): Promise<string | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), OLLAMA_TIMEOUT);

    const resp = await fetch(OLLAMA_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, prompt, stream: false }),
      signal: controller.signal,
    });

    clearTimeout(timer);
    if (!resp.ok) return null;

    const data = (await resp.json()) as { response?: string };
    return data.response ?? null;
  } catch (err: unknown) {
    const e = err as Error;
    if (e?.name === 'AbortError') return null;
    // Connection refused → return null
    return null;
  }
}

export function buildOllamaPrompt(
  issue: Record<string, unknown>,
  pkgName: string,
  funcNames: string[],
  matches: ReachabilityMatch[],
): string {
  const issueData = (issue['issueData'] as Record<string, unknown>) ?? {};
  const title     = (issueData['title']       as string) ?? 'Unknown';
  const vulnId    = (issueData['id']          as string) ?? 'Unknown';
  const severity  = (issueData['severity']    as string) ?? 'unknown';
  const description = (issueData['description'] as string) ?? 'No description available.';
  const cvss      = (issueData['CVSSv3'] as string) ?? (issueData['cvssScore'] as string) ?? 'N/A';

  const importMatches = matches.filter(m => m.match_type === MATCH_IMPORT);
  const funcMatches   = matches.filter(m => m.match_type === MATCH_FUNC);

  const formatMatches = (ms: ReachabilityMatch[]) =>
    ms.slice(0, 30).map(m =>
      `  - ${m.file}:${m.line}\n    \`${m.content.trim()}\``
    ).join('\n') || '  (none)';

  const funcsText = funcNames.length > 0
    ? funcNames.map(f => `\`${f}\``).join(', ')
    : '*(not specified by Snyk — check import usage)*';

  return `You are a security engineer performing **reachability analysis** on a software project.

Your ONLY goal is to answer one question:

> **Is the vulnerable function from the package \`${pkgName}\` actually called anywhere in this project's source code?**

---

## Vulnerability

| Field | Value |
|-------|-------|
| ID | ${vulnId} |
| Title | ${title} |
| Severity | ${severity.toUpperCase()} |
| CVSS | ${cvss} |
| Package | \`${pkgName}\` |
| Vulnerable function(s) | ${funcsText} |

**Description:** ${description}

---

## Evidence Found in Project Source Code

### Import / Require statements (${importMatches.length} found)
These lines show the package is imported into the project:
${formatMatches(importMatches)}

### Function call references (${funcMatches.length} found)
These lines show calls that may invoke the vulnerable function:
${formatMatches(funcMatches)}

---

## Instructions

Analyze the evidence above and answer these questions in order:

### 1. Is the package imported?
State clearly: Yes / No / Partially. List the files where it is imported.

### 2. Are the vulnerable functions called?
For each vulnerable function (${funcsText}), state whether it appears to be called and in which files/lines.
If no vulnerable functions are listed, assess whether the way the package is used could trigger the vulnerability based on the description.

### 3. Is the vulnerable code path reachable?
Explain your reasoning. Consider:
- Is the import followed by actual usage, or just declared?
- Do the function calls match the known vulnerable functions exactly, or are they coincidentally named?
- Is there enough context to determine if user-controlled input flows into the vulnerable function?

### 4. Finding locations
If the vulnerability IS reachable, list the **exact file paths and line numbers** where the vulnerable code is called.

### 5. Verdict
End with EXACTLY one of:

**VERDICT: LIKELY REACHABLE** — The vulnerable function is imported AND called in the project.
**VERDICT: LIKELY NOT REACHABLE** — The package is imported but the vulnerable function is not called, or the package is not imported at all.
**VERDICT: INCONCLUSIVE** — There is insufficient evidence to determine reachability.
`;
}

export function extractVerdict(text: string): string {
  const upper = text.toUpperCase();
  if (upper.includes('VERDICT: LIKELY NOT REACHABLE') || upper.includes('LIKELY NOT REACHABLE') || upper.includes('NOT REACHABLE'))
    return 'NOT REACHABLE';
  if (upper.includes('VERDICT: LIKELY REACHABLE') || upper.includes('LIKELY REACHABLE'))
    return 'LIKELY REACHABLE';
  return 'INCONCLUSIVE';
}

// ---------------------------------------------------------------------------
// Main analyser
// ---------------------------------------------------------------------------

export async function analyzeReachability(
  issue: Record<string, unknown>,
  codebasePath: string,
  ollamaModel: string,
  onProgress: (p: { file: string; done: number; total: number }) => void,
): Promise<{
  matches: ReachabilityMatch[];
  import_count: number;
  func_count: number;
  verdict: string;
  ollama_reasoning: string | null;
}> {
  const issueData = (issue['issueData'] as Record<string, unknown>) ?? {};
  const pkgName =
    ((issueData['packageName'] as string) || (issue['pkgName'] as string) || '').trim() || 'unknown';

  const pkgVariants = normalisePkg(pkgName);
  const importPatterns = buildImportPatterns(pkgVariants);
  const funcNames = extractFunctionNames(issue);
  const funcPatterns = buildFunctionPatterns(funcNames);

  const allFiles = [...walkFiles(codebasePath)];
  const totalFiles = allFiles.length;
  const allMatches: ReachabilityMatch[] = [];

  for (let idx = 0; idx < allFiles.length; idx++) {
    const filepath = allFiles[idx];
    const fileMatches = scanFile(filepath, importPatterns, funcPatterns, pkgVariants);
    allMatches.push(...fileMatches);

    if ((idx + 1) % 50 === 0 || idx + 1 === totalFiles) {
      onProgress({ file: path.basename(filepath), done: idx + 1, total: totalFiles });
    }
  }

  const importCount = allMatches.filter((m) => m.match_type === MATCH_IMPORT).length;
  const funcCount = allMatches.filter((m) => m.match_type === MATCH_FUNC).length;

  let verdict = 'INCONCLUSIVE';
  let ollamaReasoning: string | null = null;

  if (allMatches.length === 0) {
    verdict = 'NOT REACHABLE';
  } else {
    const promptText = buildOllamaPrompt(issue, pkgName, funcNames, allMatches);
    const responseText = await queryOllama(ollamaModel, promptText);

    if (responseText) {
      verdict = extractVerdict(responseText);
      ollamaReasoning = responseText;
    } else {
      // Heuristic fallback
      if (funcCount > 0) verdict = 'LIKELY REACHABLE';
      else if (importCount > 0) verdict = 'INCONCLUSIVE';
      else verdict = 'NOT REACHABLE';
    }
  }

  return {
    matches: allMatches,
    import_count: importCount,
    func_count: funcCount,
    verdict,
    ollama_reasoning: ollamaReasoning,
  };
}

// ---------------------------------------------------------------------------
// Full end-to-end analysis (clone + scan + Ollama)
// ---------------------------------------------------------------------------

export interface ReachabilityAnalysisParams {
  issue: Record<string, unknown>;
  projectName: string;
  projectOrigin: string;
  githubToken: string | null;
  ollamaModel: string;
  codebasePath?: string;
  gheHost?: string;
  forceReclone?: boolean;        // If true, delete cached repo dir before cloning
}

export interface ReachabilityAnalysisResult {
  matches: ReachabilityMatch[];
  import_count: number;
  func_count: number;
  verdict: string;
  ollama_reasoning: string | null;
  repo_cloned: boolean;
  repo_path: string;
  repo_info: { owner: string; repo: string; branch: string | null } | null;
  error_details: string | null;
}

export async function runFullAnalysis(
  params: ReachabilityAnalysisParams,
  onProgress: (phase: string, message: string, pct?: number) => void,
): Promise<ReachabilityAnalysisResult> {
  let codebasePath = params.codebasePath ?? '';
  let repoCloned = false;
  let repoInfo: { owner: string; repo: string; branch: string | null } | null = null;
  let errorDetails: string | null = null;

  if (!codebasePath) {
    // Phase: resolving
    onProgress('resolving', 'Extracting repository info from project...', 0);
    const extracted = extractRepoFromProject(params.projectName, params.projectOrigin);

    if (!extracted) {
      errorDetails = `Cannot determine GitHub repo from project "${params.projectName}" (origin: "${params.projectOrigin}"). Provide codebasePath to skip cloning.`;
      onProgress('error', errorDetails, 0);
      return {
        matches: [],
        import_count: 0,
        func_count: 0,
        verdict: 'INCONCLUSIVE',
        ollama_reasoning: null,
        repo_cloned: false,
        repo_path: '',
        repo_info: null,
        error_details: errorDetails,
      };
    }

    const branch = extractBranchFromProject(params.projectName);
    repoInfo = { owner: extracted.owner, repo: extracted.repo, branch };
    onProgress('resolving', `Resolved repo: ${extracted.owner}/${extracted.repo}${branch ? ` (branch: ${branch})` : ''}`, 5);

    // Phase: cloning
    const gheHost = params.gheHost ?? getStoredGHEHost() ?? null;

    // If forceReclone, wipe the cached repo dir so cloneOrUpdateRepoDirect does a fresh clone
    if (params.forceReclone) {
      const localPath = repoLocalPath(extracted.owner, extracted.repo);
      if (fs.existsSync(localPath)) {
        onProgress('resolving', `Deleting cached repo at ${localPath}...`, 6);
        fs.rmSync(localPath, { recursive: true, force: true });
      }
    }

    // Try to get default branch from GitHub API (best-effort, skip on error)
    let targetBranch: string | null = branch;

    if (!targetBranch) {
      onProgress('cloning', `Fetching default branch from GitHub API...`, 10);
      try {
        const repoDetails = await getRepoInfo(extracted.owner, extracted.repo, params.githubToken);
        targetBranch = repoDetails.defaultBranch;
        onProgress('cloning', `Default branch: ${targetBranch}`, 12);
      } catch {
        onProgress('cloning', `API lookup skipped — will clone default branch directly`, 12);
      }
    }

    const hostLabel = gheHost ? ` from ${gheHost}` : '';
    onProgress('cloning', `Checking repository access...`, 12);

    // Pre-flight access check — catches OAuth App restrictions and SSO issues
    // before wasting time on a git clone that will just say "Repository not found"
    const accessError = await checkRepoAccess(extracted.owner, extracted.repo, params.githubToken);
    if (accessError) {
      errorDetails = accessError;
      onProgress('error', errorDetails, 0);
      return {
        matches: [], import_count: 0, func_count: 0,
        verdict: 'INCONCLUSIVE', ollama_reasoning: null,
        repo_cloned: false, repo_path: '', repo_info: repoInfo, error_details: errorDetails,
      };
    }

    onProgress('cloning', `Cloning ${extracted.owner}/${extracted.repo}${hostLabel}...`, 15);
    try {
      codebasePath = await cloneOrUpdateRepoDirect(
        extracted.owner,
        extracted.repo,
        targetBranch,
        params.githubToken,
        gheHost,
        (msg) => { onProgress('cloning', msg, 20); },
      );
      repoCloned = true;
      onProgress('cloning', `Repository ready at ${codebasePath}`, 30);
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      // Give a helpful hint if the clone failed — could be GHE host needed
      const hint = !gheHost
        ? ' If this repo is on a private GitHub Enterprise Server, configure the GHE hostname in Settings.'
        : '';
      errorDetails = `Clone failed: ${errMsg}${hint}`;
      onProgress('error', errorDetails, 0);
      return {
        matches: [],
        import_count: 0,
        func_count: 0,
        verdict: 'INCONCLUSIVE',
        ollama_reasoning: null,
        repo_cloned: false,
        repo_path: '',
        repo_info: repoInfo,
        error_details: errorDetails,
      };
    }
  }

  // Phase: scanning
  onProgress('scanning', `Scanning codebase at ${codebasePath}...`, 35);

  const issueData = (params.issue['issueData'] as Record<string, unknown>) ?? {};
  const pkgName =
    ((issueData['packageName'] as string) || (params.issue['pkgName'] as string) || '').trim() || 'unknown';
  const pkgVariants = normalisePkg(pkgName);
  const importPatterns = buildImportPatterns(pkgVariants);
  const funcNames = extractFunctionNames(params.issue);
  const funcPatterns = buildFunctionPatterns(funcNames);

  const allFiles = [...walkFiles(codebasePath)];
  const totalFiles = allFiles.length;
  const allMatches: ReachabilityMatch[] = [];

  for (let idx = 0; idx < allFiles.length; idx++) {
    const filepath = allFiles[idx];
    const fileMatches = scanFile(filepath, importPatterns, funcPatterns, pkgVariants);
    allMatches.push(...fileMatches);

    if ((idx + 1) % 50 === 0 || idx + 1 === totalFiles) {
      const pct = 35 + Math.floor(((idx + 1) / totalFiles) * 40);
      onProgress('scanning', `Scanned ${idx + 1}/${totalFiles} files (${path.basename(filepath)})`, pct);
    }
  }

  const importCount = allMatches.filter((m) => m.match_type === MATCH_IMPORT).length;
  const funcCount = allMatches.filter((m) => m.match_type === MATCH_FUNC).length;
  onProgress('scanning', `Scan complete: ${allMatches.length} matches (${importCount} imports, ${funcCount} calls)`, 75);

  // Phase: analyzing
  let verdict = 'INCONCLUSIVE';
  let ollamaReasoning: string | null = null;

  if (allMatches.length === 0) {
    verdict = 'NOT REACHABLE';
    onProgress('analyzing', 'No code references found — marking as likely not reachable', 80);
  } else {
    onProgress('analyzing', `Sending ${allMatches.length} matches to Ollama model "${params.ollamaModel}"...`, 80);
    const promptText = buildOllamaPrompt(params.issue, pkgName, funcNames, allMatches);
    const responseText = await ollamaGenerate(params.ollamaModel, promptText, OLLAMA_TIMEOUT);

    if (responseText) {
      verdict = extractVerdict(responseText);
      ollamaReasoning = responseText;
      onProgress('analyzing', `Ollama verdict: ${verdict}`, 95);
    } else {
      if (funcCount > 0) verdict = 'LIKELY REACHABLE';
      else if (importCount > 0) verdict = 'INCONCLUSIVE';
      else verdict = 'NOT REACHABLE';
      onProgress('analyzing', `Ollama unavailable — using heuristic verdict: ${verdict}`, 95);
    }
  }

  onProgress('complete', `Analysis complete: ${verdict}`, 100);

  return {
    matches: allMatches,
    import_count: importCount,
    func_count: funcCount,
    verdict,
    ollama_reasoning: ollamaReasoning,
    repo_cloned: repoCloned,
    repo_path: codebasePath,
    repo_info: repoInfo,
    error_details: errorDetails,
  };
}
