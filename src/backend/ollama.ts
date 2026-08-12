/**
 * src/backend/ollama.ts — Ollama model management.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface OllamaModel {
  name: string;
  size: number;
  modified_at: string;
  details?: {
    family: string;
    parameter_size: string;
    quantization_level: string;
  };
}

export interface OllamaStatus {
  available: boolean;
  version: string | null;
  models: OllamaModel[];
  error: string | null;
}

const OLLAMA_BASE = 'http://localhost:11434';
const OLLAMA_TIMEOUT = 120_000;

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

export async function getOllamaStatus(): Promise<OllamaStatus> {
  try {
    // Check version
    const versionResp = await fetchWithTimeout(`${OLLAMA_BASE}/api/version`, {}, 5000);
    let version: string | null = null;
    if (versionResp.ok) {
      const vData = (await versionResp.json()) as { version?: string };
      version = vData.version ?? null;
    }

    // List models
    const tagsResp = await fetchWithTimeout(`${OLLAMA_BASE}/api/tags`, {}, 5000);
    if (!tagsResp.ok) {
      return { available: true, version, models: [], error: `Tags endpoint returned ${tagsResp.status}` };
    }

    const tagsData = (await tagsResp.json()) as {
      models?: Array<{
        name: string;
        size: number;
        modified_at: string;
        details?: {
          family: string;
          parameter_size: string;
          quantization_level: string;
        };
      }>;
    };

    const models: OllamaModel[] = (tagsData.models ?? []).map((m) => ({
      name: m.name,
      size: m.size,
      modified_at: m.modified_at,
      details: m.details,
    }));

    return { available: true, version, models, error: null };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const isConnRefused = msg.includes('ECONNREFUSED') || msg.includes('fetch failed') || msg.includes('connect');
    return {
      available: false,
      version: null,
      models: [],
      error: isConnRefused ? 'Ollama is not running (connection refused)' : msg,
    };
  }
}

// ---------------------------------------------------------------------------
// Pull
// ---------------------------------------------------------------------------

export async function pullModel(
  name: string,
  onProgress?: (msg: string) => void,
): Promise<void> {
  onProgress?.(`Pulling model: ${name}...`);

  const resp = await fetchWithTimeout(
    `${OLLAMA_BASE}/api/pull`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, stream: false }),
    },
    OLLAMA_TIMEOUT,
  );

  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    throw new Error(`Failed to pull model "${name}" (${resp.status}): ${text}`);
  }

  const data = (await resp.json()) as { status?: string; error?: string };
  if (data.error) throw new Error(`Ollama pull error: ${data.error}`);

  onProgress?.(`Model "${name}" pulled successfully (status: ${data.status ?? 'done'})`);
}

// ---------------------------------------------------------------------------
// Generate
// ---------------------------------------------------------------------------

export async function generate(
  model: string,
  prompt: string,
  timeoutMs: number = OLLAMA_TIMEOUT,
): Promise<string | null> {
  try {
    const resp = await fetchWithTimeout(
      `${OLLAMA_BASE}/api/generate`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model, prompt, stream: false }),
      },
      timeoutMs,
    );

    if (!resp.ok) return null;
    const data = (await resp.json()) as { response?: string };
    return data.response ?? null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Fetch with timeout
// ---------------------------------------------------------------------------

function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, { ...init, signal: controller.signal }).finally(() => clearTimeout(timer));
}
