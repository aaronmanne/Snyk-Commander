/**
 * src/backend/fixPr.ts — Trigger fix PRs via Snyk HTTP API.
 */

export async function triggerFixPr(
  token: string,
  orgSlug: string,
  projectId: string,
): Promise<{ ok: boolean; message: string }> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30_000);

    const resp = await fetch(
      `https://app.snyk.io/registry/org/${orgSlug}/fix-request/v2/${projectId}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `snyk-token=${token}`,
          Authorization: `token ${token}`,
        },
        body: JSON.stringify({}),
        signal: controller.signal,
      },
    );

    clearTimeout(timer);
    return { ok: resp.ok, message: `${resp.status} ${resp.statusText}` };
  } catch (err) {
    return { ok: false, message: String(err) };
  }
}
