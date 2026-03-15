import { readFile, writeFile, mkdir, rename, unlink, open } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import { randomUUID } from "node:crypto";
import type { TrustRule, SessionFile } from "./types.js";

const SESSIONS_DIR = join(homedir(), ".config", "trustengine", "sessions");

function validate_session_id(session_id: string): void {
    if (!/^[a-zA-Z0-9-]+$/.test(session_id)) {
        throw new Error(
            `Invalid session_id: "${session_id}" — must match [a-zA-Z0-9-]`,
        );
    }
}

function session_path(session_id: string): string {
    validate_session_id(session_id);
    return join(SESSIONS_DIR, `${session_id}.json`);
}

async function ensure_sessions_dir(): Promise<void> {
    await mkdir(SESSIONS_DIR, { recursive: true });
}

async function atomic_write(path: string, data: string): Promise<void> {
    const tmp_path = `${path}.${randomUUID()}.tmp`;
    await writeFile(tmp_path, data, "utf-8");
    await rename(tmp_path, path);
}

async function with_file_lock<T>(
    lock_path: string,
    fn: () => Promise<T>,
    retries = 5,
    delay_ms = 50,
): Promise<T> {
    for (let attempt = 0; attempt < retries; attempt++) {
        let handle;
        try {
            // O_CREAT | O_EXCL — fails if the lock file already exists
            handle = await open(lock_path, "wx");
            await handle.close();
            try {
                return await fn();
            } finally {
                await unlink(lock_path).catch(() => {});
            }
        } catch (err: unknown) {
            if (handle) await handle.close().catch(() => {});
            if ((err as NodeJS.ErrnoException).code === "EEXIST") {
                // Lock held by another process — wait and retry
                await new Promise((r) => setTimeout(r, delay_ms * (attempt + 1)));
                continue;
            }
            throw err;
        }
    }
    // Final attempt — force-remove stale lock and try once more
    await unlink(lock_path).catch(() => {});
    return fn();
}

export async function load_session_grants(
    session_id: string,
): Promise<TrustRule[]> {
    try {
        const raw = await readFile(session_path(session_id), "utf-8");
        const data = JSON.parse(raw) as SessionFile;
        return data.grants ?? [];
    } catch (err: unknown) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") {
            return [];
        }
        throw err;
    }
}

export async function add_session_grant(
    session_id: string,
    rule: TrustRule,
): Promise<void> {
    await ensure_sessions_dir();
    const lock = session_path(session_id) + ".lock";
    await with_file_lock(lock, async () => {
        const existing = await load_session_grants(session_id);
        existing.push(rule);
        const session_file: SessionFile = {
            session_id,
            grants: existing,
            created_at: new Date().toISOString(),
        };
        await atomic_write(
            session_path(session_id),
            JSON.stringify(session_file, null, 4),
        );
    });
}

export async function consume_once_grant(
    session_id: string,
    rule_id: string,
): Promise<void> {
    await ensure_sessions_dir();
    const lock = session_path(session_id) + ".lock";
    await with_file_lock(lock, async () => {
        const grants = await load_session_grants(session_id);
        const updated = grants.filter(
            (g) => !(g.id === rule_id && g.scope === "once"),
        );

        if (updated.length === grants.length) {
            return; // nothing to consume
        }

        const session_file: SessionFile = {
            session_id,
            grants: updated,
            created_at: new Date().toISOString(),
        };
        await atomic_write(
            session_path(session_id),
            JSON.stringify(session_file, null, 4),
        );
    });
}

export async function write_session_breadcrumb(
    session_id: string,
): Promise<void> {
    await ensure_sessions_dir();
    const breadcrumb_path = join(SESSIONS_DIR, "_current_session");
    await writeFile(breadcrumb_path, session_id, "utf-8");
}

export async function read_session_breadcrumb(): Promise<string | null> {
    try {
        const breadcrumb_path = join(SESSIONS_DIR, "_current_session");
        const content = await readFile(breadcrumb_path, "utf-8");
        return content.trim() || null;
    } catch {
        return null;
    }
}

export function is_async_session(session_id: string): boolean {
    return session_id.startsWith("async-");
}

export async function load_session_mode(
    session_id: string,
): Promise<string | undefined> {
    try {
        const raw = await readFile(session_path(session_id), "utf-8");
        const data = JSON.parse(raw) as SessionFile;
        return data.mode;
    } catch {
        return undefined;
    }
}

export async function apply_async_session(
    target_session_id: string,
    async_session_id: string,
): Promise<{ grants_copied: number; error?: string }> {
    if (!is_async_session(async_session_id)) {
        return { grants_copied: 0, error: "async_session_id must start with 'async-'" };
    }

    validate_session_id(async_session_id);
    validate_session_id(target_session_id);

    // Load grants from async session
    const async_grants = await load_session_grants(async_session_id);
    if (async_grants.length === 0) {
        return { grants_copied: 0, error: `No grants found in async session "${async_session_id}"` };
    }

    await ensure_sessions_dir();
    const lock = session_path(target_session_id) + ".lock";
    let grants_copied = 0;

    await with_file_lock(lock, async () => {
        const existing = await load_session_grants(target_session_id);
        const existing_ids = new Set(existing.map((g) => g.id));

        // Add grants that aren't already present (dedup by rule ID)
        for (const grant of async_grants) {
            if (!existing_ids.has(grant.id)) {
                existing.push(grant);
                grants_copied++;
            }
        }

        const session_file: SessionFile = {
            session_id: target_session_id,
            grants: existing,
            created_at: new Date().toISOString(),
            mode: "async",
        };
        await atomic_write(
            session_path(target_session_id),
            JSON.stringify(session_file, null, 4),
        );
    });

    return { grants_copied };
}

export async function clear_session(session_id: string): Promise<void> {
    try {
        await unlink(session_path(session_id));
    } catch (err: unknown) {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
            throw err;
        }
    }
}
