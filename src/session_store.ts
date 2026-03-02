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

export async function clear_session(session_id: string): Promise<void> {
    try {
        await unlink(session_path(session_id));
    } catch (err: unknown) {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
            throw err;
        }
    }
}
