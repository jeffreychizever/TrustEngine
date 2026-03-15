import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { join } from "node:path";
import { mkdtemp, rm, readFile, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import type { SessionFile, TrustRule } from "./types.js";

// We test the pure helper and the async session logic by importing from the module.
// For apply_async_session we need to work with real files, so we mock SESSIONS_DIR
// by testing the logic directly.

import {
    is_async_session,
    load_session_mode,
    apply_async_session,
    load_session_grants,
    add_session_grant,
    clear_session,
} from "./session_store.js";

// ---------------------------------------------------------------------------
// is_async_session
// ---------------------------------------------------------------------------

describe("is_async_session", () => {
    it("returns true for async- prefixed IDs", () => {
        expect(is_async_session("async-abc123")).toBe(true);
        expect(is_async_session("async-")).toBe(true);
        expect(is_async_session("async-some-long-uuid-here")).toBe(true);
    });

    it("returns false for regular session IDs", () => {
        expect(is_async_session("regular-session")).toBe(false);
        expect(is_async_session("session-async-123")).toBe(false);
    });

    it("is case-sensitive", () => {
        expect(is_async_session("ASYNC-uppercase")).toBe(false);
        expect(is_async_session("Async-mixed")).toBe(false);
    });

    it("returns false for empty string", () => {
        expect(is_async_session("")).toBe(false);
    });
});

// ---------------------------------------------------------------------------
// apply_async_session — integration tests using real session store
// ---------------------------------------------------------------------------

describe("apply_async_session", () => {
    const async_id = "async-test-source";
    const target_id = "apply-test-target";

    const sample_grant: TrustRule = {
        id: "grant-test-001",
        tool: "Bash",
        match: { command: "^curl\\b" },
        action: "allow",
        priority: 85,
        description: "[granted] Allow curl",
        scope: "session",
    };

    afterEach(async () => {
        // Clean up test sessions
        await clear_session(async_id).catch(() => {});
        await clear_session(target_id).catch(() => {});
    });

    it("copies grants from async session to target session", async () => {
        // Set up async session with a grant
        await add_session_grant(async_id, sample_grant);

        const result = await apply_async_session(target_id, async_id);
        expect(result.error).toBeUndefined();
        expect(result.grants_copied).toBe(1);

        // Verify the target session has the grant
        const target_grants = await load_session_grants(target_id);
        expect(target_grants).toHaveLength(1);
        expect(target_grants[0].id).toBe("grant-test-001");
    });

    it("sets target session mode to async", async () => {
        await add_session_grant(async_id, sample_grant);
        await apply_async_session(target_id, async_id);

        const mode = await load_session_mode(target_id);
        expect(mode).toBe("async");
    });

    it("rejects non-async session IDs", async () => {
        const result = await apply_async_session(target_id, "regular-session");
        expect(result.error).toContain("must start with 'async-'");
        expect(result.grants_copied).toBe(0);
    });

    it("returns error when async session has no grants", async () => {
        const result = await apply_async_session(target_id, async_id);
        expect(result.error).toContain("No grants found");
        expect(result.grants_copied).toBe(0);
    });

    it("deduplicates grants on repeated apply", async () => {
        await add_session_grant(async_id, sample_grant);

        await apply_async_session(target_id, async_id);
        const result2 = await apply_async_session(target_id, async_id);
        expect(result2.grants_copied).toBe(0);

        const target_grants = await load_session_grants(target_id);
        expect(target_grants).toHaveLength(1);
    });

    it("is additive when target already has grants", async () => {
        const existing_grant: TrustRule = {
            id: "grant-existing",
            tool: "Write",
            action: "allow",
            priority: 85,
            description: "[granted] Existing grant",
            scope: "session",
        };

        // Add existing grant to target
        await add_session_grant(target_id, existing_grant);

        // Add grant to async session
        await add_session_grant(async_id, sample_grant);

        const result = await apply_async_session(target_id, async_id);
        expect(result.grants_copied).toBe(1);

        const target_grants = await load_session_grants(target_id);
        expect(target_grants).toHaveLength(2);
        expect(target_grants.map((g) => g.id).sort()).toEqual(
            ["grant-existing", "grant-test-001"],
        );
    });
});
