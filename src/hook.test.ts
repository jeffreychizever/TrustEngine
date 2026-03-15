import { describe, it, expect, afterEach } from "vitest";
import type { HookInput, HookOutput } from "./types.js";
import { handle_hook_input } from "./hook.js";
import {
    add_session_grant,
    clear_session,
    apply_async_session,
} from "./session_store.js";
import type { TrustRule } from "./types.js";

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

/**
 * Helper to build a HookInput with sensible defaults.
 * Override any field by passing it in the partial.
 */
function make_input(partial: Partial<HookInput> & { tool_name: string }): HookInput {
    return {
        session_id: partial.session_id ?? "test-session",
        cwd: partial.cwd ?? "/tmp/test",
        tool_name: partial.tool_name,
        tool_input: partial.tool_input ?? {},
    };
}

function decision(output: HookOutput): string {
    return output.hookSpecificOutput.permissionDecision;
}

function reason(output: HookOutput): string | undefined {
    return output.hookSpecificOutput.permissionDecisionReason;
}

function context(output: HookOutput): string | undefined {
    return output.hookSpecificOutput.additionalContext;
}

// ---------------------------------------------------------------------------
// Auto-allow tools
// ---------------------------------------------------------------------------

describe("auto-allow tools", () => {
    it("auto-allows check_permission", async () => {
        const out = await handle_hook_input(
            make_input({ tool_name: "mcp__trustengine__check_permission" }),
        );
        expect(decision(out)).toBe("allow");
    });

    it("auto-allows acknowledge_risk", async () => {
        const out = await handle_hook_input(
            make_input({ tool_name: "mcp__trustengine__acknowledge_risk" }),
        );
        expect(decision(out)).toBe("allow");
    });

    it("auto-allows apply_async_session", async () => {
        const out = await handle_hook_input(
            make_input({ tool_name: "mcp__trustengine__apply_async_session" }),
        );
        expect(decision(out)).toBe("allow");
    });
});

// ---------------------------------------------------------------------------
// grant_permission validation
// ---------------------------------------------------------------------------

describe("grant_permission validation", () => {
    it("auto-allows help mode", async () => {
        const out = await handle_hook_input(
            make_input({
                tool_name: "mcp__trustengine__grant_permission",
                tool_input: { help: true },
            }),
        );
        expect(decision(out)).toBe("allow");
    });

    it("denies when missing required fields", async () => {
        const out = await handle_hook_input(
            make_input({
                tool_name: "mcp__trustengine__grant_permission",
                tool_input: { scope: "session" },
            }),
        );
        expect(decision(out)).toBe("deny");
        expect(reason(out)).toContain("'tool' is required");
    });

    it("denies unqualified MCP tool names", async () => {
        const out = await handle_hook_input(
            make_input({
                tool_name: "mcp__trustengine__grant_permission",
                tool_input: {
                    tool: "some_tool",
                    scope: "session",
                    justification: "testing unqualified name",
                    description: "test",
                },
            }),
        );
        expect(decision(out)).toBe("deny");
        expect(reason(out)).toContain("MCP qualified syntax");
    });

    it("asks human for valid grant request", async () => {
        const out = await handle_hook_input(
            make_input({
                tool_name: "mcp__trustengine__grant_permission",
                tool_input: {
                    tool: "Bash",
                    scope: "session",
                    justification: "need to run curl for API testing",
                    description: "Allow curl",
                    command_names: ["curl"],
                    path_prefix: "https://example.com",
                },
            }),
        );
        expect(decision(out)).toBe("ask");
    });

    it("requires path_prefix for destructive commands", async () => {
        const out = await handle_hook_input(
            make_input({
                tool_name: "mcp__trustengine__grant_permission",
                tool_input: {
                    tool: "Bash",
                    scope: "session",
                    justification: "need to remove test files",
                    description: "Allow rm",
                    command_names: ["rm"],
                },
            }),
        );
        expect(decision(out)).toBe("deny");
        expect(reason(out)).toContain("path_prefix");
    });
});

// ---------------------------------------------------------------------------
// Async agent mode
// ---------------------------------------------------------------------------

describe("async agent mode", () => {
    const async_session = "async-test-hook";
    const child_session = "child-hook-test";

    const sample_grant: TrustRule = {
        id: "grant-hook-test",
        tool: "Bash",
        match: { command: "^ls\\b" },
        action: "allow",
        priority: 85,
        description: "[granted] Allow ls",
        scope: "session",
    };

    afterEach(async () => {
        await clear_session(async_session).catch(() => {});
        await clear_session(child_session).catch(() => {});
    });

    it("denies grant_permission for async- prefixed session IDs", async () => {
        const out = await handle_hook_input(
            make_input({
                session_id: async_session,
                tool_name: "mcp__trustengine__grant_permission",
                tool_input: {
                    tool: "Bash",
                    scope: "session",
                    justification: "I need curl access",
                    description: "Allow curl",
                },
            }),
        );
        expect(decision(out)).toBe("deny");
        expect(reason(out)).toContain("async mode");
    });

    it("includes guidance in async denial context", async () => {
        const out = await handle_hook_input(
            make_input({
                session_id: async_session,
                tool_name: "mcp__trustengine__grant_permission",
                tool_input: {
                    tool: "Bash",
                    scope: "session",
                    justification: "I need curl access",
                    description: "Allow curl",
                },
            }),
        );
        expect(context(out)).toContain("async mode");
        expect(context(out)).toContain("check_permission");
        expect(context(out)).toContain("acknowledge_risk");
    });

    it("allows grant_permission help mode even in async sessions", async () => {
        const out = await handle_hook_input(
            make_input({
                session_id: async_session,
                tool_name: "mcp__trustengine__grant_permission",
                tool_input: { help: true },
            }),
        );
        expect(decision(out)).toBe("allow");
    });

    it("denies grant_permission after apply_async_session sets mode", async () => {
        // Set up: parent provisions grants into async session
        await add_session_grant(async_session, sample_grant);

        // Child applies the async session
        const apply_result = await apply_async_session(child_session, async_session);
        expect(apply_result.error).toBeUndefined();

        // Child tries to grant_permission — should be denied (mode is "async")
        const out = await handle_hook_input(
            make_input({
                session_id: child_session,
                tool_name: "mcp__trustengine__grant_permission",
                tool_input: {
                    tool: "Bash",
                    scope: "session",
                    justification: "I want more access",
                    description: "More access",
                },
            }),
        );
        expect(decision(out)).toBe("deny");
        expect(reason(out)).toContain("async mode");
    });

    it("allows check_permission in async sessions", async () => {
        const out = await handle_hook_input(
            make_input({
                session_id: async_session,
                tool_name: "mcp__trustengine__check_permission",
            }),
        );
        expect(decision(out)).toBe("allow");
    });

    it("allows acknowledge_risk in async sessions", async () => {
        const out = await handle_hook_input(
            make_input({
                session_id: async_session,
                tool_name: "mcp__trustengine__acknowledge_risk",
            }),
        );
        expect(decision(out)).toBe("allow");
    });

    it("allows tool calls with pre-provisioned grants in async child session", async () => {
        // Parent provisions
        await add_session_grant(async_session, sample_grant);

        // Child applies
        await apply_async_session(child_session, async_session);

        // Child runs ls — should be allowed via inherited grant
        const out = await handle_hook_input(
            make_input({
                session_id: child_session,
                cwd: "/tmp/test",
                tool_name: "Bash",
                tool_input: { command: "ls" },
            }),
        );
        expect(decision(out)).toBe("allow");
    });
});

// ---------------------------------------------------------------------------
// Self-protection
// ---------------------------------------------------------------------------

describe("self-protection", () => {
    it("hard-denies writes to policies.json", async () => {
        const out = await handle_hook_input(
            make_input({
                tool_name: "Write",
                tool_input: {
                    file_path: "/home/someone/.config/trustengine/policies.json",
                    content: "{}",
                },
            }),
        );
        expect(decision(out)).toBe("deny");
        expect(reason(out)).toContain("policies.json is protected");
    });

    it("hard-denies writes to overlays directory", async () => {
        const out = await handle_hook_input(
            make_input({
                tool_name: "Edit",
                tool_input: {
                    file_path: "/home/someone/.config/trustengine/overlays/user-grants.json",
                    old_string: "a",
                    new_string: "b",
                },
            }),
        );
        expect(decision(out)).toBe("deny");
        expect(reason(out)).toContain("overlays directory is protected");
    });

    it("hard-denies writes to scripts directory", async () => {
        const out = await handle_hook_input(
            make_input({
                tool_name: "Write",
                tool_input: {
                    file_path: "/home/someone/.config/trustengine/scripts/evil.sh",
                    content: "rm -rf /",
                },
            }),
        );
        expect(decision(out)).toBe("deny");
        expect(reason(out)).toContain("scripts directory is protected");
    });
});
