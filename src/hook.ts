#!/usr/bin/env node

import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { appendFile, realpath, writeFile, mkdir } from "node:fs/promises";
import type { HookInput, HookOutput } from "./types.js";
import { load_policies, load_overlays, merge_policies_with_overlays, evaluate, validate_policy_regexes } from "./engine.js";
import {
    load_session_grants,
    consume_once_grant,
    write_session_breadcrumb,
    is_async_session,
    load_session_mode,
} from "./session_store.js";
import { build_deny_guidance } from "./deny_guidance.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const INSTALL_DIR = join(__dirname, "..");
const CONFIG_DIR = join(homedir(), ".config", "trustengine");
const POLICIES_PATH = join(CONFIG_DIR, "policies.json");
const OVERLAYS_DIR = join(CONFIG_DIR, "overlays");
const DEBUG_LOG = "/tmp/trustengine-debug.log";

async function resolve_file_path(file_path: string): Promise<string> {
    // Try to resolve the full path via realpath (follows symlinks)
    try {
        return await realpath(file_path);
    } catch {
        // File may not exist yet — resolve the parent directory instead
        try {
            const dir = dirname(file_path);
            const resolved_dir = await realpath(dir);
            const basename = file_path.slice(file_path.lastIndexOf("/") + 1);
            return join(resolved_dir, basename);
        } catch {
            // Parent doesn't exist either — return as-is
            return file_path;
        }
    }
}

async function debug(msg: string): Promise<void> {
    if (process.env.TRUSTENGINE_DEBUG !== "1") return;
    const ts = new Date().toISOString();
    await appendFile(DEBUG_LOG, `[${ts}] ${msg}\n`).catch(() => {});
}

function make_deny_output(reason: string, context?: string): HookOutput {
    return {
        hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: "deny",
            permissionDecisionReason: reason,
            additionalContext: context,
        },
    };
}

function make_allow_output(): HookOutput {
    return {
        hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: "allow",
        },
    };
}

function make_ask_output(reason: string): HookOutput {
    return {
        hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: "ask",
            permissionDecisionReason: reason,
        },
    };
}

function build_async_guidance(session_id: string): string {
    return [
        "You are running in async mode (no human available for approval).",
        "",
        "To work within your permissions:",
        "  1. Call check_permission(help=true) to understand the permission system",
        `  2. Call check_permission(session_id="${session_id}") to test what's already allowed`,
        "  3. Use acknowledge_risk for acknowledge-tier risks (no human needed)",
        "  4. Adjust your approach to use only pre-provisioned permissions",
        "",
        "If you need permissions that aren't available, document what you need",
        "so the parent agent or user can provision them for next time.",
    ].join("\n");
}

/**
 * Core hook logic — takes parsed input, returns the hook output decision.
 * Extracted from run() so it can be called directly in tests without stdin/stdout.
 */
export async function handle_hook_input(input: HookInput): Promise<HookOutput> {
    const { session_id, cwd, tool_name, tool_input } = input;
    await debug(`Evaluating: tool=${tool_name} cwd=${cwd}`);

    // Write session breadcrumb for MCP server
    if (session_id) {
        await write_session_breadcrumb(session_id).catch(() => {});
    }

    // check_permission is read-only, auto-allow it
    if (tool_name === "mcp__trustengine__check_permission") {
        return make_allow_output();
    }

    // acknowledge_risk is for "acknowledge" tier risks — auto-allow it
    // (the MCP server validates that only acknowledge-tier risks are accepted)
    if (tool_name === "mcp__trustengine__acknowledge_risk") {
        return make_allow_output();
    }

    // apply_async_session is safe — the MCP server handles validation
    if (tool_name === "mcp__trustengine__apply_async_session") {
        return make_allow_output();
    }

    // grant_permission: validate before asking the human
    if (tool_name === "mcp__trustengine__grant_permission") {
        // Help mode is read-only, auto-allow it
        if (tool_input.help === true) {
            return make_allow_output();
        }

        // Async sessions cannot request new permissions
        const session_mode = session_id
            ? await load_session_mode(session_id)
            : undefined;
        const is_async =
            (session_id && is_async_session(session_id)) ||
            session_mode === "async";

        if (is_async) {
            return make_deny_output(
                "TrustEngine: grant_permission is not available in async mode.",
                build_async_guidance(session_id),
            );
        }

        const scope = tool_input.scope as string | undefined;
        const desc = tool_input.description as string | undefined;
        const justification = tool_input.justification as string | undefined;
        const tool_pattern = tool_input.tool as string | undefined;
        const match_raw = tool_input.match as Record<string, string> | undefined;
        const command_names = tool_input.command_names as string[] | undefined;
        const path_prefix = tool_input.path_prefix as string | undefined;

        // Directory management mode — different validation
        const add_safe = tool_input.add_safe_directory as string | undefined;
        const add_unsafe = tool_input.add_unsafe_directory as string | undefined;
        const remove_safe = tool_input.remove_safe_directory as string | undefined;
        const remove_unsafe = tool_input.remove_unsafe_directory as string | undefined;
        const is_dir_mgmt = !!(add_safe || add_unsafe || remove_safe || remove_unsafe);

        if (is_dir_mgmt) {
            const errors: string[] = [];
            if (!justification || justification.length < 10) {
                errors.push("'justification' is required (min 10 chars)");
            }
            for (const [label, path] of [
                ["add_safe_directory", add_safe],
                ["add_unsafe_directory", add_unsafe],
                ["remove_safe_directory", remove_safe],
                ["remove_unsafe_directory", remove_unsafe],
            ] as const) {
                if (path && !path.startsWith("/") && path !== "$CWD" && path !== "$NOTCWD") {
                    errors.push(`'${label}' must be an absolute path, $CWD, or $NOTCWD. Got: "${path}"`);
                }
            }

            if (errors.length > 0) {
                return make_deny_output(
                    `TrustEngine: invalid directory management request:\n${errors.map((e) => `  - ${e}`).join("\n")}`,
                );
            }

            // Build a human-readable summary of the proposed changes
            const changes: string[] = [];
            if (add_safe) changes.push(`Add "${add_safe}" to safe directories`);
            if (add_unsafe) changes.push(`Add "${add_unsafe}" to unsafe directories`);
            if (remove_safe) changes.push(`Remove "${remove_safe}" from safe directories`);
            if (remove_unsafe) changes.push(`Remove "${remove_unsafe}" from unsafe directories`);

            return make_ask_output(
                `TrustEngine: Agent requests directory classification change:\n` +
                changes.map((c) => `  - ${c}`).join("\n") +
                (justification ? `\nJustification: ${justification}` : ""),
            );
        }

        // Script mode — show script content to human for review
        const script_content = tool_input.script as string | undefined;
        if (script_content) {
            const script_errors: string[] = [];
            if (!scope || !["once", "session", "permanent"].includes(scope)) {
                script_errors.push("'scope' is required");
            }
            if (!justification || justification.length < 10) {
                script_errors.push("'justification' is required (min 10 chars)");
            }
            if (!desc) {
                script_errors.push("'description' is required");
            }
            if (script_errors.length > 0) {
                return make_deny_output(
                    `TrustEngine: invalid script request:\n${script_errors.map((e) => `  - ${e}`).join("\n")}`,
                );
            }

            const interpreter = (tool_input.script_interpreter as string | undefined) ?? "bash";
            const ack_risks = tool_input.acknowledged_risks as string[] | undefined;

            // Write script to a temp file so the human can review it with proper formatting
            const review_dir = join(homedir(), ".config", "trustengine", "review");
            await mkdir(review_dir, { recursive: true });
            const ext_map: Record<string, string> = {
                bash: "sh", sh: "sh", python: "py", python3: "py", node: "mjs",
            };
            const ext = ext_map[interpreter] ?? "sh";
            const review_path = join(review_dir, `pending.${ext}`);
            await writeFile(review_path, script_content, "utf-8");

            return make_ask_output(
                `TrustEngine: Agent requests ${scope} permission to run a script` +
                (desc ? ` — ${desc}` : "") +
                (justification ? `\nJustification: ${justification}` : "") +
                (ack_risks && ack_risks.length > 0
                    ? `\nAcknowledged risks: ${ack_risks.join(", ")}`
                    : "") +
                `\nReview script: cat ${review_path}`,
            );
        }

        // Normal rule grant — pre-validate
        const errors: string[] = [];

        if (!tool_pattern) errors.push("'tool' is required");
        if (!scope || !["once", "session", "permanent"].includes(scope)) {
            errors.push("'scope' must be one of: once, session, permanent");
        }
        if (!justification || justification.length < 10) {
            errors.push("'justification' is required (min 10 chars)");
        }
        if (!desc) errors.push("'description' is required");

        // Validate tool pattern looks like it will actually match something.
        // Standard Claude tools use PascalCase. MCP tools use mcp__server__tool.
        // If the pattern is a simple name that doesn't match either convention,
        // it's likely an unqualified MCP tool name that won't match anything.
        if (tool_pattern && !/[|.*+?^${}()[\]\\]/.test(tool_pattern)) {
            const known_tools = new Set([
                "Bash", "Read", "Write", "Edit", "Glob", "Grep",
                "WebFetch", "WebSearch", "Agent", "NotebookEdit",
                "TaskCreate", "TaskUpdate", "TaskGet", "TaskList",
                "TaskOutput", "TaskStop", "AskUserQuestion",
                "EnterPlanMode", "ExitPlanMode", "EnterWorktree",
                "ExitWorktree", "Skill", "ToolSearch",
                "CronCreate", "CronDelete", "CronList",
            ]);
            if (!known_tools.has(tool_pattern) && !tool_pattern.startsWith("mcp__")) {
                errors.push(
                    `Tool pattern "${tool_pattern}" doesn't match any known Claude tool ` +
                    `and doesn't use MCP qualified syntax (mcp__<server>__<tool>). ` +
                    `If this is an MCP tool, use the full qualified name.`,
                );
            }
        }

        if (match_raw && command_names && command_names.length > 0) {
            errors.push("Cannot use both 'match' and structured fields (command_names/path_prefix/allowed_flags). Use one or the other.");
        }

        // Validate command_names require path_prefix for destructive commands
        const destructive_cmds = ["rm", "rmdir", "curl", "wget", "dd", "mkfs", "chmod", "chown"];
        if (command_names && command_names.length > 0 && !path_prefix) {
            const risky = command_names.filter((c) => destructive_cmds.includes(c));
            if (risky.length > 0) {
                errors.push(
                    `'path_prefix' is required for destructive commands: ${risky.join(", ")}. ` +
                    `Scope to the relevant directory.`,
                );
            }
        }

        // Warn about patterns that may cause subtle issues
        const warnings: string[] = [];
        if (match_raw) {
            for (const [param, pattern] of Object.entries(match_raw)) {
                // .* can break backslash-escape handling and may be overly broad
                if (/\.\*/.test(pattern)) {
                    warnings.push(
                        `Pattern for '${param}' contains '.*' which may be overly broad ` +
                        `and can interfere with backslash-escaped paths. ` +
                        `Consider using structured fields (command_names, path_prefix) instead.`,
                    );
                }
                // $SAFE_CMD in deny rules has inverted semantics that are rarely intended
                if (/\$SAFE_CMD/.test(pattern) && tool_input.action === "deny") {
                    warnings.push(
                        `$SAFE_CMD in a deny rule means "deny if the inner command is safe" ` +
                        `which is rarely the intended semantics. $SAFE_CMD is designed for ` +
                        `allow rules.`,
                    );
                }
            }
        }

        if (errors.length > 0) {
            const msg = errors.map((e) => `  - ${e}`).join("\n");
            const warn_msg = warnings.length > 0
                ? `\nWarnings:\n${warnings.map((w) => `  - ${w}`).join("\n")}`
                : "";
            return make_deny_output(
                `TrustEngine: invalid grant_permission request:\n${msg}${warn_msg}`,
            );
        }

        // Valid request — ask the human (include warnings if any)
        const ack_risks = tool_input.acknowledged_risks as string[] | undefined;
        const warn_suffix = warnings.length > 0
            ? `\nWarnings:\n${warnings.map((w) => `  ⚠ ${w}`).join("\n")}`
            : "";
        return make_ask_output(
            `TrustEngine: Agent requests ${scope} permission for "${tool_pattern}"` +
            (desc ? ` — ${desc}` : "") +
            (justification ? `\nJustification: ${justification}` : "") +
            (ack_risks && ack_risks.length > 0
                ? `\nAcknowledged risks: ${ack_risks.join(", ")}`
                : "") +
            warn_suffix,
        );
    }

    // Load policies + overlays early so self-protection can reference unsafe_directories
    const base_policies = await load_policies(POLICIES_PATH);
    const overlays = await load_overlays(OVERLAYS_DIR);
    const policies = merge_policies_with_overlays(base_policies, overlays);

    // Validate all regex patterns at load time — a malformed deny-rule regex
    // would silently fail to match (the catch block in matches_tool_and_input
    // returns false), effectively failing open. This check surfaces errors
    // early so broken policies don't silently allow dangerous commands.
    validate_policy_regexes(policies, cwd);

    // Build the list of protected paths for hardcoded self-protection.
    // This covers both Write/Edit and Bash commands referencing these paths.
    const protected_paths = [CONFIG_DIR, INSTALL_DIR];
    if (policies.unsafe_directories) {
        for (const dir of policies.unsafe_directories) {
            // Resolve macros to concrete paths for string matching
            if (dir === "$CWD") {
                protected_paths.push(cwd);
            } else if (dir === "$NOTCWD") {
                // $NOTCWD is regex-level — handled by the deny-write-in-unsafe rule, not here
                continue;
            } else if (!dir.includes("$")) {
                protected_paths.push(dir);
            }
        }
    }

    // Resolve symlinks in file_path before self-protection and evaluation
    const resolved_input = { ...tool_input } as Record<string, unknown>;
    if (typeof resolved_input.file_path === "string") {
        resolved_input.file_path = await resolve_file_path(
            resolved_input.file_path as string,
        );
    }

    // Self-protection: hard-deny writes to protected directories
    if (
        (tool_name === "Write" || tool_name === "Edit") &&
        typeof resolved_input.file_path === "string"
    ) {
        const target = resolved_input.file_path as string;
        if (target === POLICIES_PATH || target.endsWith("/trustengine/policies.json")) {
            return make_deny_output(
                "TrustEngine: policies.json is protected. Use grant_permission(scope='permanent') to modify policies.",
            );
        }
        // Check protected subdirectories — precise prefix + generic substring fallback
        const protected_dirs: Array<[string, string]> = [
            ["overlays", "TrustEngine: the overlays directory is protected. Use grant_permission(scope='permanent') to modify policies."],
            ["sessions", "TrustEngine: the sessions directory is protected. Session files cannot be modified directly."],
            ["scripts", "TrustEngine: the scripts directory is protected. Use grant_permission(script=...) to create approved scripts."],
        ];
        for (const [dir_name, message] of protected_dirs) {
            const prefix = join(CONFIG_DIR, dir_name);
            if (target === prefix || target.startsWith(prefix + "/") || target.includes(`/trustengine/${dir_name}/`)) {
                return make_deny_output(message);
            }
        }
        // Protect CONFIG_DIR itself
        if (target === CONFIG_DIR || target.endsWith("/trustengine")) {
            return make_deny_output(
                "TrustEngine: the config directory is protected.",
            );
        }
        if (target === INSTALL_DIR || target.startsWith(INSTALL_DIR + "/")) {
            return make_deny_output(
                "TrustEngine: the installation directory is protected. Do not modify TrustEngine's source or built files.",
            );
        }
    }

    // Self-protection: hard-deny Bash commands that reference protected paths
    if (
        tool_name === "Bash" &&
        typeof tool_input.command === "string"
    ) {
        const cmd = tool_input.command as string;
        for (const dir of protected_paths) {
            if (cmd.includes(dir)) {
                return make_deny_output(
                    `TrustEngine: "${dir}" is a protected path. Bash commands referencing it are denied.`,
                );
            }
        }
    }

    // Strip null bytes and non-printable control characters from string
    // values in tool_input before regex evaluation. Null bytes can cause
    // regex patterns to silently fail to match (e.g. "su\x00do" won't
    // match /sudo/), which could bypass deny rules. We preserve standard
    // whitespace (\t, \n, \r) since they have legitimate uses in commands.
    for (const [key, val] of Object.entries(resolved_input)) {
        if (typeof val === "string") {
            // eslint-disable-next-line no-control-regex
            resolved_input[key] = val.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
        }
    }

    const session_grants = session_id
        ? await load_session_grants(session_id)
        : [];

    // Evaluate
    const result = evaluate(
        policies,
        session_grants,
        tool_name,
        resolved_input,
        cwd,
    );

    await debug(`Result: ${result.decision} — ${result.reason}`);

    if (result.decision === "allow") {
        // Consume one-off grants (single rule or compound bash)
        if (session_id) {
            if (
                result.matched_rule?.scope === "once" &&
                result.matched_rule.id
            ) {
                await consume_once_grant(session_id, result.matched_rule.id).catch(
                    () => {},
                );
            }
            if (result.once_grants_consumed) {
                for (const id of result.once_grants_consumed) {
                    await consume_once_grant(session_id, id).catch(() => {});
                }
            }
        }
        return make_allow_output();
    }

    // Denied — build context with suggested grant_permission call
    const deny_reason = `TrustEngine DENIED: ${result.reason}`;
    let context = "";

    if (result.risk_warnings.length > 0) {
        const risks = result.risk_warnings
            .map((r) => `[${r.severity}] ${r.id}: ${r.risk}`)
            .join("\n");
        context += `Known risks:\n${risks}\n\n`;
    }

    const risks = result.risk_warnings.map((r) => ({ id: r.id, severity: r.severity }));
    context += build_deny_guidance(
        tool_name,
        tool_input as Record<string, unknown>,
        result.denied_commands,
        result.denied_sub_commands,
        session_id,
        risks,
    );

    return make_deny_output(deny_reason, context);
}

async function run(): Promise<void> {
    await debug("Hook invoked");
    let input: HookInput;

    try {
        const raw = await new Promise<string>((resolve, reject) => {
            let data = "";
            process.stdin.setEncoding("utf-8");
            process.stdin.on("data", (chunk) => (data += chunk));
            process.stdin.on("end", () => resolve(data));
            process.stdin.on("error", reject);
        });
        await debug(`Raw input: ${raw.slice(0, 200)}`);
        input = JSON.parse(raw) as HookInput;
    } catch (e) {
        // Can't parse input — fail closed
        await debug(`Parse error: ${e}`);
        const output = make_deny_output("TrustEngine: failed to parse hook input");
        process.stdout.write(JSON.stringify(output));
        return;
    }

    try {
        const output = await handle_hook_input(input);
        process.stdout.write(JSON.stringify(output));
    } catch (err) {
        // Fail closed on any error
        const message =
            err instanceof Error ? err.message : "Unknown error";
        const output = make_deny_output(
            `TrustEngine: internal error — ${message}. Failing closed.`,
        );
        process.stdout.write(JSON.stringify(output));
    }
}

// Only auto-run when executed directly (not when imported for testing)
const is_main = process.argv[1]?.endsWith("/hook.js") ||
    process.argv[1]?.endsWith("/hook.ts") ||
    process.argv[1]?.endsWith("/trustengine-hook");
if (is_main) {
    run();
}
