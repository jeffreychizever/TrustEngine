import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { appendFile, realpath } from "node:fs/promises";
import type { HookInput, HookOutput } from "./types.js";
import { load_policies, evaluate } from "./engine.js";
import {
    load_session_grants,
    consume_once_grant,
    write_session_breadcrumb,
} from "./session_store.js";

const POLICIES_PATH = join(homedir(), ".config", "trustengine", "policies.json");
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

function extract_common_path(sub_commands: string[]): string | null {
    // Extract path arguments from commands like "rm /tmp/foo" → "/tmp/foo"
    const paths: string[] = [];
    for (const cmd of sub_commands) {
        const match = cmd.match(/\s+(\/\S+)/);
        if (match) paths.push(match[1]);
    }
    if (paths.length === 0) return null;

    // Find common directory prefix
    const dirs = paths.map((p) => p.substring(0, p.lastIndexOf("/") + 1));
    let common = dirs[0];
    for (const dir of dirs.slice(1)) {
        while (common && !dir.startsWith(common)) {
            common = common.substring(0, common.lastIndexOf("/", common.length - 2) + 1);
        }
    }
    return common || null;
}

function build_deny_guidance(
    tool_name: string,
    tool_input: Record<string, unknown>,
    denied_commands: string[] | undefined,
    denied_sub_commands: string[] | undefined,
    session_id: string,
): string {
    const lines: string[] = [];

    // First-time nudge
    lines.push(
        `If this is your first TrustEngine denial, call grant_permission(help=true) to learn the system before requesting access.`,
    );

    // Generate a concrete suggested grant_permission call
    if (tool_name === "Bash" && denied_commands && denied_commands.length > 0) {
        const unique_cmds = [...new Set(denied_commands)];
        const cmd_names_json = JSON.stringify(unique_cmds);

        // Try to extract a common path to scope the pattern
        const common_path = denied_sub_commands
            ? extract_common_path(denied_sub_commands)
            : null;

        lines.push(
            `\nSuggested grant_permission call (use structured matchers, not raw regex):\n` +
            `  tool: "Bash"\n` +
            `  command_names: ${cmd_names_json}\n` +
            (common_path
                ? `  path_prefix: "${common_path}"\n`
                : `  path_prefix: "<required — scope to the relevant directory>"\n`) +
            `  allowed_flags: [] (add any needed flags like "-r", "-f", "--force")\n` +
            `  scope: "session" (or "permanent" if the user will always need this)\n` +
            `  session_id: "${session_id}"\n` +
            `  description: <what this allows>\n` +
            `  justification: <why this is needed and safe>`,
        );
    } else if (
        (tool_name === "Write" || tool_name === "Edit") &&
        typeof tool_input.file_path === "string"
    ) {
        const fp = tool_input.file_path as string;
        const dir = fp.substring(0, fp.lastIndexOf("/") + 1);
        const escaped_dir = dir.replace(/[.*+?^${}()|[\]\\]/g, "\\\\$&");

        lines.push(
            `\nSuggested grant_permission call:\n` +
            `  tool: "${tool_name}"\n` +
            `  match: {"file_path": "^${escaped_dir}"}\n` +
            `  scope: "session"\n` +
            `  session_id: "${session_id}"\n` +
            `  description: <what this allows>\n` +
            `  justification: <why this is needed and safe>`,
        );
    } else {
        lines.push(
            `\nCall grant_permission to request access.\n` +
            `  tool: "${tool_name}"\n` +
            `  scope: "session"\n` +
            `  session_id: "${session_id}"`,
        );
    }

    return lines.join("\n");
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
        const { session_id, cwd, tool_name, tool_input } = input;
        await debug(`Evaluating: tool=${tool_name} cwd=${cwd}`);

        // Write session breadcrumb for MCP server
        if (session_id) {
            await write_session_breadcrumb(session_id).catch(() => {});
        }

        // check_permission is read-only, auto-allow it
        if (tool_name === "mcp__trustengine__check_permission") {
            const output = make_allow_output();
            process.stdout.write(JSON.stringify(output));
            return;
        }

        // grant_permission: help mode is read-only, auto-allow it
        if (tool_name === "mcp__trustengine__grant_permission" && tool_input.help === true) {
            const output = make_allow_output();
            process.stdout.write(JSON.stringify(output));
            return;
        }

        // grant_permission: validate before asking the human
        if (tool_name === "mcp__trustengine__grant_permission") {
            const scope = tool_input.scope as string | undefined;
            const desc = tool_input.description as string | undefined;
            const justification = tool_input.justification as string | undefined;
            const tool_pattern = tool_input.tool as string | undefined;
            const match_raw = tool_input.match as Record<string, string> | undefined;
            const command_names = tool_input.command_names as string[] | undefined;
            const path_prefix = tool_input.path_prefix as string | undefined;

            // Pre-validate: reject obviously invalid requests before bothering the human
            const errors: string[] = [];

            if (!tool_pattern) errors.push("'tool' is required");
            if (!scope || !["once", "session", "permanent"].includes(scope)) {
                errors.push("'scope' must be one of: once, session, permanent");
            }
            if (!justification || justification.length < 10) {
                errors.push("'justification' is required (min 10 chars)");
            }
            if (!desc) errors.push("'description' is required");

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

            if (errors.length > 0) {
                const output = make_deny_output(
                    `TrustEngine: invalid grant_permission request:\n${errors.map((e) => `  - ${e}`).join("\n")}`,
                );
                process.stdout.write(JSON.stringify(output));
                return;
            }

            // Valid request — ask the human
            const output: HookOutput = {
                hookSpecificOutput: {
                    hookEventName: "PreToolUse",
                    permissionDecision: "ask",
                    permissionDecisionReason:
                        `TrustEngine: Agent requests ${scope} permission for "${tool_pattern}"` +
                        (desc ? ` — ${desc}` : "") +
                        (justification ? `\nJustification: ${justification}` : ""),
                },
            };
            process.stdout.write(JSON.stringify(output));
            return;
        }

        // Self-protection: hard-deny writes to policies.json
        if (
            (tool_name === "Write" || tool_name === "Edit") &&
            typeof tool_input.file_path === "string"
        ) {
            const target = tool_input.file_path as string;
            if (target === POLICIES_PATH || target.endsWith("/trustengine/policies.json")) {
                const output = make_deny_output(
                    "TrustEngine: policies.json is protected. Use grant_permission(scope='permanent') to modify policies.",
                );
                process.stdout.write(JSON.stringify(output));
                return;
            }
        }

        // Self-protection: hard-deny Bash commands that reference policies.json
        if (
            tool_name === "Bash" &&
            typeof tool_input.command === "string"
        ) {
            const cmd = tool_input.command as string;
            if (cmd.includes("trustengine/policies.json")) {
                const output = make_deny_output(
                    "TrustEngine: policies.json is protected. Use grant_permission(scope='permanent') to modify policies.",
                );
                process.stdout.write(JSON.stringify(output));
                return;
            }
        }

        // Resolve symlinks in file_path before evaluation
        const resolved_input = { ...tool_input } as Record<string, unknown>;
        if (typeof resolved_input.file_path === "string") {
            resolved_input.file_path = await resolve_file_path(
                resolved_input.file_path as string,
            );
        }

        // Load policies and session grants
        const policies = await load_policies(POLICIES_PATH);
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
            const output = make_allow_output();
            process.stdout.write(JSON.stringify(output));
            return;
        }

        // Denied — build context with suggested grant_permission call
        const deny_reason = `TrustEngine DENIED: ${result.reason}`;
        let context = "";

        if (result.risk_warnings.length > 0) {
            const risks = result.risk_warnings
                .map((r) => `[${r.severity.toUpperCase()}] ${r.risk}`)
                .join("\n");
            context += `Known risks:\n${risks}\n\n`;
        }

        context += build_deny_guidance(
            tool_name,
            tool_input as Record<string, unknown>,
            result.denied_commands,
            result.denied_sub_commands,
            session_id,
        );

        const output = make_deny_output(deny_reason, context);
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

run();
