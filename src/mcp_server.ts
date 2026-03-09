import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { readFile, writeFile, mkdir, rename, chmod } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import type { PoliciesFile, TrustRule, KnownRisk } from "./types.js";
import { is_safe_regex } from "./engine.js";
import {
    add_session_grant,
    read_session_breadcrumb,
} from "./session_store.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const POLICIES_PATH = join(homedir(), ".config", "trustengine", "policies.json");
const SCRIPTS_DIR = join(homedir(), ".config", "trustengine", "scripts");

// User override: ~/.config/trustengine/help.ejs
// Fallback: bundled template in src/templates/
const USER_HELP_TEMPLATE = join(homedir(), ".config", "trustengine", "help.ejs");
const BUNDLED_HELP_TEMPLATE = join(__dirname, "..", "src", "templates", "help.ejs");

let cached_help: string | null = null;

function load_help_text(): string {
    if (!cached_help) {
        try {
            cached_help = readFileSync(USER_HELP_TEMPLATE, "utf-8");
        } catch {
            cached_help = readFileSync(BUNDLED_HELP_TEMPLATE, "utf-8");
        }
    }
    return cached_help;
}

function validate_regex(pattern: string): boolean {
    try {
        new RegExp(pattern);
        return true;
    } catch {
        return false;
    }
}

function is_overly_broad(pattern: string): boolean {
    // Test the pattern against a diverse set of tool names.
    // If it matches >= 80%, it's too broad.
    const test_names = [
        "Bash", "Read", "Write", "Edit", "Glob", "Grep",
        "WebFetch", "WebSearch", "Agent", "NotebookEdit",
    ];
    try {
        const re = new RegExp(`^(?:${pattern})$`);
        const match_count = test_names.filter((n) => re.test(n)).length;
        return match_count >= test_names.length * 0.8;
    } catch {
        return false;
    }
}

function escape_regex(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function compile_structured_match(
    command_names: string[],
    path_prefix?: string,
    allowed_flags?: string[],
): { pattern: string; error?: string } {
    if (command_names.length === 0) {
        return { pattern: "", error: "command_names must not be empty" };
    }

    // Validate command names are simple words
    for (const name of command_names) {
        if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
            return {
                pattern: "",
                error: `Invalid command name: "${name}" — must be alphanumeric`,
            };
        }
    }

    const cmd_part = command_names.length === 1
        ? escape_regex(command_names[0])
        : `(${command_names.map(escape_regex).join("|")})`;

    let flags_part = "";
    if (allowed_flags && allowed_flags.length > 0) {
        // Separate short flags and long flags
        const short_chars: Set<string> = new Set();
        const long_flags: string[] = [];

        for (const flag of allowed_flags) {
            if (flag.startsWith("--")) {
                long_flags.push(escape_regex(flag));
            } else if (flag.startsWith("-") && flag.length >= 2) {
                // Extract individual chars from combined short flags like "-rf"
                for (const ch of flag.slice(1)) {
                    short_chars.add(ch);
                }
            }
        }

        const parts: string[] = [];
        if (short_chars.size > 0) {
            const chars = [...short_chars].join("");
            parts.push(`-[${escape_regex(chars)}]+`);
        }
        for (const lf of long_flags) {
            parts.push(lf);
        }

        const flag_alt = parts.length === 1 ? parts[0] : `(${parts.join("|")})`;
        flags_part = `(${flag_alt} +)*`;
    }

    let path_part = "";
    if (path_prefix) {
        path_part = escape_regex(path_prefix);
    }

    const pattern = `^${cmd_part} +${flags_part}${path_part}`;
    return { pattern };
}

async function load_or_create_policies(): Promise<PoliciesFile> {
    try {
        const raw = await readFile(POLICIES_PATH, "utf-8");
        return JSON.parse(raw) as PoliciesFile;
    } catch {
        return { version: 1, rules: [], known_risks: [] };
    }
}

async function save_policies(policies: PoliciesFile): Promise<void> {
    await mkdir(dirname(POLICIES_PATH), { recursive: true });
    const tmp_path = `${POLICIES_PATH}.${randomUUID()}.tmp`;
    await writeFile(tmp_path, JSON.stringify(policies, null, 4), "utf-8");
    await rename(tmp_path, POLICIES_PATH);
}

const server = new Server(
    {
        name: "trustengine",
        version: "1.0.0",
    },
    {
        capabilities: {
            tools: {},
        },
    },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
        {
            name: "grant_permission",
            description:
                "Request permission for a tool call that was denied by TrustEngine. " +
                "Provide a justification for why the action is needed and safe. " +
                "IMPORTANT: On your first denial, call with help=true BEFORE requesting any grants — " +
                "this returns guidelines on scoping, patterns, and philosophy that will help you " +
                "craft effective permission requests.",
            inputSchema: {
                type: "object" as const,
                properties: {
                    help: {
                        type: "boolean",
                        description: "Set to true to get TrustEngine guidelines without creating a rule",
                    },
                    tool: {
                        type: "string",
                        description:
                            "Regex pattern matching the tool name (e.g., 'Bash', 'Write|Edit')",
                    },
                    command_names: {
                        type: "array",
                        items: { type: "string" },
                        description:
                            "PREFERRED for Bash rules. List of command names to allow (e.g., ['curl', 'wget']). " +
                            "Compiles to a safe regex automatically. CANNOT be combined with 'match'.",
                    },
                    path_prefix: {
                        type: "string",
                        description:
                            "Use with command_names. Restrict to paths/URLs starting with this prefix " +
                            "(e.g., '/tmp/test/', 'https://example.com'). " +
                            "REQUIRED for destructive or network commands.",
                    },
                    allowed_flags: {
                        type: "array",
                        items: { type: "string" },
                        description:
                            "Use with command_names. Flags permitted before the path " +
                            "(e.g., ['-r', '-f', '--force']). Omit to allow no flags.",
                    },
                    match: {
                        type: "object",
                        additionalProperties: { type: "string" },
                        description:
                            "ADVANCED ONLY — raw regex match patterns. CANNOT be combined with " +
                            "command_names/path_prefix/allowed_flags. For Bash rules, prefer the " +
                            "structured fields above which are safer and auto-compiled.",
                    },
                    scope: {
                        type: "string",
                        enum: ["once", "session", "permanent"],
                        description:
                            "Prefer 'session' (current session) or 'permanent' (persists forever). " +
                            "Only use 'once' for truly one-time actions you won't repeat.",
                    },
                    justification: {
                        type: "string",
                        description: "Why this action is needed and safe (min 10 chars)",
                    },
                    description: {
                        type: "string",
                        description: "Human-readable rule description",
                    },
                    session_id: {
                        type: "string",
                        description:
                            "Session ID for once/session scopes (from deny message)",
                    },
                    acknowledged_risks: {
                        type: "array",
                        items: { type: "string" },
                        description:
                            "Risk IDs being acknowledged (e.g., ['risk-git-push', 'risk-network']). " +
                            "Required for 'escalate' tier risks — the human reviewing the grant " +
                            "can see which risks the agent is aware of. For 'acknowledge' tier " +
                            "risks, use the acknowledge_risk tool instead (no human approval needed).",
                    },
                    known_risks: {
                        type: "array",
                        items: {
                            type: "object",
                            properties: {
                                id: { type: "string" },
                                risk: { type: "string" },
                                severity: {
                                    type: "string",
                                    enum: ["block", "escalate", "acknowledge"],
                                },
                            },
                            required: ["id", "risk", "severity"],
                        },
                        description:
                            "For permanent rules: NEW risks to record for future deny-and-acknowledge flow. " +
                            "Each risk needs a unique id (e.g., 'risk-my-thing').",
                    },
                    add_safe_directory: {
                        type: "string",
                        description:
                            "Add an absolute directory path to the safe directories list. " +
                            "Rules using $SAFE will match paths under safe directories. " +
                            "Permissions cascade: anything allowed for $UNSAFE also applies to $SAFE.",
                    },
                    add_unsafe_directory: {
                        type: "string",
                        description:
                            "Add an absolute directory path to the unsafe directories list. " +
                            "Rules using $UNSAFE will match paths under unsafe directories.",
                    },
                    remove_safe_directory: {
                        type: "string",
                        description: "Remove a directory path from the safe directories list.",
                    },
                    remove_unsafe_directory: {
                        type: "string",
                        description: "Remove a directory path from the unsafe directories list.",
                    },
                    script: {
                        type: "string",
                        description:
                            "Full script content to approve and run. The human reviews the exact script. " +
                            "On approval, TrustEngine writes it to a trusted scripts directory and returns " +
                            "the command to execute it. Use this for complex operations that are hard to " +
                            "model with regex patterns. When using script, 'tool' is auto-set to 'Bash'. " +
                            "Include a shebang (e.g., #!/bin/bash) at the top.",
                    },
                    script_interpreter: {
                        type: "string",
                        enum: ["bash", "python", "python3", "node", "sh"],
                        description:
                            "Interpreter for the script (default: 'bash'). Determines file extension " +
                            "and the command used to invoke it.",
                    },
                },
                required: [],
            },
        },
        {
            name: "check_permission",
            description:
                "Pre-flight check: test whether a tool call would be allowed or denied " +
                "without actually executing it. Use this to plan ahead and request all " +
                "needed grants before attempting a multi-step operation. " +
                "Call with help=true to get TrustEngine guidelines without checking anything.",
            inputSchema: {
                type: "object" as const,
                properties: {
                    help: {
                        type: "boolean",
                        description: "Set to true to get TrustEngine guidelines without creating a rule",
                    },
                    tool_name: {
                        type: "string",
                        description: "The tool name to check (e.g., 'Bash', 'Write')",
                    },
                    tool_input: {
                        type: "object",
                        additionalProperties: {},
                        description: "The tool input to check (e.g., {command: 'curl https://example.com'})",
                    },
                    cwd: {
                        type: "string",
                        description: "Working directory for $CWD substitution",
                    },
                    session_id: {
                        type: "string",
                        description: "Session ID to include session grants in evaluation",
                    },
                },
                required: [],
            },
        },
        {
            name: "acknowledge_risk",
            description:
                "Acknowledge known risks for tool calls without requiring human approval. " +
                "Only works for 'acknowledge' tier risks — 'escalate' tier risks still " +
                "require grant_permission with human approval. Creates a session-scoped " +
                "grant that acknowledges the specified risk IDs.",
            inputSchema: {
                type: "object" as const,
                properties: {
                    risk_ids: {
                        type: "array",
                        items: { type: "string" },
                        description:
                            "Risk IDs to acknowledge (e.g., ['risk-rm', 'risk-file-overwrite']). " +
                            "Only 'acknowledge' tier risks can be self-served this way.",
                    },
                    tool: {
                        type: "string",
                        description:
                            "Regex pattern matching the tool name this acknowledgement applies to (e.g., 'Bash').",
                    },
                    match: {
                        type: "object",
                        additionalProperties: { type: "string" },
                        description:
                            "Optional match patterns to scope the acknowledgement (e.g., {command: '^rm'}).",
                    },
                    session_id: {
                        type: "string",
                        description: "Session ID (from deny message). Auto-detected if omitted.",
                    },
                },
                required: ["risk_ids", "tool"],
            },
        },
    ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
    if (request.params.name === "check_permission") {
        const args = (request.params.arguments ?? {}) as Record<string, unknown>;

        // Help mode — return guidelines
        if (args.help === true) {
            return {
                content: [{ type: "text" as const, text: load_help_text() }],
            };
        }

        const tool_name = args.tool_name as string;
        const tool_input = (args.tool_input ?? {}) as Record<string, unknown>;
        const cwd = (args.cwd as string) ?? process.cwd();
        const session_id = args.session_id as string | undefined;

        const policies = await load_or_create_policies();
        const session_grants = session_id
            ? await (await import("./session_store.js")).load_session_grants(session_id)
            : [];

        const result = (await import("./engine.js")).evaluate(
            policies,
            session_grants,
            tool_name,
            tool_input,
            cwd,
        );

        const status = result.decision === "allow" ? "ALLOWED" : "DENIED";
        let text = `${status}: ${result.reason}`;
        if (result.risk_warnings.length > 0) {
            text += "\n\nKnown risks:\n" +
                result.risk_warnings.map((r) => `  [${r.severity}] ${r.id}: ${r.risk}`).join("\n");
        }
        if (result.denied_commands && result.denied_commands.length > 0) {
            text += `\n\nDenied commands: ${result.denied_commands.join(", ")}`;
        }

        return {
            content: [{ type: "text" as const, text }],
        };
    }

    if (request.params.name === "acknowledge_risk") {
        const args = (request.params.arguments ?? {}) as Record<string, unknown>;
        const risk_ids = args.risk_ids as string[] | undefined;
        const tool = args.tool as string | undefined;
        const match = args.match as Record<string, string> | undefined;
        let session_id = args.session_id as string | undefined;

        if (!risk_ids || risk_ids.length === 0) {
            return {
                content: [{ type: "text" as const, text: "Error: 'risk_ids' is required and must not be empty." }],
                isError: true,
            };
        }

        if (!tool) {
            return {
                content: [{ type: "text" as const, text: "Error: 'tool' is required." }],
                isError: true,
            };
        }

        // Validate that all risk IDs are "acknowledge" tier
        const policies = await load_or_create_policies();
        const risk_map = new Map(policies.known_risks.map((r) => [r.id, r]));
        const errors: string[] = [];

        for (const id of risk_ids) {
            const risk = risk_map.get(id);
            if (!risk) {
                errors.push(`Unknown risk ID: "${id}"`);
            } else if (risk.severity === "block") {
                errors.push(`"${id}" is a block-tier risk — cannot be acknowledged`);
            } else if (risk.severity === "escalate") {
                errors.push(`"${id}" is an escalate-tier risk — requires grant_permission with human approval`);
            }
        }

        if (errors.length > 0) {
            return {
                content: [{
                    type: "text" as const,
                    text: `Error:\n${errors.map((e) => `  - ${e}`).join("\n")}`,
                }],
                isError: true,
            };
        }

        // Resolve session_id
        if (!session_id) {
            session_id = (await read_session_breadcrumb()) ?? undefined;
        }
        if (!session_id) {
            return {
                content: [{
                    type: "text" as const,
                    text: "Error: could not determine session_id. Pass it explicitly.",
                }],
                isError: true,
            };
        }

        // Create a session-scoped grant acknowledging these risks
        const rule: TrustRule = {
            id: `ack-${randomUUID().slice(0, 8)}`,
            tool,
            match,
            action: "allow",
            priority: 85,
            description: `[acknowledged] risks: ${risk_ids.join(", ")}`,
            scope: "session",
            acknowledged_risks: risk_ids,
        };

        await add_session_grant(session_id, rule);

        return {
            content: [{
                type: "text" as const,
                text:
                    `Risks acknowledged (session):\n` +
                    `  Risk IDs: ${risk_ids.join(", ")}\n` +
                    `  Tool: ${tool}\n` +
                    `  Match: ${match ? JSON.stringify(match) : "(any)"}\n\n` +
                    `You may now retry the tool call.`,
            }],
        };
    }

    if (request.params.name !== "grant_permission") {
        return {
            content: [
                {
                    type: "text" as const,
                    text: `Unknown tool: ${request.params.name}`,
                },
            ],
            isError: true,
        };
    }

    const args = (request.params.arguments ?? {}) as Record<string, unknown>;

    // Help mode
    if (args.help === true) {
        return {
            content: [{ type: "text" as const, text: load_help_text() }],
        };
    }

    // Directory management mode
    const add_safe = args.add_safe_directory as string | undefined;
    const add_unsafe = args.add_unsafe_directory as string | undefined;
    const remove_safe = args.remove_safe_directory as string | undefined;
    const remove_unsafe = args.remove_unsafe_directory as string | undefined;

    if (add_safe || add_unsafe || remove_safe || remove_unsafe) {
        const justification = args.justification as string | undefined;
        if (!justification || justification.length < 10) {
            return {
                content: [{
                    type: "text" as const,
                    text: "Error: 'justification' is required (min 10 chars) for directory management.",
                }],
                isError: true,
            };
        }

        // Validate paths are absolute
        for (const [label, path] of [
            ["add_safe_directory", add_safe],
            ["add_unsafe_directory", add_unsafe],
            ["remove_safe_directory", remove_safe],
            ["remove_unsafe_directory", remove_unsafe],
        ] as const) {
            if (path && !path.startsWith("/")) {
                return {
                    content: [{
                        type: "text" as const,
                        text: `Error: '${label}' must be an absolute path (starts with /). Got: "${path}"`,
                    }],
                    isError: true,
                };
            }
        }

        const policies = await load_or_create_policies();
        policies.safe_directories ??= [];
        policies.unsafe_directories ??= [];

        const changes: string[] = [];

        if (add_safe) {
            if (!policies.safe_directories.includes(add_safe)) {
                policies.safe_directories.push(add_safe);
                changes.push(`Added "${add_safe}" to safe directories`);
            } else {
                changes.push(`"${add_safe}" is already in safe directories`);
            }
        }

        if (add_unsafe) {
            if (!policies.unsafe_directories.includes(add_unsafe)) {
                policies.unsafe_directories.push(add_unsafe);
                changes.push(`Added "${add_unsafe}" to unsafe directories`);
            } else {
                changes.push(`"${add_unsafe}" is already in unsafe directories`);
            }
        }

        if (remove_safe) {
            const idx = policies.safe_directories.indexOf(remove_safe);
            if (idx !== -1) {
                policies.safe_directories.splice(idx, 1);
                changes.push(`Removed "${remove_safe}" from safe directories`);
            } else {
                changes.push(`"${remove_safe}" was not in safe directories`);
            }
        }

        if (remove_unsafe) {
            const idx = policies.unsafe_directories.indexOf(remove_unsafe);
            if (idx !== -1) {
                policies.unsafe_directories.splice(idx, 1);
                changes.push(`Removed "${remove_unsafe}" from unsafe directories`);
            } else {
                changes.push(`"${remove_unsafe}" was not in unsafe directories`);
            }
        }

        // Clean up empty arrays
        if (policies.safe_directories.length === 0) delete policies.safe_directories;
        if (policies.unsafe_directories.length === 0) delete policies.unsafe_directories;

        await save_policies(policies);

        return {
            content: [{
                type: "text" as const,
                text: `Directory classification updated:\n${changes.map((c) => `  - ${c}`).join("\n")}\n\nJustification: ${justification}`,
            }],
        };
    }

    // Script mode — write a reviewed script to the trusted scripts directory
    const script = args.script as string | undefined;

    if (script) {
        const scope = args.scope as string | undefined;
        const justification = args.justification as string | undefined;
        const description = args.description as string | undefined;
        const interpreter = (args.script_interpreter as string | undefined) ?? "bash";
        let session_id = args.session_id as string | undefined;
        const acknowledged_risks = args.acknowledged_risks as string[] | undefined;

        const ext_map: Record<string, string> = {
            bash: "sh", sh: "sh", python: "py", python3: "py", node: "mjs",
        };
        const ext = ext_map[interpreter] ?? "sh";

        if (!scope || !["once", "session", "permanent"].includes(scope)) {
            return {
                content: [{ type: "text" as const, text: "Error: 'scope' is required for script grants." }],
                isError: true,
            };
        }

        if (!justification || justification.length < 10) {
            return {
                content: [{ type: "text" as const, text: "Error: 'justification' is required (min 10 chars)." }],
                isError: true,
            };
        }

        if (!description) {
            return {
                content: [{ type: "text" as const, text: "Error: 'description' is required for script grants." }],
                isError: true,
            };
        }

        // Resolve session_id
        if (scope === "once" || scope === "session") {
            if (!session_id) {
                session_id = (await read_session_breadcrumb()) ?? undefined;
            }
            if (!session_id) {
                return {
                    content: [{ type: "text" as const, text: "Error: 'session_id' is required for once/session scopes." }],
                    isError: true,
                };
            }
        }

        // Write the script
        await mkdir(SCRIPTS_DIR, { recursive: true });
        const script_id = `script-${randomUUID().slice(0, 8)}`;
        const script_path = join(SCRIPTS_DIR, `${script_id}.${ext}`);
        await writeFile(script_path, script, "utf-8");
        await chmod(script_path, 0o755);

        // Build the command that runs this script
        const run_command = `${interpreter} ${script_path}`;
        const escaped_path = escape_regex(script_path);
        const match = { command: `^${escape_regex(interpreter)} +${escaped_path}$` };

        const rule: TrustRule = {
            id: script_id,
            tool: "Bash",
            match,
            action: "allow",
            priority: 85,
            description: `[script] ${description}`,
            scope: scope as "once" | "session" | "permanent",
            acknowledged_risks: acknowledged_risks && acknowledged_risks.length > 0
                ? acknowledged_risks
                : undefined,
        };

        if (scope === "once" || scope === "session") {
            await add_session_grant(session_id!, rule);
        } else {
            const policies = await load_or_create_policies();
            policies.rules.push({ ...rule, scope: undefined });
            await save_policies(policies);
        }

        return {
            content: [{
                type: "text" as const,
                text:
                    `Script approved (${scope}):\n` +
                    `  Script ID: ${script_id}\n` +
                    `  Path: ${script_path}\n` +
                    `  Run command: ${run_command}\n` +
                    `  Description: ${description}\n` +
                    (acknowledged_risks && acknowledged_risks.length > 0
                        ? `  Acknowledged risks: ${acknowledged_risks.join(", ")}\n`
                        : "") +
                    `\nExecute the script with: ${run_command}`,
            }],
        };
    }

    // Validate required fields
    const tool = args.tool as string | undefined;
    const scope = args.scope as string | undefined;
    const justification = args.justification as string | undefined;
    const description = args.description as string | undefined;
    let match = args.match as Record<string, string> | undefined;
    const known_risks = args.known_risks as KnownRisk[] | undefined;
    let session_id = args.session_id as string | undefined;

    // Structured matcher fields (compile to match.command)
    const command_names = args.command_names as string[] | undefined;
    const path_prefix = args.path_prefix as string | undefined;
    const allowed_flags = args.allowed_flags as string[] | undefined;

    if (!tool) {
        return {
            content: [
                {
                    type: "text" as const,
                    text: "Error: 'tool' parameter is required. Provide a regex pattern matching the tool name.",
                },
            ],
            isError: true,
        };
    }

    if (!scope || !["once", "session", "permanent"].includes(scope)) {
        return {
            content: [
                {
                    type: "text" as const,
                    text: "Error: 'scope' must be one of: once, session, permanent",
                },
            ],
            isError: true,
        };
    }

    if (!justification || justification.length < 10) {
        return {
            content: [
                {
                    type: "text" as const,
                    text: "Error: 'justification' is required and must be at least 10 characters. Explain why this action is needed and safe.",
                },
            ],
            isError: true,
        };
    }

    if (!description) {
        return {
            content: [
                {
                    type: "text" as const,
                    text: "Error: 'description' is required. Provide a human-readable rule description.",
                },
            ],
            isError: true,
        };
    }

    // Validate regex patterns
    if (!validate_regex(tool)) {
        return {
            content: [
                {
                    type: "text" as const,
                    text: `Error: Invalid regex pattern for 'tool': "${tool}"`,
                },
            ],
            isError: true,
        };
    }

    if (!is_safe_regex(tool)) {
        return {
            content: [
                {
                    type: "text" as const,
                    text: `Error: Tool pattern "${tool}" is potentially unsafe (ReDoS risk). Use a simpler pattern.`,
                },
            ],
            isError: true,
        };
    }

    if (is_overly_broad(tool)) {
        return {
            content: [
                {
                    type: "text" as const,
                    text: `Error: Tool pattern "${tool}" is too broad. Use a specific pattern like "Bash" or "Write|Edit".`,
                },
            ],
            isError: true,
        };
    }

    // Compile structured matchers if provided
    if (command_names && command_names.length > 0) {
        if (match) {
            return {
                content: [
                    {
                        type: "text" as const,
                        text: "Error: Cannot use both 'match' and structured fields (command_names/path_prefix/allowed_flags). Use one or the other.",
                    },
                ],
                isError: true,
            };
        }

        const compiled = compile_structured_match(
            command_names,
            path_prefix,
            allowed_flags,
        );

        if (compiled.error) {
            return {
                content: [
                    {
                        type: "text" as const,
                        text: `Error compiling structured match: ${compiled.error}`,
                    },
                ],
                isError: true,
            };
        }

        match = { command: compiled.pattern };
    }

    if (match) {
        for (const [param, pattern] of Object.entries(match)) {
            if (!validate_regex(pattern)) {
                return {
                    content: [
                        {
                            type: "text" as const,
                            text: `Error: Invalid regex for match parameter "${param}": "${pattern}"`,
                        },
                    ],
                    isError: true,
                };
            }
            if (!is_safe_regex(pattern)) {
                return {
                    content: [
                        {
                            type: "text" as const,
                            text: `Error: Match pattern for "${param}" is potentially unsafe (ReDoS risk). Use a simpler pattern.`,
                        },
                    ],
                    isError: true,
                };
            }
        }
    }

    // Resolve session_id for once/session scopes
    if (scope === "once" || scope === "session") {
        if (!session_id) {
            session_id = (await read_session_breadcrumb()) ?? undefined;
        }
        if (!session_id) {
            return {
                content: [
                    {
                        type: "text" as const,
                        text: "Error: 'session_id' is required for once/session scopes. Check the deny message for the session ID.",
                    },
                ],
                isError: true,
            };
        }
    }

    const acknowledged_risks = args.acknowledged_risks as string[] | undefined;

    const rule: TrustRule = {
        id: `grant-${randomUUID().slice(0, 8)}`,
        tool,
        match,
        action: "allow",
        priority: 85,
        description: `[granted] ${description}`,
        scope: scope as "once" | "session" | "permanent",
        acknowledged_risks: acknowledged_risks && acknowledged_risks.length > 0
            ? acknowledged_risks
            : undefined,
    };

    if (scope === "once" || scope === "session") {
        await add_session_grant(session_id!, rule);

        return {
            content: [
                {
                    type: "text" as const,
                    text:
                        `Permission granted (${scope}):\n` +
                        `  Rule ID: ${rule.id}\n` +
                        `  Tool: ${tool}\n` +
                        `  Match: ${match ? JSON.stringify(match) : "(any)"}\n` +
                        `  Description: ${rule.description}\n` +
                        `  Justification: ${justification}\n` +
                        (acknowledged_risks && acknowledged_risks.length > 0
                            ? `  Acknowledged risks: ${acknowledged_risks.join(", ")}\n`
                            : "") +
                        `\nYou may now retry the tool call.` +
                        (scope === "once"
                            ? " This grant will be consumed after one use."
                            : ""),
                },
            ],
        };
    }

    // Permanent scope — write to policies.json
    const policies = await load_or_create_policies();
    policies.rules.push({ ...rule, scope: undefined });

    // Write associated known_risks
    if (known_risks && known_risks.length > 0) {
        for (const kr of known_risks) {
            policies.known_risks.push({
                id: kr.id,
                tool,
                match,
                risk: kr.risk,
                severity: kr.severity,
            });
        }
    }

    await save_policies(policies);

    return {
        content: [
            {
                type: "text" as const,
                text:
                    `Permanent rule added to policies.json:\n` +
                    `  Rule ID: ${rule.id}\n` +
                    `  Tool: ${tool}\n` +
                    `  Match: ${match ? JSON.stringify(match) : "(any)"}\n` +
                    `  Description: ${rule.description}\n` +
                    `  Justification: ${justification}\n` +
                    (acknowledged_risks && acknowledged_risks.length > 0
                        ? `  Acknowledged risks: ${acknowledged_risks.join(", ")}\n`
                        : "") +
                    (known_risks && known_risks.length > 0
                        ? `  New risks recorded: ${known_risks.map((r) => r.id).join(", ")}\n`
                        : "") +
                    `\nYou may now retry the tool call.`,
            },
        ],
    };
});

async function main(): Promise<void> {
    const transport = new StdioServerTransport();
    await server.connect(transport);
}

main().catch((err) => {
    console.error("TrustEngine MCP server error:", err);
    process.exit(1);
});
