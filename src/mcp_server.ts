import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { readFile, writeFile, mkdir, rename } from "node:fs/promises";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { randomUUID } from "node:crypto";
import type { PoliciesFile, TrustRule, KnownRisk } from "./types.js";
import { is_safe_regex } from "./engine.js";
import {
    add_session_grant,
    read_session_breadcrumb,
} from "./session_store.js";

const POLICIES_PATH = join(homedir(), ".config", "trustengine", "policies.json");

const HELP_TEXT = `# TrustEngine — Grant Permission Guide

## Philosophy
- Read-only operations are safe and pre-allowed
- Local project mutations (Write/Edit within $CWD) are generally fine
- Remote, system-level, or destructive mutations require explicit justification

## How It Works
1. Your tool calls are evaluated against policies (rules + known risks)
2. If denied, you can request access via this grant_permission tool
3. Provide a clear justification explaining WHY the action is needed and safe

## Choosing a Scope
Think about whether the action is a one-off or a recurring pattern before choosing:
- **once**: Use for truly one-time actions. Consumed after a single use.
- **session**: Use when you'll need this permission repeatedly during the current task (e.g., "I'll be running rm several times to clean up temp files"). Valid for the current session only.
- **permanent**: Use when this is a general capability the user will always need (e.g., "Allow git push to origin"). Written to policies.json, persists across sessions.

Prefer session or permanent over repeated one-off grants. If you find yourself requesting the same permission more than once, upgrade to a broader scope.

## Required Parameters
- **tool**: Regex matching the tool name (e.g., "Bash", "Write|Edit")
- **scope**: "once" | "session" | "permanent"
- **justification**: Why this is needed and safe (min 10 chars)
- **description**: Human-readable rule description (e.g., "Allow curl to fetch API docs")

## Optional Parameters
- **match**: Dict of param regex patterns (e.g., {"command": "^git push"})
- **session_id**: Required for once/session scopes (check your deny message for the ID)
- **known_risks**: ONLY for permanent rules — records risks so future invocations trigger the deny-and-acknowledge flow. Not needed for once/session grants (risks are auto-acknowledged from policies).

## Structured Matchers (preferred for Bash rules)
Instead of writing raw regex, use these fields for safe, readable patterns:
- **command_names**: ["rm", "rmdir"] — which commands to allow
- **path_prefix**: "/tmp/test/" — restrict to this directory (required for destructive commands)
- **allowed_flags**: ["-r", "-f", "--force"] — which flags are permitted (omit to allow none)

These compile to a safe regex automatically. Example:
  command_names: ["rm", "rmdir"], path_prefix: "/tmp/test/", allowed_flags: ["-r"]
  → compiles to: ^(rm|rmdir)\\s+(-[r]+\\s+)*/tmp/test/

Use raw **match** only for advanced cases the structured format can't express.

## Raw Match Patterns (advanced)
If you must use raw regex:
- Scope to a directory: "^curl\\s+https://example\\.com" not "^curl\\b"
- Combine related commands: "^(rm|rmdir)\\s+/tmp/" covers both in one rule
- Use \\b word boundaries to avoid partial matches

## Other Tips
- The deny message includes your session_id — pass it back here
- For permanent rules, include known_risks so future invocations get risk warnings
`;

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
        flags_part = `(${flag_alt}\\s+)*`;
    }

    let path_part = "";
    if (path_prefix) {
        path_part = escape_regex(path_prefix);
    }

    const pattern = `^${cmd_part}\\s+${flags_part}${path_part}`;
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
                    known_risks: {
                        type: "array",
                        items: {
                            type: "object",
                            properties: {
                                risk: { type: "string" },
                                severity: {
                                    type: "string",
                                    enum: ["low", "medium", "high"],
                                },
                            },
                            required: ["risk", "severity"],
                        },
                        description:
                            "For permanent rules: risks to record for future deny-and-acknowledge flow",
                    },
                    help: {
                        type: "boolean",
                        description: "Set to true to get TrustEngine guidelines without creating a rule",
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
                "needed grants before attempting a multi-step operation.",
            inputSchema: {
                type: "object" as const,
                properties: {
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
                required: ["tool_name", "tool_input"],
            },
        },
    ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
    if (request.params.name === "check_permission") {
        const args = (request.params.arguments ?? {}) as Record<string, unknown>;
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
                result.risk_warnings.map((r) => `  [${r.severity.toUpperCase()}] ${r.risk}`).join("\n");
        }
        if (result.denied_commands && result.denied_commands.length > 0) {
            text += `\n\nDenied commands: ${result.denied_commands.join(", ")}`;
        }

        return {
            content: [{ type: "text" as const, text }],
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
            content: [{ type: "text" as const, text: HELP_TEXT }],
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

    // Human approved this grant, so all risks are acknowledged
    const rule: TrustRule = {
        id: `grant-${randomUUID().slice(0, 8)}`,
        tool,
        match,
        action: "allow",
        priority: 85,
        description: `[granted] ${description}`,
        scope: scope as "once" | "session" | "permanent",
        risks_acknowledged: true,
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
                        `  Justification: ${justification}\n\n` +
                        `You may now retry the tool call.` +
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
                    (known_risks && known_risks.length > 0
                        ? `  Known risks recorded: ${known_risks.length}\n`
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
