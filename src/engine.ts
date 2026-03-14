import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import type {
    PoliciesFile,
    OverlayFile,
    TrustRule,
    KnownRisk,
    EvaluationResult,
} from "./types.js";

export async function load_policies(path: string): Promise<PoliciesFile> {
    const raw = await readFile(path, "utf-8");
    const data = JSON.parse(raw) as PoliciesFile;
    if (data.version == null || !Array.isArray(data.rules)) {
        throw new Error("Invalid policies file: missing version or rules");
    }
    data.known_risks ??= [];
    return data;
}

export async function load_overlays(overlays_dir: string): Promise<OverlayFile[]> {
    let entries: string[];
    try {
        entries = await readdir(overlays_dir);
    } catch {
        return [];
    }

    const json_files = entries
        .filter((f) => f.endsWith(".json"))
        .sort(); // alphabetical order for deterministic merge

    const overlays: OverlayFile[] = [];
    for (const file of json_files) {
        try {
            const raw = await readFile(join(overlays_dir, file), "utf-8");
            const data = JSON.parse(raw) as OverlayFile;
            if (data.version == null) continue; // skip invalid files
            overlays.push(data);
        } catch {
            // Skip unparseable overlay files
            continue;
        }
    }
    return overlays;
}

export function merge_policies_with_overlays(
    base: PoliciesFile,
    overlays: OverlayFile[],
): PoliciesFile {
    const merged: PoliciesFile = {
        version: base.version,
        rules: [...base.rules],
        known_risks: [...base.known_risks],
        safe_directories: base.safe_directories ? [...base.safe_directories] : undefined,
        unsafe_directories: base.unsafe_directories ? [...base.unsafe_directories] : undefined,
    };

    for (const overlay of overlays) {
        // Remove rules by ID
        if (overlay.remove_rules && overlay.remove_rules.length > 0) {
            const remove_set = new Set(overlay.remove_rules);
            merged.rules = merged.rules.filter((r) => !remove_set.has(r.id));
        }

        // Remove risks by ID
        if (overlay.remove_risks && overlay.remove_risks.length > 0) {
            const remove_set = new Set(overlay.remove_risks);
            merged.known_risks = merged.known_risks.filter((r) => !remove_set.has(r.id));
        }

        // Add rules
        if (overlay.rules && overlay.rules.length > 0) {
            merged.rules.push(...overlay.rules);
        }

        // Add risks
        if (overlay.known_risks && overlay.known_risks.length > 0) {
            merged.known_risks.push(...overlay.known_risks);
        }

        // Union safe directories
        if (overlay.safe_directories && overlay.safe_directories.length > 0) {
            merged.safe_directories ??= [];
            for (const dir of overlay.safe_directories) {
                if (!merged.safe_directories.includes(dir)) {
                    merged.safe_directories.push(dir);
                }
            }
        }

        // Union unsafe directories
        if (overlay.unsafe_directories && overlay.unsafe_directories.length > 0) {
            merged.unsafe_directories ??= [];
            for (const dir of overlay.unsafe_directories) {
                if (!merged.unsafe_directories.includes(dir)) {
                    merged.unsafe_directories.push(dir);
                }
            }
        }
    }

    return merged;
}

export function substitute_variables(
    pattern: string,
    cwd: string,
    safe_dirs?: string[],
    unsafe_dirs?: string[],
): string {
    const escaped_cwd = cwd.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

    let result = pattern.replace(/\$NOTCWD/g, `(?!${escaped_cwd}/)`);
    result = result.replace(/\$CWD/g, escaped_cwd);

    const resolve_dir = (d: string): string => {
        // $NOTCWD is a regex-level macro — expand it directly, not as a path
        if (d === "$NOTCWD") return `(?!${escaped_cwd}/)`;
        const resolved = d.replace(/\$CWD/g, cwd);
        return resolved.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    };

    if (safe_dirs && safe_dirs.length > 0) {
        const escaped = safe_dirs.map(resolve_dir);
        const alt = escaped.length === 1 ? escaped[0] : `(${escaped.join("|")})`;
        result = result.replace(/\$SAFE/g, alt);
    } else {
        // Replace $SAFE with a pattern that never matches any real path
        result = result.replace(/\$SAFE/g, "\\x00NOMATCH");
    }

    if (unsafe_dirs && unsafe_dirs.length > 0) {
        const escaped = unsafe_dirs.map(resolve_dir);
        const alt = escaped.length === 1 ? escaped[0] : `(${escaped.join("|")})`;
        result = result.replace(/\$UNSAFE/g, alt);
    } else {
        result = result.replace(/\$UNSAFE/g, "\\x00NOMATCH");
    }

    return result;
}

export function matches_rule(
    rule: TrustRule,
    tool_name: string,
    tool_input: Record<string, unknown>,
    cwd: string,
    safe_dirs?: string[],
    unsafe_dirs?: string[],
): boolean {
    const tool_pattern = substitute_variables(rule.tool, cwd, safe_dirs, unsafe_dirs);
    try {
        if (!new RegExp(`^(?:${tool_pattern})$`).test(tool_name)) {
            return false;
        }
    } catch {
        return false;
    }

    if (rule.match) {
        for (const [param, pattern] of Object.entries(rule.match)) {
            const value = tool_input[param];
            if (value === undefined || value === null) {
                return false;
            }
            const substituted = substitute_variables(pattern, cwd, safe_dirs, unsafe_dirs);
            try {
                if (!new RegExp(substituted).test(String(value))) {
                    return false;
                }
            } catch {
                return false;
            }
        }
    }

    return true;
}

export function find_matching_risks(
    risks: KnownRisk[],
    tool_name: string,
    tool_input: Record<string, unknown>,
    cwd: string,
    safe_dirs?: string[],
    unsafe_dirs?: string[],
): KnownRisk[] {
    const matched: KnownRisk[] = [];
    for (const risk of risks) {
        const tool_pattern = substitute_variables(risk.tool, cwd, safe_dirs, unsafe_dirs);
        try {
            if (!new RegExp(`^(?:${tool_pattern})$`).test(tool_name)) {
                continue;
            }
        } catch {
            continue;
        }

        if (risk.match) {
            let all_match = true;
            for (const [param, pattern] of Object.entries(risk.match)) {
                const value = tool_input[param];
                if (value === undefined || value === null) {
                    all_match = false;
                    break;
                }
                const substituted = substitute_variables(pattern, cwd, safe_dirs, unsafe_dirs);
                try {
                    if (!new RegExp(substituted).test(String(value))) {
                        all_match = false;
                        break;
                    }
                } catch {
                    all_match = false;
                    break;
                }
            }
            if (!all_match) continue;
        }

        matched.push(risk);
    }
    return matched;
}

export function split_bash_command(command: string): string[] {
    const commands: string[] = [];
    let current = "";
    let in_single_quote = false;
    let in_double_quote = false;
    let escape_next = false;
    let paren_depth = 0;

    for (let i = 0; i < command.length; i++) {
        const ch = command[i];

        if (escape_next) {
            current += ch;
            escape_next = false;
            continue;
        }

        if (ch === "\\" && !in_single_quote) {
            escape_next = true;
            current += ch;
            continue;
        }

        if (ch === "'" && !in_double_quote) {
            in_single_quote = !in_single_quote;
            current += ch;
            continue;
        }

        if (ch === '"' && !in_single_quote) {
            in_double_quote = !in_double_quote;
            current += ch;
            continue;
        }

        if (in_single_quote || in_double_quote) {
            current += ch;
            continue;
        }

        // Heredoc detection: <<[-]?['"]?WORD['"]?
        // Consume everything until WORD appears on its own line
        if (
            ch === "<" &&
            i + 1 < command.length &&
            command[i + 1] === "<" &&
            paren_depth === 0
        ) {
            current += "<<";
            let j = i + 2;
            // Optional '-' for tab-stripping heredocs
            if (j < command.length && command[j] === "-") {
                current += "-";
                j++;
            }
            // Skip whitespace between << and delimiter
            while (j < command.length && command[j] === " ") {
                current += " ";
                j++;
            }
            // Extract delimiter (strip surrounding quotes if present)
            let delimiter = "";
            const quote_ch = j < command.length ? command[j] : "";
            if (quote_ch === "'" || quote_ch === '"') {
                current += quote_ch;
                j++;
                while (j < command.length && command[j] !== quote_ch) {
                    delimiter += command[j];
                    current += command[j];
                    j++;
                }
                if (j < command.length) {
                    current += command[j]; // closing quote
                    j++;
                }
            } else {
                while (j < command.length && /[a-zA-Z0-9_]/.test(command[j])) {
                    delimiter += command[j];
                    current += command[j];
                    j++;
                }
            }

            // Now consume everything until delimiter appears on its own line
            if (delimiter) {
                while (j < command.length) {
                    current += command[j];
                    // Check if we're at a newline followed by the delimiter on its own line
                    if (command[j] === "\n") {
                        const remaining = command.slice(j + 1);
                        if (
                            remaining === delimiter ||
                            remaining.startsWith(delimiter + "\n") ||
                            remaining.startsWith(delimiter + "\r")
                        ) {
                            // Consume the delimiter
                            for (let k = 0; k < delimiter.length; k++) {
                                j++;
                                current += command[j];
                            }
                            break;
                        }
                    }
                    j++;
                }
            }
            i = j;
            continue;
        }

        // Track $() subshell depth — consume both $ and ( in one step
        if (ch === "$" && i + 1 < command.length && command[i + 1] === "(") {
            paren_depth++;
            current += "$(";
            i++; // skip the '(' so it isn't double-counted
            continue;
        }

        if (ch === "(" && paren_depth > 0) {
            paren_depth++;
            current += ch;
            continue;
        }

        if (ch === ")" && paren_depth > 0) {
            paren_depth--;
            current += ch;
            continue;
        }

        // Don't split inside subshells
        if (paren_depth > 0) {
            current += ch;
            continue;
        }

        // Split on ; && ||
        if (ch === ";") {
            const trimmed = current.trim();
            if (trimmed) commands.push(trimmed);
            current = "";
            continue;
        }

        if (ch === "&" && i + 1 < command.length && command[i + 1] === "&") {
            const trimmed = current.trim();
            if (trimmed) commands.push(trimmed);
            current = "";
            i++; // skip second &
            continue;
        }

        if (ch === "|" && i + 1 < command.length && command[i + 1] === "|") {
            const trimmed = current.trim();
            if (trimmed) commands.push(trimmed);
            current = "";
            i++; // skip second |
            continue;
        }

        // Split on pipe (single |)
        if (ch === "|") {
            const trimmed = current.trim();
            if (trimmed) commands.push(trimmed);
            current = "";
            continue;
        }

        current += ch;
    }

    const trimmed = current.trim();
    if (trimmed) commands.push(trimmed);

    // Extract commands from backtick substitutions (quote-aware)
    const backtick_cmds = extract_backtick_commands(command);
    commands.push(...backtick_cmds);

    // Extract commands from $() substitutions
    const subshell_cmds = extract_subshell_commands(command);
    commands.push(...subshell_cmds);

    return commands;
}

function extract_backtick_commands(command: string): string[] {
    const results: string[] = [];
    let in_single_quote = false;
    let in_double_quote = false;
    let escape_next = false;
    let i = 0;

    while (i < command.length) {
        const ch = command[i];

        if (escape_next) {
            escape_next = false;
            i++;
            continue;
        }

        if (ch === "\\" && !in_single_quote) {
            escape_next = true;
            i++;
            continue;
        }

        if (ch === "'" && !in_double_quote) {
            in_single_quote = !in_single_quote;
            i++;
            continue;
        }

        if (ch === '"' && !in_single_quote) {
            in_double_quote = !in_double_quote;
            i++;
            continue;
        }

        // Only extract backticks outside of single quotes
        if (ch === "`" && !in_single_quote) {
            let j = i + 1;
            let inner_escape = false;
            while (j < command.length) {
                if (inner_escape) {
                    inner_escape = false;
                    j++;
                    continue;
                }
                if (command[j] === "\\") {
                    inner_escape = true;
                    j++;
                    continue;
                }
                if (command[j] === "`") break;
                j++;
            }
            if (j < command.length) {
                const inner = command.slice(i + 1, j).trim();
                if (inner) {
                    const inner_cmds = split_bash_command(inner);
                    results.push(...inner_cmds);
                }
                i = j + 1;
            } else {
                i++;
            }
            continue;
        }

        i++;
    }

    return results;
}

function extract_subshell_commands(command: string): string[] {
    const results: string[] = [];
    let in_single_quote = false;
    let in_double_quote = false;
    let escape_next = false;
    let i = 0;

    while (i < command.length) {
        const ch = command[i];

        if (escape_next) {
            escape_next = false;
            i++;
            continue;
        }

        if (ch === "\\" && !in_single_quote) {
            escape_next = true;
            i++;
            continue;
        }

        if (ch === "'" && !in_double_quote) {
            in_single_quote = !in_single_quote;
            i++;
            continue;
        }

        if (ch === '"' && !in_single_quote) {
            in_double_quote = !in_double_quote;
            i++;
            continue;
        }

        // Only extract $() outside of single quotes
        if (ch === "$" && !in_single_quote && i + 1 < command.length && command[i + 1] === "(") {
            let depth = 1;
            let start = i + 2;
            let j = start;
            while (j < command.length && depth > 0) {
                if (command[j] === "(") depth++;
                else if (command[j] === ")") depth--;
                j++;
            }
            if (depth === 0) {
                const inner = command.slice(start, j - 1).trim();
                if (inner) {
                    const inner_cmds = split_bash_command(inner);
                    results.push(...inner_cmds);
                }
            }
            i = j;
        } else {
            i++;
        }
    }

    return results;
}

function evaluate_single(
    all_rules: TrustRule[],
    known_risks: KnownRisk[],
    tool_name: string,
    tool_input: Record<string, unknown>,
    cwd: string,
    safe_dirs?: string[],
    unsafe_dirs?: string[],
): EvaluationResult {
    // Sort: highest priority first, deny before allow at same priority
    const sorted = [...all_rules].sort((a, b) => {
        if (b.priority !== a.priority) return b.priority - a.priority;
        if (a.action === "deny" && b.action === "allow") return -1;
        if (a.action === "allow" && b.action === "deny") return 1;
        return 0;
    });

    // Find first matching rule
    for (const rule of sorted) {
        if (matches_rule(rule, tool_name, tool_input, cwd, safe_dirs, unsafe_dirs)) {
            const risk_warnings = find_matching_risks(
                known_risks,
                tool_name,
                tool_input,
                cwd,
                safe_dirs,
                unsafe_dirs,
            );

            if (rule.action === "allow" && risk_warnings.length > 0) {
                // "block" tier risks are unconditional — no acknowledgement possible
                const blockers = risk_warnings.filter((r) => r.severity === "block");
                if (blockers.length > 0) {
                    return {
                        decision: "deny",
                        matched_rule: rule,
                        risk_warnings: blockers,
                        reason: `Blocked by known risks (no override possible): ${blockers.map((r) => `${r.id} (${r.risk})`).join("; ")}`,
                    };
                }

                // "escalate" and "acknowledge" risks can be acknowledged by ID
                const ack = new Set(rule.acknowledged_risks ?? []);
                const unacknowledged = risk_warnings.filter(
                    (r) => !ack.has(r.id),
                );

                if (unacknowledged.length > 0) {
                    return {
                        decision: "deny",
                        matched_rule: rule,
                        risk_warnings: unacknowledged,
                        reason: `Allowed by rule "${rule.description}" but blocked due to unacknowledged risks: ${unacknowledged.map((r) => `${r.id} (${r.risk})`).join("; ")}`,
                    };
                }
                // All risks acknowledged by ID — fall through to allow
            }

            return {
                decision: rule.action,
                matched_rule: rule,
                risk_warnings: [],
                reason:
                    rule.action === "allow"
                        ? `Allowed by rule: ${rule.description}`
                        : `Denied by rule: ${rule.description}`,
            };
        }
    }

    // No rule matched — default deny, but still surface any known risks
    const risk_warnings = find_matching_risks(
        known_risks,
        tool_name,
        tool_input,
        cwd,
        safe_dirs,
        unsafe_dirs,
    );

    const risk_suffix =
        risk_warnings.length > 0
            ? `. Known risks: ${risk_warnings.map((r) => r.risk).join("; ")}`
            : "";

    return {
        decision: "deny",
        matched_rule: undefined,
        risk_warnings,
        reason: `No matching rule found for tool "${tool_name}" — default deny${risk_suffix}`,
    };
}

export function evaluate(
    policies: PoliciesFile,
    session_grants: TrustRule[],
    tool_name: string,
    tool_input: Record<string, unknown>,
    cwd: string,
): EvaluationResult {
    const all_rules = [...policies.rules, ...session_grants];
    const safe_dirs = policies.safe_directories;
    const unsafe_dirs = policies.unsafe_directories;

    // Special handling for Bash tool: evaluate each sub-command independently
    if (tool_name === "Bash" && typeof tool_input.command === "string") {
        // First: check the FULL unsplit command against deny-only rules.
        // This catches cross-pipe patterns like "curl ... | bash" that
        // disappear after splitting on pipe.
        const deny_rules = all_rules.filter((r) => r.action === "deny");
        const full_deny = evaluate_single(
            deny_rules,
            policies.known_risks,
            tool_name,
            tool_input,
            cwd,
            safe_dirs,
            unsafe_dirs,
        );
        if (full_deny.decision === "deny" && full_deny.matched_rule) {
            return full_deny;
        }

        const sub_commands = split_bash_command(tool_input.command);

        if (sub_commands.length === 0) {
            return {
                decision: "deny",
                matched_rule: undefined,
                risk_warnings: [],
                reason: "Empty bash command — default deny",
            };
        }

        const failures: { sub_cmd: string; result: EvaluationResult }[] = [];
        const all_risks: KnownRisk[] = [];
        const once_grants: string[] = [];

        for (const sub_cmd of sub_commands) {
            const sub_input = { ...tool_input, command: sub_cmd };
            const result = evaluate_single(
                all_rules,
                policies.known_risks,
                tool_name,
                sub_input,
                cwd,
                safe_dirs,
                unsafe_dirs,
            );

            if (result.decision === "deny") {
                failures.push({ sub_cmd, result });
                all_risks.push(...result.risk_warnings);
            } else if (
                result.matched_rule?.scope === "once" &&
                result.matched_rule.id
            ) {
                once_grants.push(result.matched_rule.id);
            }
        }

        if (failures.length > 0) {
            // Extract the base command name from each failed sub-command
            const denied_cmds = failures.map((f) => {
                const match = f.sub_cmd.match(/^\s*(\S+)/);
                return match ? match[1] : f.sub_cmd;
            });
            const unique_cmds = [...new Set(denied_cmds)];

            const details = failures
                .map((f) => `\`${f.sub_cmd}\`: ${f.result.reason}`)
                .join("\n");
            return {
                decision: "deny",
                matched_rule: failures[0].result.matched_rule,
                risk_warnings: all_risks,
                reason: failures.length === 1
                    ? `Sub-command denied: ${details}`
                    : `${failures.length} sub-commands denied:\n${details}`,
                denied_commands: unique_cmds,
                denied_sub_commands: failures.map((f) => f.sub_cmd),
            };
        }

        // All sub-commands allowed
        return {
            decision: "allow",
            matched_rule: undefined,
            risk_warnings: [],
            reason: `All ${sub_commands.length} sub-command(s) allowed`,
            once_grants_consumed: once_grants.length > 0 ? once_grants : undefined,
        };
    }

    return evaluate_single(
        all_rules,
        policies.known_risks,
        tool_name,
        tool_input,
        cwd,
        safe_dirs,
        unsafe_dirs,
    );
}
