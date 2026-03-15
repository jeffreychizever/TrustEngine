import { readFile, readdir } from "node:fs/promises";
import { realpathSync } from "node:fs";
import { join, resolve as path_resolve } from "node:path";
import { homedir } from "node:os";
import type {
    PoliciesFile,
    OverlayFile,
    TrustRule,
    KnownRisk,
    EvaluationResult,
} from "./types.js";

// ---------------------------------------------------------------------------
// Types for resolved directory state and evaluation context
// ---------------------------------------------------------------------------

export interface ResolvedDirs {
    dirs: string[];       // canonical directory paths (realpath'd where possible)
    has_notcwd: boolean;  // true if $NOTCWD was in the original list
}

export interface EvalContext {
    cwd: string;           // original CWD — used for $CWD/$NOTCWD substitution (never changes)
    effective_cwd: string; // may differ after cd in a command chain — used for $SAFE/$UNSAFE path resolution
    resolved_cwd: string;  // realpath'd cwd
    safe: ResolvedDirs;
    unsafe: ResolvedDirs;
}

/**
 * Context for $SAFE_CMD recursive evaluation. Carries the rules and risks
 * needed to evaluate captured command fragments, plus a depth counter to
 * prevent infinite recursion.
 *
 * Only passed to matches_rule (not find_matching_risks) — risks should
 * never contain $SAFE_CMD, and any __safe_cmd__ captures fail-closed
 * when this context is absent.
 */
interface RecursiveEvalContext {
    all_rules: TrustRule[];
    known_risks: KnownRisk[];
    depth: number;
    max_depth: number;
}

const MAX_SAFE_CMD_DEPTH = 3;

// ---------------------------------------------------------------------------
// Policy / overlay loading (unchanged)
// ---------------------------------------------------------------------------

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
        // Remove rules by ID (skip protected rules — these are core safety rules
        // that cannot be disabled via overlays)
        if (overlay.remove_rules && overlay.remove_rules.length > 0) {
            const remove_set = new Set(overlay.remove_rules);
            merged.rules = merged.rules.filter(
                (r) => r.protected || !remove_set.has(r.id),
            );
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

// ---------------------------------------------------------------------------
// Directory and path resolution
// ---------------------------------------------------------------------------

/**
 * Resolve a list of directory entries (from safe_directories / unsafe_directories)
 * into canonical filesystem paths. Expands $CWD, follows symlinks via realpath.
 * $NOTCWD is tracked as a flag rather than a concrete path.
 */
export function resolve_directories(dirs: string[], cwd: string): ResolvedDirs {
    const resolved: string[] = [];
    let has_notcwd = false;

    for (const dir of dirs) {
        if (dir === "$NOTCWD") {
            has_notcwd = true;
            continue;
        }

        let d = dir.replace(/\$CWD/g, cwd);

        // Skip entries with unresolved macros
        if (d.includes("$")) continue;

        try {
            resolved.push(realpathSync(d));
        } catch {
            // Directory may not exist — normalize without symlink resolution
            resolved.push(path_resolve(d));
        }
    }

    return { dirs: [...new Set(resolved)], has_notcwd };
}

/**
 * Resolve a single path captured from a $SAFE/$UNSAFE match group.
 * Handles ~, relative paths (resolved against effective_cwd), and symlinks.
 */
function resolve_match_path(captured: string, effective_cwd: string): string {
    let p = captured;

    // Strip surrounding quotes
    if (
        (p.startsWith('"') && p.endsWith('"')) ||
        (p.startsWith("'") && p.endsWith("'"))
    ) {
        p = p.slice(1, -1);
    }

    // Strip backslash escapes (e.g. my\ file.txt → my file.txt)
    p = p.replace(/\\(.)/g, "$1");

    // Expand ~
    if (p === "~") return homedir();
    if (p.startsWith("~/")) {
        p = join(homedir(), p.slice(2));
    }

    // Make absolute (also normalizes ..)
    const abs = path_resolve(effective_cwd, p);

    // Try realpath to follow symlinks
    try {
        return realpathSync(abs);
    } catch {
        return abs;
    }
}

/**
 * After a regex match, validate any $SAFE/$UNSAFE/$SAFE_CMD capture groups.
 * Returns true if all captured values pass their respective checks.
 * Returns true trivially when no capture groups are present.
 *
 * For $SAFE_CMD captures (__safe_cmd_N__), the captured command string is
 * recursively evaluated through evaluate_bash(). This requires the optional
 * recursive_ctx parameter — when absent, any __safe_cmd__ group causes a
 * fail-closed rejection (this is intentional for find_matching_risks, which
 * should never trigger recursive evaluation).
 */
function validate_path_captures(
    match: RegExpExecArray,
    ctx: EvalContext,
    recursive_ctx?: RecursiveEvalContext,
): boolean {
    if (!match.groups) return true;

    for (const [name, value] of Object.entries(match.groups)) {
        if (value === undefined) continue;

        if (name.startsWith("__safe_cmd_")) {
            // $SAFE_CMD: recursively evaluate the captured command fragment
            // through the full engine (splitting, deny checks, cd tracking).

            // Fail-closed when recursive context is unavailable (e.g. risk matching)
            if (!recursive_ctx) return false;

            // Depth limit prevents infinite recursion when SAFE_CMD rules
            // match commands that themselves contain SAFE_CMD-eligible patterns
            if (recursive_ctx.depth >= recursive_ctx.max_depth) return false;

            const inner_result = evaluate_bash(
                recursive_ctx.all_rules,
                recursive_ctx.known_risks,
                "Bash",
                { command: value },
                ctx,
                {
                    ...recursive_ctx,
                    depth: recursive_ctx.depth + 1,
                },
            );
            if (inner_result.decision === "deny") return false;
            continue;
        }

        const resolved = resolve_match_path(value, ctx.effective_cwd);

        if (name.startsWith("__safe_")) {
            // Path must be under a safe directory
            const under_safe = ctx.safe.dirs.some(
                (d) => resolved === d || resolved.startsWith(d + "/"),
            );
            if (!under_safe) return false;
        }

        if (name.startsWith("__unsafe_")) {
            // Path must be under an unsafe directory (or outside CWD if has_notcwd)
            let is_unsafe = ctx.unsafe.dirs.some(
                (d) => resolved === d || resolved.startsWith(d + "/"),
            );
            if (!is_unsafe && ctx.unsafe.has_notcwd) {
                is_unsafe =
                    resolved !== ctx.resolved_cwd &&
                    !resolved.startsWith(ctx.resolved_cwd + "/");
            }
            if (!is_unsafe) return false;
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// Pattern substitution
// ---------------------------------------------------------------------------

/**
 * Substitute policy macros in a regex pattern:
 * - $CWD → escaped literal cwd (regex macro, never changes with cd)
 * - $NOTCWD → negative lookahead for cwd (regex macro, never changes with cd)
 * - $SAFE/ → named capture group, trailing / consumed
 * - $UNSAFE/ → named capture group, trailing / consumed
 *
 * The capture group matches non-whitespace characters plus backslash-escaped
 * characters (e.g. my\ file.txt), so paths with escaped spaces are captured whole.
 *
 * When $SAFE or $UNSAFE is preceded by a literal space in the pattern
 * (the common case: "^cmd\b.* $SAFE/"), that space is replaced with a
 * negative lookbehind (?<!\\) so that the regex engine skips over
 * backslash-escaped spaces when searching for the argument boundary.
 * Without this, `.*` greedily consumes the backslash and the regex treats
 * the escaped space as a regular argument separator.
 *
 * Example: rule "^cp\b.* $SAFE/" against "cp foo /tmp/my\ file.txt"
 *   - .* backtracks, tries space after "\" → lookbehind sees \, rejects
 *   - tries space after "foo" → lookbehind sees "o", accepts
 *   - capture group gets "/tmp/my\ file.txt" (the full escaped path)
 *
 * $SAFE and $UNSAFE captures are validated post-match via validate_path_captures.
 */
/**
 * @param skip_safe_cmd - When true, $SAFE_CMD is not replaced. Used when
 *   substituting tool name patterns (where SAFE_CMD makes no sense).
 */
export function substitute_variables(
    pattern: string,
    cwd: string,
    skip_safe_cmd?: boolean,
): string {
    const escaped_cwd = cwd.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

    let result = pattern.replace(/\$NOTCWD/g, `(?!${escaped_cwd}/)`);
    result = result.replace(/\$CWD/g, escaped_cwd);

    // $SAFE_CMD: captures a command fragment for recursive evaluation.
    // Uses lazy .+? so that when multiple $SAFE_CMD appear in one pattern
    // (e.g. "^$SAFE_CMD \$\($SAFE_CMD\)"), the first capture takes as
    // little as possible, letting literal anchors like "$(" match.
    //
    // Processed BEFORE $SAFE/$UNSAFE to avoid partial matching — though
    // $SAFE\b already won't match $SAFE_CMD (since _ is a word character),
    // explicit ordering makes the intent clear.
    if (!skip_safe_cmd) {
        let safe_cmd_idx = 0;
        result = result.replace(
            /\$SAFE_CMD\b/g,
            () => `(?<__safe_cmd_${safe_cmd_idx++}__>.+?)`,
        );
    }

    // The capture group for $SAFE/$UNSAFE: matches non-whitespace characters
    // OR a backslash followed by any character (handling escaped spaces, etc).
    // This means "my\ file.txt" is captured as a single token.
    const path_capture = "(?:[^\\s]|\\\\.)+";

    // When $SAFE/$UNSAFE appears after a space in the pattern (e.g. ".* $SAFE/"),
    // we replace that space with a negative lookbehind: (?<!\\) ensures the
    // regex only matches spaces NOT preceded by a backslash. This prevents
    // the greedy .* from splitting on escaped spaces inside a path.
    //
    // \b prevents matching inside other macro names (e.g. $SAFETY).
    // \/? consumes an optional trailing / (the directory separator in patterns).
    let safe_idx = 0;
    let unsafe_idx = 0;

    // First pass: " $SAFE/" or " $SAFE" (space-prefixed) → lookbehind + capture
    result = result.replace(
        / \$SAFE\b\/?/g,
        () => `(?<!\\\\) (?<__safe_${safe_idx++}__>${path_capture})`,
    );
    // Second pass: remaining $SAFE (not space-prefixed, e.g. "^$SAFE/") → just capture
    result = result.replace(
        /\$SAFE\b\/?/g,
        () => `(?<__safe_${safe_idx++}__>${path_capture})`,
    );

    // Same two-pass approach for $UNSAFE
    result = result.replace(
        / \$UNSAFE\b\/?/g,
        () => `(?<!\\\\) (?<__unsafe_${unsafe_idx++}__>${path_capture})`,
    );
    result = result.replace(
        /\$UNSAFE\b\/?/g,
        () => `(?<__unsafe_${unsafe_idx++}__>${path_capture})`,
    );

    return result;
}

// ---------------------------------------------------------------------------
// Rule and risk matching
// ---------------------------------------------------------------------------

/**
 * Test whether a tool name + input matches a tool pattern + match conditions.
 * Used by both matches_rule and find_matching_risks.
 *
 * @param recursive_ctx - When present, enables $SAFE_CMD recursive evaluation.
 *   Omitted by find_matching_risks so that risks never trigger recursion.
 */
function matches_tool_and_input(
    tool_pattern: string,
    match_patterns: Record<string, string> | undefined,
    tool_name: string,
    tool_input: Record<string, unknown>,
    ctx: EvalContext,
    recursive_ctx?: RecursiveEvalContext,
): boolean {
    // Tool name matching — skip $SAFE_CMD replacement (tool names aren't commands)
    const tool_substituted = substitute_variables(tool_pattern, ctx.cwd, /* skip_safe_cmd */ true);
    try {
        if (!new RegExp(`^(?:${tool_substituted})$`).test(tool_name)) {
            return false;
        }
    } catch {
        return false;
    }

    // Match pattern matching — uses exec() so we get capture groups for
    // $SAFE/$UNSAFE path validation and $SAFE_CMD recursive evaluation
    if (match_patterns) {
        for (const [param, pattern] of Object.entries(match_patterns)) {
            const value = tool_input[param];
            if (value === undefined || value === null) {
                return false;
            }
            const substituted = substitute_variables(pattern, ctx.cwd);
            try {
                const match = new RegExp(substituted).exec(String(value));
                if (!match) return false;
                if (!validate_path_captures(match, ctx, recursive_ctx)) return false;
            } catch {
                return false;
            }
        }
    }

    return true;
}

export function matches_rule(
    rule: TrustRule,
    tool_name: string,
    tool_input: Record<string, unknown>,
    ctx: EvalContext,
    recursive_ctx?: RecursiveEvalContext,
): boolean {
    return matches_tool_and_input(
        rule.tool,
        rule.match,
        tool_name,
        tool_input,
        ctx,
        recursive_ctx,
    );
}

export function find_matching_risks(
    risks: KnownRisk[],
    tool_name: string,
    tool_input: Record<string, unknown>,
    ctx: EvalContext,
): KnownRisk[] {
    // No recursive_ctx — risks with $SAFE_CMD captures will fail-closed
    const matched: KnownRisk[] = [];
    for (const risk of risks) {
        if (matches_tool_and_input(risk.tool, risk.match, tool_name, tool_input, ctx)) {
            matched.push(risk);
        }
    }
    return matched;
}

// ---------------------------------------------------------------------------
// Bash command splitting (unchanged)
// ---------------------------------------------------------------------------

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

        // Single & (background operator) — treat as command separator
        if (ch === "&") {
            const trimmed = current.trim();
            if (trimmed) commands.push(trimmed);
            current = "";
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

    // Extract commands from <() and >() process substitutions
    const procsub_cmds = extract_process_substitution_commands(command);
    commands.push(...procsub_cmds);

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

function extract_process_substitution_commands(command: string): string[] {
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

        // Only extract <() and >() outside of single quotes
        if (
            !in_single_quote &&
            (ch === "<" || ch === ">") &&
            i + 1 < command.length &&
            command[i + 1] === "("
        ) {
            // For <(, make sure the previous char is not < (avoid <<( )
            if (ch === "<" && i > 0 && command[i - 1] === "<") {
                i++;
                continue;
            }
            // For >(, make sure the previous char is not > (avoid >>( )
            if (ch === ">" && i > 0 && command[i - 1] === ">") {
                i++;
                continue;
            }

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

// ---------------------------------------------------------------------------
// Core evaluation
// ---------------------------------------------------------------------------

function evaluate_single(
    all_rules: TrustRule[],
    known_risks: KnownRisk[],
    tool_name: string,
    tool_input: Record<string, unknown>,
    ctx: EvalContext,
    recursive_ctx?: RecursiveEvalContext,
): EvaluationResult {
    // Sort: highest priority first, deny before allow at same priority,
    // later rules (higher index) before earlier rules at same priority+action.
    // The last tiebreaker ensures newer session grants override older ones
    // when both match at the same priority — e.g., a grant_permission that
    // acknowledges more risks should win over an earlier acknowledge_risk.
    const indexed = all_rules.map((rule, idx) => ({ rule, idx }));
    indexed.sort((a, b) => {
        if (b.rule.priority !== a.rule.priority) return b.rule.priority - a.rule.priority;
        if (a.rule.action === "deny" && b.rule.action === "allow") return -1;
        if (a.rule.action === "allow" && b.rule.action === "deny") return 1;
        return b.idx - a.idx; // newer (higher index) wins
    });
    const sorted = indexed.map((x) => x.rule);

    // Build recursive context for $SAFE_CMD if not already provided.
    // This is constructed at the evaluate_single level (not evaluate_bash)
    // so that each rule match has access to the full rule set and risks.
    const rec_ctx: RecursiveEvalContext = recursive_ctx ?? {
        all_rules,
        known_risks,
        depth: 0,
        max_depth: MAX_SAFE_CMD_DEPTH,
    };

    // Find first matching rule
    for (const rule of sorted) {
        if (matches_rule(rule, tool_name, tool_input, ctx, rec_ctx)) {
            const risk_warnings = find_matching_risks(
                known_risks,
                tool_name,
                tool_input,
                ctx,
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
        ctx,
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

/**
 * Parse a cd sub-command and return the target directory, or null if
 * the target cannot be determined (e.g. `cd -`).
 */
function extract_cd_target(sub_cmd: string): string | null {
    if (sub_cmd === "cd") return homedir();

    const m = sub_cmd.match(/^cd\s+(.+)/);
    if (!m) return null;

    let target = m[1].trim();

    // Strip surrounding quotes
    if (
        (target.startsWith('"') && target.endsWith('"')) ||
        (target.startsWith("'") && target.endsWith("'"))
    ) {
        target = target.slice(1, -1);
    }

    // cd - goes to previous directory — can't track
    if (target === "-") return null;

    // Expand ~
    if (target === "~") return homedir();
    if (target.startsWith("~/")) {
        return join(homedir(), target.slice(2));
    }

    return target;
}

/**
 * Internal bash evaluation with full splitting, deny-check, and cd tracking.
 * Extracted from evaluate() so that $SAFE_CMD recursive evaluation can reuse
 * the same logic with pre-merged rules and an incremented depth counter.
 *
 * For non-Bash tools, delegates directly to evaluate_single.
 */
function evaluate_bash(
    all_rules: TrustRule[],
    known_risks: KnownRisk[],
    tool_name: string,
    tool_input: Record<string, unknown>,
    ctx: EvalContext,
    recursive_ctx?: RecursiveEvalContext,
): EvaluationResult {
    // Non-Bash tools go straight to evaluate_single
    if (tool_name !== "Bash" || typeof tool_input.command !== "string") {
        return evaluate_single(all_rules, known_risks, tool_name, tool_input, ctx, recursive_ctx);
    }

    // First: check the FULL unsplit command against ALL rules (with proper
    // priority ordering). This catches cross-pipe patterns like "curl ... | bash"
    // that disappear after splitting on pipe. Using all rules (not just deny)
    // ensures that a higher-priority allow isn't overridden by a lower-priority deny.
    // If this returns allow, we still proceed to split evaluation — individual
    // sub-commands may fail even if the full command matches an allow rule.
    const full_check = evaluate_single(
        all_rules,
        known_risks,
        tool_name,
        tool_input,
        ctx,
        recursive_ctx,
    );
    if (full_check.decision === "deny" && full_check.matched_rule) {
        return full_check;
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

    // Track effective CWD through cd commands within this bash invocation.
    // $CWD/$NOTCWD stay bound to the original cwd — only $SAFE/$UNSAFE
    // path resolution uses the effective_cwd.
    let effective_cwd = ctx.effective_cwd;

    for (const sub_cmd of sub_commands) {
        const sub_ctx: EvalContext = {
            ...ctx,
            effective_cwd,
        };
        const sub_input = { ...tool_input, command: sub_cmd };
        const result = evaluate_single(
            all_rules,
            known_risks,
            tool_name,
            sub_input,
            sub_ctx,
            recursive_ctx,
        );

        if (result.decision === "deny") {
            failures.push({ sub_cmd, result });
            all_risks.push(...result.risk_warnings);
        } else {
            // Only update effective_cwd after a successful cd evaluation —
            // denied cd commands should not affect subsequent path resolution
            const cd_target = extract_cd_target(sub_cmd);
            if (cd_target !== null) {
                effective_cwd = path_resolve(effective_cwd, cd_target);
            }
            if (
                result.matched_rule?.scope === "once" &&
                result.matched_rule.id
            ) {
                once_grants.push(result.matched_rule.id);
            }
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

export function evaluate(
    policies: PoliciesFile,
    session_grants: TrustRule[],
    tool_name: string,
    tool_input: Record<string, unknown>,
    cwd: string,
): EvaluationResult {
    const all_rules = [...policies.rules, ...session_grants];

    // Resolve directories once for the entire evaluation
    const safe = resolve_directories(policies.safe_directories ?? [], cwd);
    const unsafe = resolve_directories(policies.unsafe_directories ?? [], cwd);

    let resolved_cwd: string;
    try {
        resolved_cwd = realpathSync(cwd);
    } catch {
        resolved_cwd = path_resolve(cwd);
    }

    const base_ctx: EvalContext = {
        cwd,
        effective_cwd: resolved_cwd,
        resolved_cwd,
        safe,
        unsafe,
    };

    return evaluate_bash(all_rules, policies.known_risks, tool_name, tool_input, base_ctx);
}
