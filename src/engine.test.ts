import { describe, it, expect } from "vitest";
import {
    merge_policies_with_overlays,
    evaluate,
    split_bash_command,
    substitute_variables,
    matches_rule,
    find_matching_risks,
    resolve_directories,
} from "./engine.js";
import type { EvalContext, ResolvedDirs } from "./engine.js";
import type { PoliciesFile, OverlayFile, TrustRule, KnownRisk } from "./types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function make_base(): PoliciesFile {
    return {
        version: 2,
        rules: [
            {
                id: "allow-ls",
                tool: "Bash",
                match: { command: "^ls\\b" },
                action: "allow",
                priority: 60,
                description: "Allow ls",
            },
            {
                id: "deny-rm",
                tool: "Bash",
                match: { command: "^rm\\b" },
                action: "deny",
                priority: 90,
                description: "Deny rm",
            },
        ],
        known_risks: [
            {
                id: "risk-network",
                tool: "Bash",
                match: { command: "(^|[;&|] *)curl\\b" },
                risk: "Network request",
                severity: "escalate",
            },
        ],
        safe_directories: ["/home/user/project"],
        unsafe_directories: ["/etc"],
    };
}

function make_overlay(partial: Partial<OverlayFile> & { name: string; version: number }): OverlayFile {
    return {
        version: partial.version,
        name: partial.name,
        description: partial.description,
        rules: partial.rules,
        known_risks: partial.known_risks,
        remove_rules: partial.remove_rules,
        remove_risks: partial.remove_risks,
        safe_directories: partial.safe_directories,
        unsafe_directories: partial.unsafe_directories,
    };
}

// ---------------------------------------------------------------------------
// merge_policies_with_overlays
// ---------------------------------------------------------------------------

describe("merge_policies_with_overlays", () => {
    it("returns base unchanged when no overlays", () => {
        const base = make_base();
        const merged = merge_policies_with_overlays(base, []);
        expect(merged.rules).toHaveLength(base.rules.length);
        expect(merged.known_risks).toHaveLength(base.known_risks.length);
        expect(merged.safe_directories).toEqual(base.safe_directories);
    });

    it("adds overlay rules and risks", () => {
        const base = make_base();
        const overlay = make_overlay({
            version: 1,
            name: "extra",
            rules: [
                {
                    id: "allow-cat",
                    tool: "Bash",
                    match: { command: "^cat\\b" },
                    action: "allow",
                    priority: 60,
                    description: "Allow cat",
                },
            ],
            known_risks: [
                {
                    id: "risk-custom",
                    tool: "Bash",
                    match: { command: "^custom\\b" },
                    risk: "Custom risk",
                    severity: "acknowledge",
                },
            ],
        });

        const merged = merge_policies_with_overlays(base, [overlay]);
        expect(merged.rules).toHaveLength(3);
        expect(merged.rules.find((r) => r.id === "allow-cat")).toBeDefined();
        expect(merged.known_risks).toHaveLength(2);
        expect(merged.known_risks.find((r) => r.id === "risk-custom")).toBeDefined();
    });

    it("removes rules and risks by ID", () => {
        const base = make_base();
        const overlay = make_overlay({
            version: 1,
            name: "remover",
            remove_rules: ["allow-ls"],
            remove_risks: ["risk-network"],
        });

        const merged = merge_policies_with_overlays(base, [overlay]);
        expect(merged.rules.find((r) => r.id === "allow-ls")).toBeUndefined();
        expect(merged.known_risks.find((r) => r.id === "risk-network")).toBeUndefined();
        expect(merged.rules).toHaveLength(1); // only deny-rm left
        expect(merged.known_risks).toHaveLength(0);
    });

    it("remove-then-add within a single overlay replaces a rule", () => {
        const base = make_base();
        const overlay = make_overlay({
            version: 1,
            name: "replacer",
            remove_rules: ["allow-ls"],
            rules: [
                {
                    id: "allow-ls",
                    tool: "Bash",
                    match: { command: "^ls -la\\b" },
                    action: "allow",
                    priority: 65,
                    description: "Allow ls -la only",
                },
            ],
        });

        const merged = merge_policies_with_overlays(base, [overlay]);
        const ls_rule = merged.rules.find((r) => r.id === "allow-ls");
        expect(ls_rule).toBeDefined();
        expect(ls_rule!.priority).toBe(65);
        expect(ls_rule!.match!.command).toBe("^ls -la\\b");
    });

    it("later overlay can remove a rule added by earlier overlay", () => {
        const base = make_base();
        const overlay_a = make_overlay({
            version: 1,
            name: "adder",
            rules: [
                {
                    id: "allow-wget",
                    tool: "Bash",
                    match: { command: "^wget\\b" },
                    action: "allow",
                    priority: 60,
                    description: "Allow wget",
                },
            ],
        });
        const overlay_b = make_overlay({
            version: 1,
            name: "remover",
            remove_rules: ["allow-wget"],
        });

        const merged = merge_policies_with_overlays(base, [overlay_a, overlay_b]);
        expect(merged.rules.find((r) => r.id === "allow-wget")).toBeUndefined();
    });

    it("unions safe directories without duplicates", () => {
        const base = make_base();
        const overlay = make_overlay({
            version: 1,
            name: "dirs",
            safe_directories: ["/home/user/project", "/home/user/extra"],
        });

        const merged = merge_policies_with_overlays(base, [overlay]);
        expect(merged.safe_directories).toEqual([
            "/home/user/project",
            "/home/user/extra",
        ]);
    });

    it("unions unsafe directories without duplicates", () => {
        const base = make_base();
        const overlay = make_overlay({
            version: 1,
            name: "dirs",
            unsafe_directories: ["/etc", "/var/secrets"],
        });

        const merged = merge_policies_with_overlays(base, [overlay]);
        expect(merged.unsafe_directories).toEqual(["/etc", "/var/secrets"]);
    });

    it("initializes safe_directories when base has none", () => {
        const base = make_base();
        base.safe_directories = undefined;
        const overlay = make_overlay({
            version: 1,
            name: "dirs",
            safe_directories: ["/tmp/safe"],
        });

        const merged = merge_policies_with_overlays(base, [overlay]);
        expect(merged.safe_directories).toEqual(["/tmp/safe"]);
    });

    it("does not mutate the base policies object", () => {
        const base = make_base();
        const original_rule_count = base.rules.length;
        const overlay = make_overlay({
            version: 1,
            name: "extra",
            rules: [
                {
                    id: "allow-cat",
                    tool: "Bash",
                    match: { command: "^cat\\b" },
                    action: "allow",
                    priority: 60,
                    description: "Allow cat",
                },
            ],
        });

        merge_policies_with_overlays(base, [overlay]);
        expect(base.rules).toHaveLength(original_rule_count);
    });
});

// ---------------------------------------------------------------------------
// Composition-aware evaluation (deny rules in pipelines / chains)
// ---------------------------------------------------------------------------

describe("composition-aware deny rules", () => {
    // Minimal policies mirroring the default-policies.json deny rules
    function make_policies(): PoliciesFile {
        return {
            version: 2,
            rules: [
                {
                    id: "deny-pipe-to-interpreter",
                    tool: "Bash",
                    match: { command: "\\| *(bash|sh|zsh|python3?|perl|ruby|node|xargs)\\b" },
                    action: "deny",
                    priority: 100,
                    description: "Block piping to interpreters",
                },
                {
                    id: "deny-curl-mutating",
                    tool: "Bash",
                    match: { command: "^curl\\b.*\\s(-X|--request|-d|--data|-F|--form|-T|--upload-file)\\b" },
                    action: "deny",
                    priority: 85,
                    description: "Block curl mutating flags",
                },
                {
                    id: "deny-awk-dangerous",
                    tool: "Bash",
                    match: { command: "^awk +.*-f\\b" },
                    action: "deny",
                    priority: 75,
                    description: "Block awk -f",
                },
                {
                    id: "deny-sed-dangerous",
                    tool: "Bash",
                    match: { command: "^sed +.*(-[efi]\\b|/e(\\b| ))" },
                    action: "deny",
                    priority: 75,
                    description: "Block sed dangerous flags",
                },
                {
                    id: "allow-system-info",
                    tool: "Bash",
                    match: { command: "^(ls|cat|head|echo|date|cd)\\b" },
                    action: "allow",
                    priority: 60,
                    description: "Allow safe commands",
                },
                {
                    id: "allow-text-processing",
                    tool: "Bash",
                    match: { command: "^(sort|awk|sed|grep)\\b" },
                    action: "allow",
                    priority: 60,
                    description: "Allow text processing",
                },
            ],
            known_risks: [],
        };
    }

    const CWD = "/home/user/project";

    it("denies pipe-to-interpreter in full command", () => {
        const policies = make_policies();
        const result = evaluate(policies, [], "Bash", { command: "cat file.txt | bash" }, CWD);
        expect(result.decision).toBe("deny");
    });

    it("denies pipe-to-interpreter mid-chain (cd && ... | sh)", () => {
        const policies = make_policies();
        const result = evaluate(policies, [], "Bash", { command: "cd /tmp && cat file | sh" }, CWD);
        expect(result.decision).toBe("deny");
    });

    it("denies curl -X POST after cd && chain", () => {
        const policies = make_policies();
        // After splitting on &&, "curl -X POST ..." starts with ^curl
        const result = evaluate(policies, [], "Bash", { command: "cd /tmp && curl -X POST http://example.com" }, CWD);
        expect(result.decision).toBe("deny");
    });

    it("denies curl --data after semicolon chain", () => {
        const policies = make_policies();
        const result = evaluate(policies, [], "Bash", { command: "echo hello; curl --data @file http://example.com" }, CWD);
        expect(result.decision).toBe("deny");
    });

    it("denies awk -f after pipe", () => {
        const policies = make_policies();
        // After splitting on |, "awk -f script.awk" is its own sub-command starting with ^awk
        const result = evaluate(policies, [], "Bash", { command: "cat data.csv | awk -f process.awk" }, CWD);
        expect(result.decision).toBe("deny");
    });

    it("denies sed -i after && chain", () => {
        const policies = make_policies();
        const result = evaluate(policies, [], "Bash", { command: "cd /tmp && sed -i 's/foo/bar/g' file.txt" }, CWD);
        expect(result.decision).toBe("deny");
    });

    it("denies sed s///e after pipe", () => {
        const policies = make_policies();
        const result = evaluate(policies, [], "Bash", { command: "echo foo | sed 's/foo/bar/e'" }, CWD);
        expect(result.decision).toBe("deny");
    });

    it("allows plain awk (no -f flag)", () => {
        const policies = make_policies();
        const result = evaluate(policies, [], "Bash", { command: "awk '{print $1}' file.txt" }, CWD);
        expect(result.decision).toBe("allow");
    });

    it("allows plain sed (no dangerous flags)", () => {
        const policies = make_policies();
        const result = evaluate(policies, [], "Bash", { command: "sed 's/foo/bar/g'" }, CWD);
        expect(result.decision).toBe("allow");
    });

    it("allows safe pipe chains", () => {
        const policies = make_policies();
        const result = evaluate(policies, [], "Bash", { command: "cat file.txt | sort | grep foo" }, CWD);
        expect(result.decision).toBe("allow");
    });

    it("allows safe && chains", () => {
        const policies = make_policies();
        const result = evaluate(policies, [], "Bash", { command: "cd /tmp && ls -la && echo done" }, CWD);
        expect(result.decision).toBe("allow");
    });
});

// ---------------------------------------------------------------------------
// split_bash_command
// ---------------------------------------------------------------------------

describe("split_bash_command", () => {
    it("splits on semicolons", () => {
        expect(split_bash_command("ls; echo hi")).toEqual(["ls", "echo hi"]);
    });

    it("splits on &&", () => {
        expect(split_bash_command("cd /tmp && ls")).toEqual(["cd /tmp", "ls"]);
    });

    it("splits on ||", () => {
        expect(split_bash_command("test -f x || echo missing")).toEqual([
            "test -f x",
            "echo missing",
        ]);
    });

    it("splits on pipe", () => {
        expect(split_bash_command("cat file | sort | head")).toEqual([
            "cat file",
            "sort",
            "head",
        ]);
    });

    it("does not split inside single quotes", () => {
        const result = split_bash_command("echo 'foo && bar'");
        expect(result).toEqual(["echo 'foo && bar'"]);
    });

    it("does not split inside double quotes", () => {
        const result = split_bash_command('echo "foo | bar"');
        expect(result).toEqual(['echo "foo | bar"']);
    });

    it("extracts subshell commands from $()", () => {
        const result = split_bash_command("echo $(date)");
        expect(result).toContain("echo $(date)");
        expect(result).toContain("date");
    });

    it("extracts backtick commands", () => {
        const result = split_bash_command("echo `whoami`");
        expect(result).toContain("echo `whoami`");
        expect(result).toContain("whoami");
    });
});

// ---------------------------------------------------------------------------
// Helpers for directory handling tests
// ---------------------------------------------------------------------------

function make_ctx(overrides?: Partial<EvalContext>): EvalContext {
    return {
        cwd: "/home/user/project",
        effective_cwd: "/home/user/project",
        resolved_cwd: "/home/user/project",
        safe: { dirs: ["/home/user/project", "/tmp"], has_notcwd: false },
        unsafe: { dirs: [], has_notcwd: true },
        ...overrides,
    };
}

// ---------------------------------------------------------------------------
// resolve_directories
// ---------------------------------------------------------------------------

describe("resolve_directories", () => {
    it("expands $CWD to concrete path", () => {
        const result = resolve_directories(["$CWD", "/tmp"], "/home/user/project");
        expect(result.dirs).toContain("/home/user/project");
        expect(result.dirs).toContain("/tmp");
        expect(result.has_notcwd).toBe(false);
    });

    it("tracks $NOTCWD as a flag", () => {
        const result = resolve_directories(["$NOTCWD"], "/home/user/project");
        expect(result.has_notcwd).toBe(true);
        expect(result.dirs).toHaveLength(0);
    });

    it("skips entries with unresolved macros", () => {
        const result = resolve_directories(["$UNKNOWN_MACRO"], "/home/user");
        expect(result.dirs).toHaveLength(0);
    });

    it("deduplicates resolved dirs", () => {
        const result = resolve_directories(["$CWD", "/home/user/project"], "/home/user/project");
        const occurrences = result.dirs.filter((d) => d === "/home/user/project");
        expect(occurrences.length).toBe(1);
    });
});

// ---------------------------------------------------------------------------
// substitute_variables — capture groups
// ---------------------------------------------------------------------------

describe("substitute_variables capture groups", () => {
    it("replaces $CWD with escaped cwd", () => {
        const result = substitute_variables("^$CWD/", "/home/user/project");
        expect(result).toContain("/home/user/project");
        expect(result).not.toContain("$CWD");
    });

    it("replaces $NOTCWD with negative lookahead", () => {
        const result = substitute_variables("^$NOTCWD", "/home/user");
        expect(result).toMatch(/\(\?!/);
    });

    it("replaces $SAFE/ with a named capture group", () => {
        const result = substitute_variables("^$SAFE/", "/home/user");
        expect(result).toMatch(/\(\?<__safe_0__>/);
        // The trailing / should be consumed — no literal / after the group
        expect(result).not.toMatch(/\\S\+\)\//);
    });

    it("replaces $UNSAFE/ with a named capture group", () => {
        const result = substitute_variables("^$UNSAFE/", "/home/user");
        expect(result).toMatch(/\(\?<__unsafe_0__>/);
    });

    it("handles multiple $SAFE references with unique names", () => {
        const result = substitute_variables("$SAFE/ and $SAFE/", "/home/user");
        expect(result).toContain("__safe_0__");
        expect(result).toContain("__safe_1__");
    });

    it("does not match $SAFETY when replacing $SAFE", () => {
        const result = substitute_variables("$SAFETY/foo", "/home/user");
        // $SAFETY should remain untouched since \b prevents matching
        expect(result).toContain("$SAFETY");
    });
});

// ---------------------------------------------------------------------------
// matches_rule — $SAFE semantic validation
// ---------------------------------------------------------------------------

describe("matches_rule with $SAFE", () => {
    const write_safe_rule: TrustRule = {
        id: "allow-write-safe",
        tool: "Write",
        match: { file_path: "^$SAFE/" },
        action: "allow",
        priority: 70,
        description: "Allow writes in safe dirs",
    };

    it("matches file_path under a safe directory", () => {
        const ctx = make_ctx();
        const result = matches_rule(
            write_safe_rule, "Write",
            { file_path: "/home/user/project/src/foo.ts" }, ctx,
        );
        expect(result).toBe(true);
    });

    it("matches file_path under /tmp (also safe)", () => {
        const ctx = make_ctx();
        const result = matches_rule(
            write_safe_rule, "Write",
            { file_path: "/tmp/scratch.txt" }, ctx,
        );
        expect(result).toBe(true);
    });

    it("rejects file_path outside safe directories", () => {
        const ctx = make_ctx();
        const result = matches_rule(
            write_safe_rule, "Write",
            { file_path: "/etc/passwd" }, ctx,
        );
        expect(result).toBe(false);
    });

    it("rejects when no safe dirs configured", () => {
        const ctx = make_ctx({ safe: { dirs: [], has_notcwd: false } });
        const result = matches_rule(
            write_safe_rule, "Write",
            { file_path: "/tmp/foo" }, ctx,
        );
        expect(result).toBe(false);
    });
});

// ---------------------------------------------------------------------------
// matches_rule — $UNSAFE semantic validation
// ---------------------------------------------------------------------------

describe("matches_rule with $UNSAFE (has_notcwd)", () => {
    const deny_unsafe_rule: TrustRule = {
        id: "deny-write-unsafe",
        tool: "Write",
        match: { file_path: "^$UNSAFE/" },
        action: "deny",
        priority: 90,
        description: "Deny writes in unsafe dirs",
    };

    it("matches file_path outside CWD when has_notcwd", () => {
        const ctx = make_ctx();
        const result = matches_rule(
            deny_unsafe_rule, "Write",
            { file_path: "/etc/passwd" }, ctx,
        );
        expect(result).toBe(true);
    });

    it("does not match file_path inside CWD", () => {
        const ctx = make_ctx();
        const result = matches_rule(
            deny_unsafe_rule, "Write",
            { file_path: "/home/user/project/src/foo.ts" }, ctx,
        );
        expect(result).toBe(false);
    });

    it("matches when path is under an explicit unsafe dir", () => {
        const ctx = make_ctx({
            unsafe: { dirs: ["/var/secrets"], has_notcwd: false },
        });
        const result = matches_rule(
            deny_unsafe_rule, "Write",
            { file_path: "/var/secrets/key.pem" }, ctx,
        );
        expect(result).toBe(true);
    });
});

// ---------------------------------------------------------------------------
// matches_rule — bash commands with $SAFE
// ---------------------------------------------------------------------------

describe("matches_rule with bash $SAFE commands", () => {
    const cp_safe_rule: TrustRule = {
        id: "allow-cp-safe",
        tool: "Bash",
        match: { command: "^(cp|mv)\\b.* $SAFE/" },
        action: "allow",
        priority: 60,
        description: "Allow cp/mv to safe dirs",
    };

    it("allows cp to a safe directory", () => {
        const ctx = make_ctx();
        expect(matches_rule(
            cp_safe_rule, "Bash",
            { command: "cp foo.txt /tmp/bar.txt" }, ctx,
        )).toBe(true);
    });

    it("allows mv to project directory", () => {
        const ctx = make_ctx();
        expect(matches_rule(
            cp_safe_rule, "Bash",
            { command: "mv old.txt /home/user/project/new.txt" }, ctx,
        )).toBe(true);
    });

    it("rejects cp to unsafe directory", () => {
        const ctx = make_ctx();
        expect(matches_rule(
            cp_safe_rule, "Bash",
            { command: "cp foo.txt /etc/bar.txt" }, ctx,
        )).toBe(false);
    });

    it("resolves relative path against effective_cwd", () => {
        const ctx = make_ctx({ effective_cwd: "/tmp" });
        expect(matches_rule(
            cp_safe_rule, "Bash",
            { command: "cp foo.txt bar.txt" }, ctx,
        )).toBe(true);
    });

    it("resolves .. traversal paths", () => {
        const ctx = make_ctx({ effective_cwd: "/home/user/project/src" });
        expect(matches_rule(
            cp_safe_rule, "Bash",
            { command: "cp x ../foo" }, ctx,
        )).toBe(true);
    });

    it("rejects .. traversal that escapes safe dirs", () => {
        const ctx = make_ctx();
        expect(matches_rule(
            cp_safe_rule, "Bash",
            { command: "cp x ../../etc/passwd" }, ctx,
        )).toBe(false);
    });
});

// ---------------------------------------------------------------------------
// evaluate — cd tracking
// ---------------------------------------------------------------------------

describe("evaluate cd tracking", () => {
    function make_cd_policies(): PoliciesFile {
        return {
            version: 2,
            rules: [
                {
                    id: "allow-cd",
                    tool: "Bash",
                    match: { command: "^cd\\b" },
                    action: "allow",
                    priority: 60,
                    description: "Allow cd",
                },
                {
                    id: "allow-cp-safe",
                    tool: "Bash",
                    match: { command: "^(cp|mv)\\b.* $SAFE/" },
                    action: "allow",
                    priority: 60,
                    description: "Allow cp/mv to safe dirs",
                },
                {
                    id: "allow-ls",
                    tool: "Bash",
                    match: { command: "^ls\\b" },
                    action: "allow",
                    priority: 60,
                    description: "Allow ls",
                },
            ],
            known_risks: [],
            safe_directories: ["$CWD", "/tmp"],
            unsafe_directories: ["$NOTCWD"],
        };
    }

    it("allows cp with relative path after cd to safe dir", () => {
        const result = evaluate(
            make_cd_policies(), [], "Bash",
            { command: "cd /tmp && cp foo.txt bar.txt" },
            "/home/user/project",
        );
        expect(result.decision).toBe("allow");
    });

    it("denies cp with relative path after cd to unsafe dir", () => {
        const result = evaluate(
            make_cd_policies(), [], "Bash",
            { command: "cd /etc && cp foo.txt bar.txt" },
            "/home/user/project",
        );
        expect(result.decision).toBe("deny");
    });

    it("$CWD does not change with cd (stays bound to original)", () => {
        const result = evaluate(
            make_cd_policies(), [], "Bash",
            { command: "cd / && cp foo.txt /etc/passwd" },
            "/home/user/project",
        );
        expect(result.decision).toBe("deny");
    });
});

// ---------------------------------------------------------------------------
// Rules without $SAFE/$UNSAFE (regression)
// ---------------------------------------------------------------------------

describe("rules without $SAFE/$UNSAFE (regression)", () => {
    it("plain regex rules match normally", () => {
        const rule: TrustRule = {
            id: "allow-ls",
            tool: "Bash",
            match: { command: "^ls\\b" },
            action: "allow",
            priority: 60,
            description: "Allow ls",
        };
        const ctx = make_ctx();
        expect(matches_rule(rule, "Bash", { command: "ls -la" }, ctx)).toBe(true);
        expect(matches_rule(rule, "Bash", { command: "rm foo" }, ctx)).toBe(false);
    });

    it("tool-only rules (no match) still work", () => {
        const rule: TrustRule = {
            id: "allow-read",
            tool: "Read|Glob|Grep",
            action: "allow",
            priority: 80,
            description: "Allow read tools",
        };
        const ctx = make_ctx();
        expect(matches_rule(rule, "Read", {}, ctx)).toBe(true);
        expect(matches_rule(rule, "Write", {}, ctx)).toBe(false);
    });
});
