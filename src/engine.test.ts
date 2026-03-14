import { describe, it, expect } from "vitest";
import {
    merge_policies_with_overlays,
    evaluate,
    split_bash_command,
} from "./engine.js";
import type { PoliciesFile, OverlayFile } from "./types.js";

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
