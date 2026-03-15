#!/usr/bin/env node

import { homedir } from "node:os";
import { join } from "node:path";
import { readFile, readdir, writeFile } from "node:fs/promises";
import { load_policies, load_overlays, merge_policies_with_overlays, evaluate } from "./engine.js";
import type { HookInput } from "./types.js";

const CONFIG_DIR = join(homedir(), ".config", "trustengine");
const POLICIES_PATH = join(CONFIG_DIR, "policies.json");
const OVERLAYS_DIR = join(CONFIG_DIR, "overlays");

async function cmd_list(): Promise<void> {
    const base = await load_policies(POLICIES_PATH);
    const overlays = await load_overlays(OVERLAYS_DIR);
    const policies = merge_policies_with_overlays(base, overlays);

    console.log("=== Permanent Rules ===\n");
    if (policies.rules.length === 0) {
        console.log("  (none)\n");
    } else {
        for (const rule of policies.rules) {
            console.log(`  [${rule.id}] ${rule.action.toUpperCase()} (priority: ${rule.priority})`);
            console.log(`    Tool: ${rule.tool}`);
            if (rule.match) {
                console.log(`    Match: ${JSON.stringify(rule.match)}`);
            }
            console.log(`    Description: ${rule.description}`);
            console.log();
        }
    }

    console.log("=== Known Risks ===\n");
    if (policies.known_risks.length === 0) {
        console.log("  (none)\n");
    } else {
        for (const risk of policies.known_risks) {
            console.log(`  [${risk.severity.toUpperCase()}] ${risk.id} — ${risk.tool}`);
            if (risk.match) {
                console.log(`    Match: ${JSON.stringify(risk.match)}`);
            }
            console.log(`    Risk: ${risk.risk}`);
            console.log();
        }
    }

    if (overlays.length > 0) {
        console.log("=== Loaded Overlays ===\n");
        for (const overlay of overlays) {
            const rule_count = overlay.rules?.length ?? 0;
            const risk_count = overlay.known_risks?.length ?? 0;
            console.log(`  ${overlay.name}: ${rule_count} rules, ${risk_count} risks`);
            if (overlay.description) {
                console.log(`    ${overlay.description}`);
            }
            console.log();
        }
    }
}

async function cmd_evaluate(json_str: string): Promise<void> {
    const input = JSON.parse(json_str) as HookInput;
    const base = await load_policies(POLICIES_PATH);
    const overlays = await load_overlays(OVERLAYS_DIR);
    const policies = merge_policies_with_overlays(base, overlays);

    const result = evaluate(
        policies,
        [],
        input.tool_name,
        input.tool_input,
        input.cwd,
    );

    console.log(JSON.stringify(result, null, 4));
}

async function cmd_remove(rule_id: string): Promise<void> {
    // Check base policies first
    const policies = await load_policies(POLICIES_PATH);
    const base_count = policies.rules.length;
    policies.rules = policies.rules.filter((r) => r.id !== rule_id);

    if (policies.rules.length < base_count) {
        await writeFile(POLICIES_PATH, JSON.stringify(policies, null, 4), "utf-8");
        console.log(`Removed rule from base policies: ${rule_id}`);
        return;
    }

    // Check overlays (user-grants overlay is the primary target)
    let entries: string[];
    try {
        entries = await readdir(OVERLAYS_DIR);
    } catch {
        console.error(`Rule "${rule_id}" not found in base policies or overlays`);
        process.exit(1);
        return;
    }

    for (const file of entries.filter((f) => f.endsWith(".json")).sort()) {
        const file_path = join(OVERLAYS_DIR, file);
        try {
            const raw = await readFile(file_path, "utf-8");
            const overlay = JSON.parse(raw);
            if (!overlay.rules || !Array.isArray(overlay.rules)) continue;

            const orig_len = overlay.rules.length;
            overlay.rules = overlay.rules.filter((r: { id: string }) => r.id !== rule_id);

            if (overlay.rules.length < orig_len) {
                await writeFile(file_path, JSON.stringify(overlay, null, 4), "utf-8");
                console.log(`Removed rule from overlay "${file}": ${rule_id}`);
                return;
            }
        } catch {
            continue;
        }
    }

    console.error(`Rule "${rule_id}" not found in base policies or overlays`);
    process.exit(1);
}

function print_usage(): void {
    console.log(`Usage:
  trustengine list                  Show permanent rules and known risks
  trustengine evaluate '<json>'     Test a tool call against policies
  trustengine remove <rule-id>      Remove a rule by ID
`);
}

async function main(): Promise<void> {
    const args = process.argv.slice(2);
    const command = args[0];

    switch (command) {
        case "list":
            await cmd_list();
            break;
        case "evaluate":
            if (!args[1]) {
                console.error("Usage: trustengine evaluate '<json>'");
                process.exit(1);
            }
            await cmd_evaluate(args[1]);
            break;
        case "remove":
            if (!args[1]) {
                console.error("Usage: trustengine remove <rule-id>");
                process.exit(1);
            }
            await cmd_remove(args[1]);
            break;
        default:
            print_usage();
            break;
    }
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
