#!/usr/bin/env node

import { homedir } from "node:os";
import { join } from "node:path";
import { writeFile } from "node:fs/promises";
import { load_policies, evaluate } from "./engine.js";
import type { HookInput } from "./types.js";

const POLICIES_PATH = join(homedir(), ".config", "trustengine", "policies.json");

async function cmd_list(): Promise<void> {
    const policies = await load_policies(POLICIES_PATH);

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
            console.log(`  [${risk.severity.toUpperCase()}] ${risk.tool}`);
            if (risk.match) {
                console.log(`    Match: ${JSON.stringify(risk.match)}`);
            }
            console.log(`    Risk: ${risk.risk}`);
            console.log();
        }
    }
}

async function cmd_evaluate(json_str: string): Promise<void> {
    const input = JSON.parse(json_str) as HookInput;
    const policies = await load_policies(POLICIES_PATH);

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
    const policies = await load_policies(POLICIES_PATH);

    const original_count = policies.rules.length;
    policies.rules = policies.rules.filter((r) => r.id !== rule_id);

    if (policies.rules.length === original_count) {
        console.error(`Rule "${rule_id}" not found`);
        process.exit(1);
    }

    await writeFile(POLICIES_PATH, JSON.stringify(policies, null, 4), "utf-8");
    console.log(`Removed rule: ${rule_id}`);
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
