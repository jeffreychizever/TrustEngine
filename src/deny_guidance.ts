import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import ejs from "ejs";

const __dirname = dirname(fileURLToPath(import.meta.url));

// User override: ~/.config/trustengine/deny_guidance.ejs
// Fallback: bundled template in src/templates/
const USER_TEMPLATE = join(homedir(), ".config", "trustengine", "deny_guidance.ejs");
const BUNDLED_TEMPLATE = join(__dirname, "..", "src", "templates", "deny_guidance.ejs");

let cached_template: string | null = null;

function load_template(): string {
    if (!cached_template) {
        try {
            cached_template = readFileSync(USER_TEMPLATE, "utf-8");
        } catch {
            cached_template = readFileSync(BUNDLED_TEMPLATE, "utf-8");
        }
    }
    return cached_template;
}

function extract_common_path(sub_commands: string[]): string | null {
    const paths: string[] = [];
    for (const cmd of sub_commands) {
        const match = cmd.match(/\s+(\/\S+)/);
        if (match) paths.push(match[1]);
    }
    if (paths.length === 0) return null;

    const dirs = paths.map((p) => p.substring(0, p.lastIndexOf("/") + 1));
    let common = dirs[0];
    for (const dir of dirs.slice(1)) {
        while (common && !dir.startsWith(common)) {
            common = common.substring(0, common.lastIndexOf("/", common.length - 2) + 1);
        }
    }
    return common || null;
}

interface RiskInfo {
    id: string;
    severity: string;
}

export function build_deny_guidance(
    tool_name: string,
    tool_input: Record<string, unknown>,
    denied_commands: string[] | undefined,
    denied_sub_commands: string[] | undefined,
    session_id: string,
    risks?: RiskInfo[],
): string {
    let mode: "bash" | "write_edit" | "generic";
    let cmd_names_json = "";
    let path_prefix: string | null = null;
    let escaped_dir = "";

    if (tool_name === "Bash" && denied_commands && denied_commands.length > 0) {
        mode = "bash";
        const unique_cmds = [...new Set(denied_commands)];
        cmd_names_json = JSON.stringify(unique_cmds);
        path_prefix = denied_sub_commands
            ? extract_common_path(denied_sub_commands)
            : null;
    } else if (
        (tool_name === "Write" || tool_name === "Edit") &&
        typeof tool_input.file_path === "string"
    ) {
        mode = "write_edit";
        const fp = tool_input.file_path as string;
        const dir = fp.substring(0, fp.lastIndexOf("/") + 1);
        escaped_dir = dir.replace(/[.*+?^${}()|[\]\\]/g, "\\\\$&");
    } else {
        mode = "generic";
    }

    const all_risks = risks ?? [];
    const block_risks = all_risks.filter((r) => r.severity === "block");
    const escalate_risks = all_risks.filter((r) => r.severity === "escalate");
    const ack_risks = all_risks.filter((r) => r.severity === "acknowledge");

    const template = load_template();
    return ejs.render(template, {
        tool_name,
        session_id,
        mode,
        cmd_names_json,
        path_prefix,
        escaped_dir,
        block_risks,
        escalate_risks,
        ack_risks,
    }).trim();
}
