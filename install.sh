#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$HOME/.config/trustengine"
SESSIONS_DIR="$HOME/.config/trustengine/sessions"
CLAUDE_SETTINGS="$HOME/.claude/settings.json"
CLAUDE_GLOBAL="$HOME/.claude.json"
HOOK_COMMAND="node $SCRIPT_DIR/dist/hook.js"
MCP_COMMAND="node"
MCP_ARG="$SCRIPT_DIR/dist/mcp_server.js"

echo "=== TrustEngine Installer ==="
echo
echo "Choose installation mode:"
echo
echo "  1) Full mode (recommended after validation)"
echo "     TrustEngine replaces Claude's built-in permission system."
echo "     Claude's prompts are bypassed for standard tools; TrustEngine's"
echo "     hook gates everything. You only see Claude prompts for"
echo "     grant_permission calls."
echo
echo "  2) Belt-and-suspenders mode (recommended for first install)"
echo "     TrustEngine runs alongside Claude's built-in permissions."
echo "     Both systems gate tool calls, so you'll see double prompts."
echo "     Use this to validate TrustEngine's decisions match your"
echo "     expectations before fully committing."
echo

read -rp "Select mode [1/2]: " MODE
case "$MODE" in
    1) echo "  Selected: Full mode" ;;
    2) echo "  Selected: Belt-and-suspenders mode" ;;
    *)
        echo "Invalid selection. Exiting."
        exit 1
        ;;
esac
echo

# 1. Install dependencies and build
echo "[1/5] Installing dependencies and building..."
cd "$SCRIPT_DIR"
npm install
npm run build
echo "  Done."
echo

# 2. Create directories
echo "[2/5] Creating directories..."
mkdir -p "$CONFIG_DIR"
mkdir -p "$SESSIONS_DIR"
echo "  Created: $CONFIG_DIR"
echo "  Created: $SESSIONS_DIR"
echo

# 3. Copy default policies (skip if exists, unless --force)
echo "[3/5] Setting up default policies..."
FORCE=0
for arg in "$@"; do
    if [ "$arg" = "--force" ]; then
        FORCE=1
    fi
done

if [ "$FORCE" -eq 1 ] && [ -f "$CONFIG_DIR/policies.json" ]; then
    rm "$CONFIG_DIR/policies.json"
    echo "  Removed existing policies.json (--force)"
fi

if [ -f "$CONFIG_DIR/policies.json" ]; then
    echo "  Skipped: $CONFIG_DIR/policies.json already exists (use --force to overwrite)"
else
    cp "$SCRIPT_DIR/default-policies.json" "$CONFIG_DIR/policies.json"
    echo "  Copied default policies to $CONFIG_DIR/policies.json"
fi
echo

# 4. Add PreToolUse hook + permissions to ~/.claude/settings.json
echo "[4/5] Configuring Claude Code hook..."
mkdir -p "$HOME/.claude"

CLAUDE_SETTINGS="$CLAUDE_SETTINGS" INSTALL_MODE="$MODE" HOOK_COMMAND="$HOOK_COMMAND" node -e "
const fs = require('fs');
const path = process.env.CLAUDE_SETTINGS;
const mode = process.env.INSTALL_MODE;
let settings = {};
try { settings = JSON.parse(fs.readFileSync(path, 'utf-8')); } catch {}

// Ensure hooks.PreToolUse array exists
if (!settings.hooks) settings.hooks = {};
if (!Array.isArray(settings.hooks.PreToolUse)) settings.hooks.PreToolUse = [];

// Check if hook already configured
const hookCmd = process.env.HOOK_COMMAND;
const exists = settings.hooks.PreToolUse.some(
    h => Array.isArray(h.hooks) && h.hooks.some(hh => hh.command === hookCmd)
);
if (!exists) {
    settings.hooks.PreToolUse.push({
        matcher: '.*',
        hooks: [
            {
                type: 'command',
                command: hookCmd,
                timeout: 10
            }
        ]
    });
    console.log('  Added PreToolUse hook');
} else {
    console.log('  Hook already configured');
}

// Full mode: auto-allow standard tools so TrustEngine is the sole gate
if (mode === '1') {
    if (!settings.permissions) settings.permissions = {};
    if (!Array.isArray(settings.permissions.allow)) settings.permissions.allow = [];

    const tools_to_allow = [
        'Bash', 'Read', 'Write', 'Edit', 'Glob', 'Grep',
        'WebFetch', 'WebSearch', 'NotebookEdit'
    ];

    for (const tool of tools_to_allow) {
        if (!settings.permissions.allow.includes(tool)) {
            settings.permissions.allow.push(tool);
        }
    }
    console.log('  Auto-allowed standard tools (Full mode)');
    console.log('  Claude will only prompt for grant_permission calls');
} else {
    console.log('  Keeping Claude built-in permissions active (Belt-and-suspenders mode)');
    console.log('  You will see both Claude prompts and TrustEngine decisions');
}

fs.writeFileSync(path, JSON.stringify(settings, null, 4));
console.log('  Wrote ' + path);
"
echo

# 5. Add MCP server to ~/.claude.json
echo "[5/5] Configuring MCP server..."

CLAUDE_GLOBAL="$CLAUDE_GLOBAL" MCP_COMMAND="$MCP_COMMAND" MCP_ARG="$MCP_ARG" node -e "
const fs = require('fs');
const path = process.env.CLAUDE_GLOBAL;
let config = {};
try { config = JSON.parse(fs.readFileSync(path, 'utf-8')); } catch {}

// Add MCP server
if (!config.mcpServers) config.mcpServers = {};
config.mcpServers.trustengine = {
    command: process.env.MCP_COMMAND,
    args: [process.env.MCP_ARG],
    env: {}
};

fs.writeFileSync(path, JSON.stringify(config, null, 4));
console.log('  Added MCP server to ' + path);
"
echo

echo "=== Installation Complete ==="
echo
if [ "$MODE" = "1" ]; then
    echo "Full mode active. TrustEngine is now the sole permission gate."
    echo "Claude will only prompt you when the agent calls grant_permission."
else
    echo "Belt-and-suspenders mode active. Both systems are running."
    echo "Claude's built-in prompts + TrustEngine's hook will both gate tool calls."
    echo "Once you're confident TrustEngine works as expected, re-run with mode 1."
fi
echo
echo "Restart Claude Code to apply changes."
echo
echo "Quick test:"
echo "  echo '{\"session_id\":\"test\",\"cwd\":\"/tmp\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"ls\"}}' | node $SCRIPT_DIR/dist/hook.js"
echo
