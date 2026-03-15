#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$HOME/.config/trustengine"
SESSIONS_DIR="$HOME/.config/trustengine/sessions"
OVERLAYS_DIR="$HOME/.config/trustengine/overlays"
CLAUDE_SETTINGS="$HOME/.claude/settings.json"
CLAUDE_GLOBAL="$HOME/.claude.json"
# Resolve the globally-installed bin commands.
# If installed via npm install -g, these will be on PATH.
# Fall back to $SCRIPT_DIR/dist/ for legacy installs.
if command -v trustengine-hook &>/dev/null; then
    HOOK_COMMAND="trustengine-hook"
    MCP_COMMAND="trustengine-mcp"
    MCP_ARG=""
else
    HOOK_COMMAND="node $SCRIPT_DIR/dist/hook.js"
    MCP_COMMAND="node"
    MCP_ARG="$SCRIPT_DIR/dist/mcp_server.js"
fi

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

echo "Directory trust settings for Write/Edit operations:"
echo "  Policies include 'allow-write-in-safe' and 'deny-write-in-unsafe' rules."
echo "  Safe directories are explicitly allowed; unsafe directories are denied."
echo "  Directories not in either list are normal (governed by other rules)."
echo

read -rp "Treat /tmp as a safe directory? [Y/n]: " TMP_SAFE
case "$TMP_SAFE" in
    [Nn]) TMP_SAFE="n"; echo "  /tmp: normal" ;;
    *)    TMP_SAFE="y"; echo "  /tmp: safe" ;;
esac

read -rp "Treat CWD as a safe directory? [Y/n]: " CWD_SAFE
case "$CWD_SAFE" in
    [Nn]) CWD_SAFE="n"; echo "  CWD: normal" ;;
    *)    CWD_SAFE="y"; echo "  CWD: safe" ;;
esac

read -rp "Treat outside of CWD as unsafe? [Y/n]: " NOTCWD_UNSAFE
case "$NOTCWD_UNSAFE" in
    [Nn]) NOTCWD_UNSAFE="n"; echo "  Outside CWD: normal" ;;
    *)    NOTCWD_UNSAFE="y"; echo "  Outside CWD: unsafe" ;;
esac
echo

# 1. Verify build
echo "[1/5] Verifying installation..."
if [ ! -f "$SCRIPT_DIR/dist/hook.js" ]; then
    echo "  ERROR: dist/hook.js not found. Run 'npm install && npm run build && npm install -g .' first."
    exit 1
fi
echo "  Done."
echo

# 2. Create directories
echo "[2/5] Creating directories..."
mkdir -p "$CONFIG_DIR"
mkdir -p "$SESSIONS_DIR"
mkdir -p "$OVERLAYS_DIR"
echo "  Created: $CONFIG_DIR"
echo "  Created: $SESSIONS_DIR"
echo "  Created: $OVERLAYS_DIR"
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

# Apply directory trust settings
TMP_SAFE="$TMP_SAFE" CWD_SAFE="$CWD_SAFE" NOTCWD_UNSAFE="$NOTCWD_UNSAFE" POLICIES="$CONFIG_DIR/policies.json" node -e "
const fs = require('fs');
const policies = JSON.parse(fs.readFileSync(process.env.POLICIES, 'utf-8'));
const tmpSafe = process.env.TMP_SAFE === 'y';
const cwdSafe = process.env.CWD_SAFE === 'y';
const notcwdUnsafe = process.env.NOTCWD_UNSAFE === 'y';

// Build safe_directories
const safeDirs = [];
if (tmpSafe) safeDirs.push('/tmp');
if (cwdSafe) safeDirs.push('\$CWD');
if (safeDirs.length > 0) {
    policies.safe_directories = safeDirs;
    console.log('  Safe directories: ' + safeDirs.join(', '));
} else {
    delete policies.safe_directories;
    console.log('  No safe directories');
}

// Build unsafe_directories
// Always include the TrustEngine config dir — the deny-write-in-unsafe rule
// (priority 90) beats grant_permission grants (priority 85), so the agent
// cannot grant itself Write/Edit access to policies.json.
// Bash-level protection is still hardcoded in the hook for full coverage.
const configDir = require('path').join(require('os').homedir(), '.config', 'trustengine');
const unsafeDirs = [configDir];
if (notcwdUnsafe) unsafeDirs.push('\$NOTCWD');
policies.unsafe_directories = unsafeDirs;
console.log('  Unsafe directories: ' + unsafeDirs.join(', '));

fs.writeFileSync(process.env.POLICIES, JSON.stringify(policies, null, 4));
"
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

// Remove any existing TrustEngine hooks (handles path changes from reinstalls)
const hookCmd = process.env.HOOK_COMMAND;
settings.hooks.PreToolUse = settings.hooks.PreToolUse.filter(
    h => !Array.isArray(h.hooks) || !h.hooks.some(hh => typeof hh.command === 'string' && hh.command.includes('trustengine'))
);

// Add the hook with the current path
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
console.log('  Set PreToolUse hook: ' + hookCmd);

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
var mcpArgs = process.env.MCP_ARG ? [process.env.MCP_ARG] : [];
config.mcpServers.trustengine = {
    command: process.env.MCP_COMMAND,
    args: mcpArgs,
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
echo "Directory trust:"
if [ "$TMP_SAFE" = "y" ]; then echo "  /tmp: safe"; else echo "  /tmp: normal"; fi
if [ "$CWD_SAFE" = "y" ]; then echo "  CWD: safe"; else echo "  CWD: normal"; fi
if [ "$NOTCWD_UNSAFE" = "y" ]; then echo "  Outside CWD: unsafe"; else echo "  Outside CWD: normal"; fi
echo "Use grant_permission to add/remove safe and unsafe directories."
echo
echo "Restart Claude Code to apply changes."
echo
echo "Quick test:"
echo "  echo '{\"session_id\":\"test\",\"cwd\":\"/tmp\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"ls\"}}' | $HOOK_COMMAND"
echo
