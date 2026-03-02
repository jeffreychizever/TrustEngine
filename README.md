# TrustEngine

Policy-driven trust enforcement for agentic AI tools. Provides granular control over which tool calls are allowed, denied, or require explicit justification — keeping the human in control while letting the agent self-serve within safe boundaries.

## How It Works

1. A **PreToolUse hook** intercepts every tool call and evaluates it against configurable policies
2. **Safe operations** (reads, searches, local edits) are auto-allowed
3. **Risky operations** (network, destructive commands, writes outside project) are denied with guidance
4. The agent requests access via **`grant_permission`** (MCP tool), providing justification
5. The **human approves or rejects** via Claude Code's permission prompt
6. Grants can be **one-off**, **session-scoped**, or **permanent**

```
Agent tries tool call
    |
    v
PreToolUse Hook ──reads──> policies.json + session grants
    |
    ├── ALLOW (matches allow rule, no unacknowledged risks)
    |
    ├── DENY (no matching rule / deny rule / known risks)
    |       |
    |       v
    |   Agent calls grant_permission ──> Hook validates args
    |       |                                |
    |       ├── Invalid args → DENY          |
    |       |   (bounced back to agent)      |
    |       |                                |
    |       └── Valid → ASK ─────> Human approves/rejects
    |                                  |
    |                                  v
    |                          Grant written to session/policies
    |                                  |
    |                                  v
    |                          Agent retries → ALLOW
    |
    └── Also: check_permission (pre-flight, no execution)
```

## Getting Started

### Installation

```bash
git clone <repo-url> && cd TrustEngine
./install.sh
```

The installer will:
1. Build TypeScript and install dependencies
2. Create config directory (`~/.config/trustengine/`)
3. Copy default policies
4. Add the PreToolUse hook to `~/.claude/settings.json`
5. Add the MCP server to `~/.claude.json`

Choose **Full mode** to replace Claude's built-in permissions with TrustEngine, or **Belt-and-suspenders mode** to run both systems in parallel while you validate.

Restart Claude Code after installation.

### Demo

Try this prompt in a Claude Code session to exercise TrustEngine's features:

```
I need you to do the following:
1. Create a project directory at /tmp/trustengine-demo with subdirectories src/ and build/
2. Write a simple hello.js file in src/ that console.logs "Hello from TrustEngine demo"
3. Run the script with node to verify it works
4. Fetch the contents of https://httpbin.org/json using curl
5. Copy the curl output to build/api-response.json
6. Run `git init` in the demo directory, add all files, and commit
7. Clean up by removing the entire /tmp/trustengine-demo directory
```

What you should see:

| Step | Tool | TrustEngine Decision | Why |
|------|------|---------------------|-----|
| 1 | `Bash: mkdir -p` | Auto-allowed | `mkdir` is a safe command |
| 2 | `Write` to `/tmp/...` | **Denied** → grant needed | Outside `$CWD` |
| 3 | `Bash: node src/hello.js` | Auto-allowed | `node` is a safe command |
| 4 | `Bash: curl` | **Denied** with risk warning | Network request risk |
| 5 | `Write` or `cp` | May need grant | Depends on approach |
| 6 | `Bash: git init/add/commit` | Auto-allowed | Safe git commands |
| 7 | `Bash: rm -r` | **Denied** with risk warning | File deletion risk |

You should be prompted to approve 3-4 `grant_permission` requests. The agent should:
- Call `grant_permission(help=true)` on first denial to learn the system
- Use **structured matchers** (`command_names` + `path_prefix`) instead of raw regex
- Choose **session** scope (not one-off) for operations it may repeat
- Scope destructive commands to `/tmp/trustengine-demo/`

## Default Policies

### Auto-Allowed
- Read, Glob, Grep, WebSearch, WebFetch (read-only tools)
- Agent orchestration tools (Agent, TaskCreate, etc.)
- Write/Edit within `$CWD/` (local project files)
- Safe bash commands (ls, git status, npm test, node, etc.)
- npm install, local git mutations (add, commit, checkout)

### Auto-Denied
- Destructive bash (`rm -rf /`, `sudo`, `mkfs`, fork bombs)
- Pipe-to-shell patterns (`curl | bash`)
- Write/Edit outside `$CWD/`

### Known Risks (deny + require justification)
- `git push` — modifies shared remote state
- `git reset --hard`, `git rebase`, `git push --force` — destructive history rewrite
- `curl`, `wget` — network requests
- `rm` — irreversible file deletion
- `.env` file edits — secrets exposure
- `npm publish` — irreversible public registry push

## MCP Tools

### `grant_permission`

Request permission for a blocked tool call. The human approves or rejects via Claude's prompt.

**Structured matchers (preferred for Bash):**
```
grant_permission(
  tool: "Bash",
  command_names: ["curl"],
  path_prefix: "https://api.example.com/",
  allowed_flags: ["--header", "-s"],
  scope: "session",
  description: "Allow curl to fetch from example API",
  justification: "Need to query the API for project data",
  session_id: "<from deny message>"
)
```

This compiles to: `^curl\s+(--header\s+|-[s]+\s+)*https://api\.example\.com/`

**Raw regex (advanced):**
```
grant_permission(
  tool: "Write|Edit",
  match: {"file_path": "^/home/user/.claude/plans/"},
  scope: "permanent",
  description: "Allow writing Claude Code plan files",
  justification: "Plan mode needs to write to ~/.claude/plans/"
)
```

### `check_permission`

Pre-flight check — test whether a tool call would be allowed without executing it:

```
check_permission(
  tool_name: "Bash",
  tool_input: {"command": "curl https://example.com"},
  cwd: "/home/user/project",
  session_id: "<session_id>"
)
```

Returns `ALLOWED` or `DENIED` with reasons. Use this to plan ahead and batch grant requests.

## CLI Usage

```bash
# List all permanent rules and known risks
npx trustengine list

# Test a tool call against policies
npx trustengine evaluate '{"session_id":"test","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"ls"}}'

# Remove a rule by ID
npx trustengine remove <rule-id>
```

## Policy File Format

Policies live at `~/.config/trustengine/policies.json`:

```json
{
    "version": 1,
    "rules": [
        {
            "id": "allow-reads",
            "tool": "Read|Glob|Grep",
            "action": "allow",
            "priority": 80,
            "description": "Allow read-only tools"
        },
        {
            "id": "deny-rm-root",
            "tool": "Bash",
            "match": { "command": "^rm\\s+-rf\\s+/($|\\s)" },
            "action": "deny",
            "priority": 100,
            "description": "Block rm -rf / (root)"
        }
    ],
    "known_risks": [
        {
            "tool": "Bash",
            "match": { "command": "git\\s+push" },
            "risk": "Modifies shared remote state",
            "severity": "medium"
        }
    ]
}
```

### Rule Fields
- **id**: Unique identifier
- **tool**: Regex matching tool name
- **match**: Optional dict of parameter regex patterns (`$CWD` is substituted)
- **action**: `allow` or `deny`
- **priority**: Higher = evaluated first. Deny wins at equal priority. Grants get priority 95.
- **description**: Human-readable explanation
- **risks_acknowledged**: `true` on human-approved grants to bypass known risk veto

## Bash Command Decomposition

TrustEngine splits compound bash commands (`;`, `&&`, `||`, `|`, `$()`, backticks) and evaluates each sub-command independently. ALL sub-commands must pass for the compound command to be allowed.

This prevents bypass attempts like `ls && rm -rf /` — both sub-commands are evaluated, and the denial message lists all failures so the agent can request a single broad grant.

## Design Principles

- **Fail-closed**: Unknown tools/commands are denied by default
- **Human-in-the-loop**: `grant_permission` requires human approval via Claude's prompt
- **Self-protected**: The agent cannot directly edit `policies.json`
- **Priority-based**: Higher priority rules override lower ones; deny wins ties
- **Risk-aware**: Known risks override allow rules, requiring explicit acknowledgment
- **Structured matchers**: Agent specifies command names + path prefixes instead of writing raw regex
- **Pre-validated**: Invalid grant requests are rejected before reaching the human
- **Portable**: `$CWD` substitution makes rules work across projects
