export interface HookInput {
    session_id: string;
    cwd: string;
    tool_name: string;
    tool_input: Record<string, unknown>;
}

export interface HookSpecificOutput {
    hookEventName: "PreToolUse";
    permissionDecision: "allow" | "deny" | "ask";
    permissionDecisionReason?: string;
    additionalContext?: string;
}

export interface HookOutput {
    hookSpecificOutput: HookSpecificOutput;
}

export interface TrustRule {
    id: string;
    tool: string;
    match?: Record<string, string>;
    action: "allow" | "deny";
    priority: number;
    description: string;
    scope?: "permanent" | "session" | "once";
    acknowledged_risks?: string[];
}

export interface KnownRisk {
    id: string;
    tool: string;
    match?: Record<string, string>;
    risk: string;
    severity: "block" | "escalate" | "acknowledge";
}

export interface PoliciesFile {
    version: number;
    rules: TrustRule[];
    known_risks: KnownRisk[];
    safe_directories?: string[];
    unsafe_directories?: string[];
}

export interface OverlayFile {
    version: number;
    name: string;
    description?: string;
    rules?: TrustRule[];
    known_risks?: KnownRisk[];
    remove_rules?: string[];
    remove_risks?: string[];
    safe_directories?: string[];
    unsafe_directories?: string[];
}

export interface SessionFile {
    session_id: string;
    grants: TrustRule[];
    created_at: string;
}

export interface EvaluationResult {
    decision: "allow" | "deny";
    matched_rule?: TrustRule;
    risk_warnings: KnownRisk[];
    reason: string;
    once_grants_consumed?: string[];
    denied_commands?: string[];
    denied_sub_commands?: string[];
}
