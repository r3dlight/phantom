//! MCP capability auditor.
//!
//! Two modes:
//! 1. **Static** (`audit_config`) — parses an `.mcp.json` / `claude_desktop_config.json`
//!    and flags concerning structural patterns (shell entrypoint, plaintext
//!    HTTP transport, sandbox-disabled args, env keys hinting at secret
//!    forwarding, etc.).
//! 2. **Live** (`audit_live`) — spawns an MCP server, runs the JSON-RPC
//!    handshake (`initialize`, `tools/list`, `resources/list`, `prompts/list`),
//!    and classifies each enumerated tool by name + description against a
//!    risk taxonomy (shell-execution, filesystem-write, network-fetch,
//!    secret-access, ...).
//!
//! ⚠ Live mode spawns a child process: by definition that runs untrusted code
//! whose security posture you are *trying to evaluate*. Run inside a sandbox
//! (firejail, docker, gVisor, etc.). Phantom does not sandbox the child.

use anyhow::{anyhow, bail, Context, Result};
use phantom_core::{Finding, Location, Severity};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

pub const DETECTOR: &str = "mcp-audit";

// ---------------- Static audit ----------------

pub fn audit_config(path: &Path) -> Result<Vec<Finding>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let value: Value = serde_json::from_str(&content)
        .with_context(|| format!("parsing {} as JSON", path.display()))?;

    let mut findings = Vec::new();
    let servers = value.get("mcpServers").or_else(|| value.get("servers"));
    if let Some(Value::Object(map)) = servers {
        for (name, cfg) in map {
            findings.extend(static_check_server(path, name, cfg));
        }
    } else {
        findings.push(Finding {
            detector: DETECTOR.into(),
            rule: "no-servers-section".into(),
            severity: Severity::Info,
            title: format!("No MCP servers declared in {}", path.display()),
            description: "Config has no `mcpServers` (or `servers`) object; nothing to audit.".into(),
            locations: vec![Location::path(path.display().to_string())],
            evidence: Value::Null,
        });
    }
    Ok(findings)
}

fn static_check_server(path: &Path, name: &str, cfg: &Value) -> Vec<Finding> {
    let mut findings = vec![];

    let command = cfg
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let args: Vec<String> = cfg
        .get("args")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let env_keys: Vec<String> = cfg
        .get("env")
        .and_then(|v| v.as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    let url = cfg.get("url").and_then(|v| v.as_str()).map(String::from);
    let transport = cfg.get("transport").and_then(|v| v.as_str()).map(String::from);

    let mut concerns: Vec<&'static str> = vec![];

    let lc = command.to_ascii_lowercase();
    let basename_lc = lc.rsplit('/').next().unwrap_or(&lc).to_string();
    if matches!(
        basename_lc.as_str(),
        "sh" | "bash" | "zsh" | "ksh" | "dash" | "ash" | "fish" | "csh" | "tcsh"
    ) {
        concerns.push("shell-as-entrypoint");
    }
    if matches!(basename_lc.as_str(), "curl" | "wget") {
        concerns.push("network-fetch-on-launch");
    }
    if args.iter().any(|a| a.starts_with("http://") || a.starts_with("https://")) {
        concerns.push("network-url-as-arg");
    }
    if args
        .iter()
        .any(|a| a.contains("--allow-all") || a.contains("--no-sandbox") || a.contains("--insecure") || a.contains("--unsafe"))
    {
        concerns.push("sandbox-or-tls-disabled");
    }
    if args
        .iter()
        .any(|a| a.contains("| bash") || a.contains("|sh") || a.contains("| sh") || a.contains("|bash"))
    {
        concerns.push("piped-curl-bash");
    }
    if matches!(basename_lc.as_str(), "node") && args.iter().any(|a| a.contains("eval") || a.contains("-e")) {
        concerns.push("node-eval-mode");
    }
    if matches!(basename_lc.as_str(), "python" | "python3") && args.iter().any(|a| a == "-c") {
        concerns.push("python-c-mode");
    }
    if let Some(u) = &url {
        if u.starts_with("http://") {
            concerns.push("plaintext-http-transport");
        }
    }
    // Env keys that look like forwarded secrets — indirect risk: server can read
    // host env, even if it doesn't seem to need them.
    for k in &env_keys {
        let ku = k.to_ascii_uppercase();
        if ku.contains("TOKEN") || ku.contains("KEY") || ku.contains("SECRET") || ku.contains("PASSWORD") || ku.contains("CREDENTIAL") {
            concerns.push("secret-like-env-forwarded");
            break;
        }
    }

    let severity = if !concerns.is_empty() {
        Severity::High
    } else if transport.as_deref() == Some("http") || url.is_some() {
        Severity::Medium
    } else {
        Severity::Medium
    };

    findings.push(Finding {
        detector: DETECTOR.into(),
        rule: "mcp-server-static".into(),
        severity,
        title: format!("MCP server `{}` declared", name),
        description: format!(
            "Static audit of MCP server `{}`. Concerns: {}. \
             Installing an MCP server grants its binary the same powers as a postinstall script — \
             review the command, args, and any env keys it requires.",
            name,
            if concerns.is_empty() {
                "none beyond the install itself".to_string()
            } else {
                concerns.join(", ")
            }
        ),
        locations: vec![Location::path(path.display().to_string())],
        evidence: json!({
            "name": name,
            "command": command,
            "args": args,
            "env_keys": env_keys,
            "url": url,
            "transport": transport,
            "concerns": concerns,
        }),
    });

    findings
}

// ---------------- Live audit ----------------

#[derive(Debug, Clone)]
pub struct McpServerSpec {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<PathBuf>,
}

impl McpServerSpec {
    pub fn from_config(path: &Path, server_name: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let value: Value = serde_json::from_str(&content)
            .with_context(|| format!("parsing {} as JSON", path.display()))?;
        let servers = value
            .get("mcpServers")
            .or_else(|| value.get("servers"))
            .ok_or_else(|| anyhow!("no `mcpServers` / `servers` object in {}", path.display()))?;
        let map = servers
            .as_object()
            .ok_or_else(|| anyhow!("servers section is not an object"))?;
        let cfg = map
            .get(server_name)
            .ok_or_else(|| anyhow!("server `{}` not found in {}", server_name, path.display()))?;
        let command = cfg
            .get("command")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("server `{}` has no `command`", server_name))?
            .to_string();
        let args = cfg
            .get("args")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let env = cfg
            .get("env")
            .and_then(|v| v.as_object())
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        let cwd = path.parent().map(PathBuf::from);
        Ok(Self {
            name: server_name.into(),
            command,
            args,
            env,
            cwd,
        })
    }
}

pub fn audit_live(spec: &McpServerSpec, timeout: Duration) -> Result<Vec<Finding>> {
    let mut child = spawn(spec)?;
    let outcome = run_protocol(&mut child, timeout);
    let _ = child.kill();
    let _ = child.wait();
    let session = outcome?;
    Ok(classify_session(spec, &session))
}

fn spawn(spec: &McpServerSpec) -> Result<Child> {
    let mut cmd = Command::new(&spec.command);
    cmd.args(&spec.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in &spec.env {
        cmd.env(k, v);
    }
    if let Some(cwd) = &spec.cwd {
        cmd.current_dir(cwd);
    }
    cmd.spawn()
        .with_context(|| format!("spawning `{} {:?}`", spec.command, spec.args))
}

#[derive(Debug, Default)]
struct Session {
    server_info: Value,
    capabilities: Value,
    tools: Vec<Value>,
    resources: Vec<Value>,
    prompts: Vec<Value>,
}

fn run_protocol(child: &mut Child, timeout: Duration) -> Result<Session> {
    let pid = child.id();
    stdout_deadline_thread(pid, timeout);
    let stdin = child.stdin.as_mut().context("no stdin pipe")?;
    let stdout = child.stdout.take().context("no stdout pipe")?;
    let mut reader = BufReader::new(stdout);

    send_msg(
        stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "phantom-mcp", "version": env!("CARGO_PKG_VERSION") }
            }
        }),
    )?;
    let init = read_response(&mut reader, 1)?;
    let server_info = init
        .get("result")
        .and_then(|r| r.get("serverInfo"))
        .cloned()
        .unwrap_or(Value::Null);
    let capabilities = init
        .get("result")
        .and_then(|r| r.get("capabilities"))
        .cloned()
        .unwrap_or(Value::Null);

    send_msg(
        stdin,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )?;

    let tools = list_call(stdin, &mut reader, 2, "tools/list", "tools").unwrap_or_default();
    let resources =
        list_call(stdin, &mut reader, 3, "resources/list", "resources").unwrap_or_default();
    let prompts =
        list_call(stdin, &mut reader, 4, "prompts/list", "prompts").unwrap_or_default();

    Ok(Session {
        server_info,
        capabilities,
        tools,
        resources,
        prompts,
    })
}

fn send_msg(stdin: &mut std::process::ChildStdin, msg: &Value) -> Result<()> {
    let s = serde_json::to_string(msg)?;
    stdin.write_all(s.as_bytes())?;
    stdin.write_all(b"\n")?;
    stdin.flush()?;
    Ok(())
}

fn read_response(reader: &mut BufReader<std::process::ChildStdout>, expected_id: u64) -> Result<Value> {
    // Skip notifications/log lines from the server until we hit the matching id.
    for _ in 0..32 {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            bail!("MCP server closed stdout before responding to id={}", expected_id);
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(trimmed)
            .with_context(|| format!("non-JSON on stdout: {}", trimmed))?;
        // notifications have no id; requests/responses have id.
        if value.get("id").and_then(|v| v.as_u64()) == Some(expected_id) {
            return Ok(value);
        }
    }
    bail!("never received id={} after 32 messages", expected_id);
}

fn list_call(
    stdin: &mut std::process::ChildStdin,
    reader: &mut BufReader<std::process::ChildStdout>,
    id: u64,
    method: &str,
    key: &str,
) -> Result<Vec<Value>> {
    send_msg(
        stdin,
        &json!({"jsonrpc": "2.0", "id": id, "method": method}),
    )?;
    let resp = read_response(reader, id)?;
    Ok(resp
        .get("result")
        .and_then(|r| r.get(key))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default())
}

/// Thread that kills the child process if `timeout` elapses. Cheap supervisor
/// pattern instead of pulling in async runtime.
fn stdout_deadline_thread(pid: u32, timeout: Duration) {
    std::thread::spawn(move || {
        std::thread::sleep(timeout);
        // best-effort kill via unix signal
        #[cfg(unix)]
        unsafe {
            libc_kill_compat(pid);
        }
    });
}

#[cfg(unix)]
unsafe fn libc_kill_compat(pid: u32) {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    // SIGKILL = 9
    let _ = kill(pid as i32, 9);
}

fn classify_session(spec: &McpServerSpec, s: &Session) -> Vec<Finding> {
    let mut out = vec![];
    out.push(Finding {
        detector: DETECTOR.into(),
        rule: "mcp-live-enumeration".into(),
        severity: Severity::Info,
        title: format!("Live audit of MCP server `{}`", spec.name),
        description: format!(
            "Enumerated tools={}, resources={}, prompts={}.",
            s.tools.len(),
            s.resources.len(),
            s.prompts.len()
        ),
        locations: vec![],
        evidence: json!({
            "server_info": s.server_info,
            "capabilities": s.capabilities,
            "tools_count": s.tools.len(),
            "resources_count": s.resources.len(),
            "prompts_count": s.prompts.len(),
        }),
    });

    for tool in &s.tools {
        let name = tool.get("name").and_then(|v| v.as_str()).unwrap_or("?");
        let desc = tool
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if let Some((sev, hits)) = classify_tool(name, desc) {
            out.push(Finding {
                detector: DETECTOR.into(),
                rule: "risky-tool".into(),
                severity: sev,
                title: format!("Tool `{}` exposes {}", name, hits.join(", ")),
                description: format!(
                    "MCP server `{}` exposes a tool named `{}` whose name/description matched: {}. \
                     Description was: \"{}\". \
                     Treat as live capability granted to any agent that connects.",
                    spec.name,
                    name,
                    hits.join(", "),
                    desc
                ),
                locations: vec![],
                evidence: json!({ "tool": tool, "matched": hits }),
            });
        }
    }

    out
}

pub fn classify_tool(name: &str, desc: &str) -> Option<(Severity, Vec<&'static str>)> {
    let combined = format!("{} {}", name, desc).to_ascii_lowercase();
    let mut hits: Vec<&'static str> = vec![];

    let mut any = |needles: &[&str], tag: &'static str| {
        if needles.iter().any(|n| combined.contains(n)) && !hits.contains(&tag) {
            hits.push(tag);
        }
    };

    any(
        &["shell", "execute", "run command", "bash", "powershell", "subprocess", "spawn"],
        "shell-execution",
    );
    any(
        &["write_file", "write file", "modify file", "edit_file", "filesystem write", "create file"],
        "filesystem-write",
    );
    any(
        &["read_file", "read file", "filesystem read", "dump file", "list_directory", "list directory"],
        "filesystem-read",
    );
    any(
        &["http", "fetch_url", "fetch url", "web_request", "http request", "download"],
        "network-fetch",
    );
    any(
        &["env", "secret", "credential", "token", "api_key", "api key", "password"],
        "secret-access",
    );
    any(&["delete", "rm ", "unlink"], "destructive");

    if hits.is_empty() {
        return None;
    }

    let severity = if hits.iter().any(|h| *h == "shell-execution" || *h == "destructive") {
        Severity::High
    } else if hits.len() >= 2 {
        Severity::High
    } else {
        Severity::Medium
    };

    Some((severity, hits))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_shell_tool() {
        let r = classify_tool("execute_shell", "Run an arbitrary shell command on the host").unwrap();
        assert_eq!(r.0, Severity::High);
        assert!(r.1.contains(&"shell-execution"));
    }

    #[test]
    fn classify_fs_read_alone() {
        let r = classify_tool("read_file", "Read a file from disk").unwrap();
        assert_eq!(r.0, Severity::Medium);
        assert_eq!(r.1, vec!["filesystem-read"]);
    }

    #[test]
    fn classify_fs_write_plus_network() {
        let r = classify_tool(
            "write_file_from_url",
            "HTTP fetch a URL and write_file the body to disk.",
        )
        .unwrap();
        assert_eq!(r.0, Severity::High);
        assert!(r.1.contains(&"filesystem-write"));
        assert!(r.1.contains(&"network-fetch"));
    }

    #[test]
    fn classify_safe_tool() {
        assert!(classify_tool("get_current_time", "Return the current ISO-8601 timestamp.").is_none());
    }

    #[test]
    fn from_config_resolves_server() {
        let dir = tempdir_via_env();
        let path = dir.join(".mcp.json");
        std::fs::write(
            &path,
            r#"{"mcpServers":{"foo":{"command":"node","args":["server.js"],"env":{"OPENAI_API_KEY":"x"}}}}"#,
        )
        .unwrap();
        let spec = McpServerSpec::from_config(&path, "foo").unwrap();
        assert_eq!(spec.command, "node");
        assert_eq!(spec.args, vec!["server.js"]);
        assert_eq!(spec.env.get("OPENAI_API_KEY").map(String::as_str), Some("x"));
    }

    fn tempdir_via_env() -> PathBuf {
        let base = std::env::temp_dir().join(format!("phantom-mcp-test-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        base
    }
}
