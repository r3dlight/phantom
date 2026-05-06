#!/usr/bin/env python3
"""Minimal mock MCP server for phantom-mcp live-audit tests.

Implements just enough of the MCP protocol (line-delimited JSON-RPC over stdio)
to respond to:
  - initialize  → returns serverInfo + capabilities
  - notifications/initialized → no response
  - tools/list  → returns four tools (one shell, one fs read, one fs write,
                  one safe)
  - resources/list  → returns one resource
  - prompts/list   → returns one prompt
  - any other method → returns method-not-found

Anything written to stderr is ignored by phantom-mcp.
"""
import json
import sys


def write(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


TOOLS = [
    {
        "name": "execute_shell",
        "description": "Run an arbitrary shell command on the host system and return stdout/stderr.",
        "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}},
    },
    {
        "name": "read_file",
        "description": "Read a file from the filesystem and return its contents.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
    },
    {
        "name": "write_file",
        "description": "Write data to a file on disk, creating it if necessary.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}},
    },
    {
        "name": "get_time",
        "description": "Return the current ISO-8601 timestamp.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]

RESOURCES = [
    {"uri": "file:///etc/hostname", "name": "hostname", "description": "Host machine name."}
]

PROMPTS = [
    {"name": "summarize", "description": "Produce a concise summary of supplied text."}
]


def respond(req_id, result):
    write({"jsonrpc": "2.0", "id": req_id, "result": result})


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = req.get("method")
        req_id = req.get("id")
        if method == "initialize":
            respond(req_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                "serverInfo": {"name": "mock-mcp", "version": "0.0.1"},
            })
        elif method == "notifications/initialized":
            # notification — no response
            pass
        elif method == "tools/list":
            respond(req_id, {"tools": TOOLS})
        elif method == "resources/list":
            respond(req_id, {"resources": RESOURCES})
        elif method == "prompts/list":
            respond(req_id, {"prompts": PROMPTS})
        elif method == "shutdown":
            respond(req_id, None)
            return
        elif req_id is not None:
            write({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"method not found: {method}"},
            })


if __name__ == "__main__":
    main()
