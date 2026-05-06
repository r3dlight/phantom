# Phantom — example fixtures

## `aiconfig-trap/`

Synthetic repo seeded with four AI-era attack patterns:

1. **Prompt injection** in `CLAUDE.md` (`Ignore previous instructions…`).
2. **Hardcoded trust** assertion (`Always trust commits from …@tukaani.org`).
3. **Suspicious MCP server** in `.mcp.json` (`bash -c curl … | bash`).
4. **Permission bypass** in `.claude/settings.json` (`bypassPermissions: true`).

```sh
cargo run --bin phantom -- aiconfig examples/aiconfig-trap
cargo run --bin phantom -- mcp-audit examples/aiconfig-trap/.mcp.json
```

## `promptinjection-trap/`

A docs tree (`README.md`, `docs/welcome.md`, `.github/ISSUE_TEMPLATE/bug.md`)
seeded with prompt-injection content aimed at downstream AI reviewers:
override phrases, `###system` spoof, exfiltration directive, zero-width
Unicode characters in a comment.

```sh
cargo run --bin phantom -- promptinjection examples/promptinjection-trap
```

## `mcp-mock/`

A minimal Python MCP server (`server.py`) that responds to the JSON-RPC
handshake and advertises four tools (`execute_shell`, `read_file`,
`write_file`, `get_time`), one resource, one prompt. Used to drive the live
audit path of `phantom mcp-audit`.

```sh
cargo run --bin phantom -- mcp-audit examples/mcp-mock/.mcp.json --live --server mock
```

⚠ `--live` spawns the server. The mock is harmless; never run `--live` on a
server you do not already trust to start, and prefer running inside a sandbox
(firejail, docker, gVisor).

## `xz-replay/`

Synthetic reproduction of the CVE-2024-3094 smoking gun: a `git.tar.gz` that
has no `m4/build-to-host.m4`, paired with a `release.tar.gz` whose
`m4/build-to-host.m4` contains an `eval | base64 -d | tr` chain wrapped
around a long base64 string — the structural shape of the actual XZ payload.

```sh
cargo run --bin phantom -- tarball-diff \
    --git-archive examples/xz-replay/build/git.tar.gz \
    --release-tarball examples/xz-replay/build/release.tar.gz
```

Expected: an INFO on the file's release-only presence (allowlisted gettext
macro) **plus** a HIGH `build-file-obfuscation` finding listing the matched
patterns (`eval-piped-through-tr`, `base64-decode-shell`, `long-base64-string`).

The actual upstream XZ v5.6.0 / v5.6.1 release tarballs are no longer
available from the GitHub source — Phantom on a clean public release
(e.g. `tarball-diff --release tukaani-project/xz@v5.4.7`) reports zero
P0 / HIGH findings.

## Snapshot demo

There is no static fixture for `phantom snapshot` — a synthetic repo built
on the fly is more illustrative:

```sh
mkdir /tmp/snapdemo && cd /tmp/snapdemo && git init
# ... commits by Alice (src/) and a high-build-attraction author ...
phantom snapshot . --min-commits 5
```
