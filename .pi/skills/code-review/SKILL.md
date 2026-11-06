---
name: code-review
description: Review ssh-mcp changes for defects before merge — diff/PR/file review with this repo's severity rubric, concurrency, SFTP and path-safety checks. Use when asked to review code, a diff, a branch, or a PR here.
---

# Code review for ssh-mcp

Review is a defect hunt, not a summary of the diff. Read enough of the surrounding code to judge whether a change is correct, then report only what carries risk.

## Establish scope first

Never review a diff you have not seen in full.

```bash
git status --short
git diff --stat                 # what changed
git diff                        # unstaged
git diff --cached               # staged
git log --oneline -5            # context for a branch review
git show <sha>                  # single commit
```

Large diffs: review file by file, and read the whole function around each hunk. The changed lines rarely contain the invariant they break.

## Read the project rubric

Read the changed module and its neighbours before judging: `src/ssh_mcp/ssh/` (pool, connector, auth_state, sftp_ops, transfer), `src/ssh_mcp/tools/`, `src/ssh_mcp/config.py`, `src/ssh_mcp/errors.py`.

## Checklist for this codebase

**Connections and lifecycle** — `ssh/pool.py`, `ssh/connector.py`, `ssh/auth_state.py`
- Is a connection always closed on every error path, including cancellation?
- Does a "rebuilt" connection keep its handle identity (see `test_auth_state.py`)? A rebuild that leaks the old client or hands back a dead one is P0.
- Are pool ceilings enforced before dialling, so a burst cannot open unbounded sessions?

**Async correctness**
- Any blocking call inside a coroutine (`time.sleep`, sync socket/file I/O, `requests`) is P0: it stalls the whole event loop.
- Timeouts must propagate through the whole operation, not only the socket connect. `asyncio.CancelledError` must not be swallowed by a bare `except Exception`.
- Shared mutable state across tasks needs an owner: lock, single writer, or explicit per-task copy.

**Transfer and SFTP** — `ssh/sftp_ops.py`, `ssh/transfer.py`, `tools/transfer_tools.py`
- Partial writes: a failure must not leave a truncated file that looks complete. Expect temp file + atomic rename, or an error the caller cannot mistake for success.
- Resume/retry: bounded attempts, and retry must not replay already-written bytes.
- Verify size/mtime or hash where the code claims it did.
- Timeouts: `SSH_MCP_SFTP_TOTAL_TIMEOUT` caps the whole transfer; `0` means no cap and must stay that way.

**Input validation** — `errors.py::validate_remote_path`, `config.py::PathNotAllowed`
- Exactly one implementation of remote-path validation. A second local copy is P1 (they drift; this already happened, see commit `fix: dedupe remote-path validation`).
- Local writes are capped by `SSH_MCP_WRITE_LOCAL_ROOTS`; upload targets must go through it. Symlink traversal out of an allowed root counts as a hole.
- Paths that arrive from the model are untrusted input: no shell interpolation, no `..` escapes.

**Config** — `config.py`
- New fields go through `src.number()` / `src.env()` so bad values raise `ConfigError` instead of silently defaulting.
- New environment variables need `.env.example` and README entries; a missing doc entry is P2, a missing validation is P1.

**Errors and logging** — `errors.py`, `logging_setup.py`
- `ToolFailure` should carry something diagnosable. Turning a specific exception into a generic string is P1.
- Never log passwords, key material, or `MCP_KEY`. Grep the diff for `password`, `key`, `token`, `secret`.
- Broad `except Exception: pass` is P0 when it hides a failed operation.

**Credentials and crypto** — `credentials/client.py`, `crypto/blob_decryptor.py`
- Key material must not be written to disk in clear or printed. Decryption failures must fail closed.

**Tool layer** — `tools/*.py`
- MCP schema and implementation must agree on names, defaults, and required fields (`tests/test_tools_schema.py` covers this).
- Return payloads must stay out of the context budget: never return whole file contents when a summary or a path suffices.
- Resource ids and server names in tool results must stay valid for later calls.

**Tests**
- Run is `python -m pytest`, config `pythonpath = src`, `asyncio_mode = auto`.
- On Windows the default temp dir may be unwritable: use `--basetemp=.pytest-tmp/<name>`.
- A behaviour change without a test, a bug fix without a regression test, or a test that asserts on a mock instead of the code under test: P1.
- Review tests for real coverage: a test that would pass with the fix reverted proves nothing.

## Severity

- **P0 — block**: wrong results, data loss, secret leak, crash, resource leak, silent corruption, event-loop stall.
- **P1 — fix before merge**: realistic-path correctness bug, missing I/O error handling, unbounded growth, race, missing regression test, validation drift.
- **P2 — suggest**: naming, duplication, doc drift — only with a stated maintenance cost.

## Evidence rules

- Every finding: `path:line`, failure mode, triggering input or state, concrete fix.
- Trace it: name the caller or test that shows the hazard. Untraced suspicion is reported as unverified, never as a defect.
- Quote the judged line. No finding made of adjectives.
- Style preferences are not defects. Keep them out of P0/P1.
- "No P0/P1 findings" is a complete, useful review. Do not invent findings to look thorough.

## Output

```markdown
## Scope
Commit/range/files reviewed and how you established it.

## Findings
### P0
- `path:line` — failure mode, trigger, fix.
### P1
### P2

## Verified
What you actually checked (call sites, error paths, tests); what remains unverified.

## Verdict
Mergeable / needs changes / needs rework + the minimum set for merge.
```

## Rules of engagement

- Read-only: no edits, no builds, no mutating commands. Allowed: `git` inspection, `rg`, reading files, `pytest --collect-only`, and running a single relevant test when that is the only way to confirm a suspicion.
- Never run the full suite as part of a review unless asked.
- Do not review code you were not asked to review, and do not propose unrelated refactors.
