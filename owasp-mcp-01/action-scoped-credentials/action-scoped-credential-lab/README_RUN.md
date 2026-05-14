# action-scoped-credential-lab

Enterprise-style **local lab** demonstrating **action-scoped credentials** as a mitigation for **OWASP MCP-01** (token / credential exposure in MCP-like agent tool execution).

- **Python 3.11**, **stdlib only** (no `pip` dependencies).
- **Ollama** at `http://127.0.0.1:11434` using `/api/chat` with `stream: false`, `format: "json"`, `temperature: 0`.
- Runs on **Windows PowerShell** and **Linux/macOS**.

## What this lab proves

| Concept | Role |
|--------|------|
| **Broad token exposure** | Maps to **MCP-01 risk**: long-lived or delegation tokens in LLM context, logs, or traces are stealable and replayable at excessive scope. |
| **Signed capability** | **Authorization scope**: which tool, which constraints (`department`, `max_priority`), and lifetime — still server-verified, not raw LLM discretion. |
| **Action-scoped credential** | **Least-privilege execution + replay resistance**: one HMAC-bound execution for an exact `tool_name` + canonical `tool_input` hash, short TTL, **one-time nonce**. |
| **Token-less LLM path** | **Secrets never enter the model**: the SAFE orchestrator sends only `capability_id` + constraint hints; the vault holds the delegation token; the tool server binds execution to the action credential. |

## Components

| File | Purpose |
|------|---------|
| `common_http.py` | `post_json` with helpful HTTP error bodies. |
| `idp_stub.py` | Pseudo delegation token (server-side only in SAFE flow). |
| `capability_issuer.py` | HMAC-SHA256 signed capabilities (`canonical_json` for signing). |
| `action_credential.py` | HMAC-bound action credentials + in-memory nonce replay cache. |
| `register_key_norm.py` | Shared Unicode normalization + optional fp12 for REGISTER_KEY debug. |
| `tool_server.py` | HTTP server on **127.0.0.1:8799** — `/register`, `/issue`, `/tool`. |
| `agent_ollama.py` | Ollama JSON tool-intent extraction (SAFE vs UNSAFE prompt builders). |
| `orchestrator_safe.py` | Full SAFE pipeline + policy + replay tests. |
| `orchestrator_unsafe.py` | MCP-01 style: token in LLM context + injection attempt. |

## Threat model (concise)

**Trust boundaries**

1. **Human / client** → orchestrator: user intent in natural language.
2. **Orchestrator** → **IdP stub**: obtains delegation token; **must not** pass it to the LLM in the SAFE design.
3. **Orchestrator** → **Ollama**: only capability metadata and task text (SAFE).
4. **Orchestrator** → **tool_server `/register`**: registers `capability_id` → delegation token in an in-memory vault. Auth uses **`register_hmac`** in the JSON body: `HMAC-SHA256(REGISTER_KEY, canonical_json({capability_id, delegation_token}))` so the raw register secret is not placed in HTTP headers (avoids header encoding issues). Optional legacy: header `X-Register-Key` with the same secret.
5. **Orchestrator** → **tool_server `/issue`**: sends signed **capability** + structured **tool_input**; receives **action_credential** only (never the delegation token).
6. **Orchestrator** → **tool_server `/tool`**: sends **action_credential** + **tool_input**; server verifies binding and **one-time use**, then uses the vault token **only server-side** to simulate ITSM.

**How SAFE mitigates MCP-01**

- The **LLM never sees** the delegation token.
- Even if the model is **prompt-injected**, it cannot mint a valid **action credential** without the **HMAC signing keys** held by the tool server.
- **Replay** of a stolen action credential fails after first successful verification (nonce consumed).

**Out of scope (lab limits)**

- In-memory vault and replay set reset when the server restarts.
- No TLS, no real IdP, no database — patterns are illustrative.

## Prerequisites

1. **Python 3.11+**
2. **Ollama** installed and running locally.

### Start Ollama and pull a model

```bash
ollama serve
```

In another terminal:

```bash
ollama pull llama3.2
# or: ollama pull gemma3
```

## Environment variables

Set strong random strings for signing and registration (examples use PowerShell and bash).

**Windows PowerShell**

```powershell
$env:CAP_SIGNING_KEY = "replace-with-long-random-secret-a"
$env:ACTION_CRED_SIGNING_KEY = "replace-with-long-random-secret-b"
$env:REGISTER_KEY = "replace-with-long-random-register-secret"
$env:OLLAMA_MODEL = "llama3.2"
```

**Linux / macOS (bash)**

```bash
export CAP_SIGNING_KEY='replace-with-long-random-secret-a'
export ACTION_CRED_SIGNING_KEY='replace-with-long-random-secret-b'
export REGISTER_KEY='replace-with-long-random-register-secret'
export OLLAMA_MODEL='llama3.2'
```

Optional:

- `TOOL_SERVER_URL` — base URL the orchestrators call (default `http://127.0.0.1:8799`; must match where `tool_server` listens).
- `TOOL_SERVER_BIND` / `TOOL_SERVER_PORT` — bind address and port for `tool_server.py` (defaults `127.0.0.1` and `8799`).

## Run the tool server

From the `action-scoped-credential-lab` directory:

```bash
cd action-scoped-credential-lab
python tool_server.py
```

Leave this process running. Audit lines appear on **stderr** (no delegation tokens).

## Run orchestrators

**New terminal**, same `cd`, same env vars:

```bash
python orchestrator_safe.py
python orchestrator_unsafe.py
```

### Expected observations

**`orchestrator_safe.py`**

- **Scenario 1**: LLM returns JSON `tool_name` / `tool_input` / `capability_id` without any delegation material; `/issue` returns `action_credential`; `/tool` returns a synthetic `ticket_id`.
- **Scenario 2**: `/issue` with `priority: "high"` returns **`403`** / `forbidden` with message like `priority_exceeds_capability` (strict deny above `max_priority=medium`).
- **Scenario 3**: First `/tool` succeeds; second identical call returns **`replay_detected`** (or forbidden with that message).

**`orchestrator_unsafe.py`**

- Large **warning banner**.
- Stderr lines simulating **insecure agent logging** (length only, not required to print the secret).
- Model output is inspected for **substring match** of the embedded delegation token — if present, a **CRITICAL** line explains MCP-01 style exfiltration.

## Ollama JSON determinism

`agent_ollama.py` sets `format: "json"` and `temperature: 0` to encourage stable structured outputs. Models may still occasionally drift; Scenario 2 uses a **deterministic** `/issue` payload to prove server-side policy regardless of LLM variance.

## Security notes

- **Never** commit real signing keys.
- The **UNSAFE** script is for **training only**; it deliberately places secrets near the model.

## Troubleshooting

### Request never reaches the tool server (`ConnectionRefusedError`, timeout, or URL errors)

1. **Confirm the server is running** — in the terminal where you started `python tool_server.py` you should see  
   `tool_server listening on http://127.0.0.1:8799` (or your `TOOL_SERVER_BIND` / `TOOL_SERVER_PORT`).  
   If the process exited immediately, fix missing env vars (`CAP_SIGNING_KEY`, etc.) printed on stderr.

2. **Same machine, same URL** — orchestrators default to **`http://127.0.0.1:8799`**. The server binds to **`127.0.0.1`** by default so IPv4 clients always hit the listener. If you changed bind/port, set **`TOOL_SERVER_URL`** to match, e.g. `$env:TOOL_SERVER_URL = "http://127.0.0.1:9000"`.

3. **Quick port check (PowerShell)** — with the server running:

   ```powershell
   Test-NetConnection -ComputerName 127.0.0.1 -Port 8799
   ```

   `TcpTestSucceeded : True` means something is accepting on that port.

4. **WSL vs Windows** — if `tool_server` runs on **Windows** and the orchestrator runs inside **WSL**, `http://127.0.0.1:8799` from WSL is the **Linux** loopback, not Windows. Either run both in the same OS, or point **`TOOL_SERVER_URL`** at the Windows host IP from WSL (often the default gateway shown by `ip route` in WSL2).

5. **Firewall** — rare for loopback; if you bound to `0.0.0.0` and connect from another machine, allow the port in the OS firewall.

6. **Wrong `tool_server.py`** — this repo has more than one `tool_server.py` (e.g. under `delegation-token/`, `token-less-execution/`, and this lab). Run with an explicit path so you know which file Python loaded, for example:

   ```powershell
   python "C:\...\action-scoped-credential-lab\tool_server.py"
   ```

   On startup this lab’s server prints **`[tool_server] starting — loaded from:`** and the full path to the file that is actually running.

7. **Debug `print()` not visible** — the lab sends most server messages to **stderr** (`[AUDIT]`, listening line). The IDE “Run Python” panel sometimes treats stdout and stderr differently. Prefer `print(..., file=sys.stderr, flush=True)` for debugging, or run from a normal terminal: `python tool_server.py`.

### `[HTTP 401] … /register` and `invalid_register_key`

Registration accepts either:

1. **`register_hmac`** (preferred) — lowercase hex of `HMAC-SHA256(REGISTER_KEY, canonical_json({"capability_id":…,"delegation_token":…}))`, sent in the **JSON body** with those same fields. The orchestrators use this path so the register secret never travels in an HTTP header.

2. **Legacy** — header `X-Register-Key: <REGISTER_KEY>` (for manual `curl`). The header value must exactly match the server’s `REGISTER_KEY` (after the same trim / NFKC rules as the server).

Typical causes (when using legacy header auth, or if `register_hmac` is wrong):

1. **Different terminals** — keys exported in the orchestrator shell but the server was started earlier in another window **without** the same `REGISTER_KEY`.
2. **IDE vs terminal** — the server runs inside Cursor/VS Code with one env; the orchestrator runs in PowerShell with another.
3. **Typo or partial copy** when setting the three secrets.

**Fix:** stop `tool_server.py`, in **one** shell set `CAP_SIGNING_KEY`, `ACTION_CRED_SIGNING_KEY`, and `REGISTER_KEY` (and optionally `OLLAMA_MODEL`), start `python tool_server.py`, then in **that same shell** (or another shell with the **identical** three key values) run the orchestrator.

**PowerShell gotcha:** set the value without extra quotes inside the string, for example `$env:REGISTER_KEY = 'my-secret-here'` (single quotes avoid `$` expansion). After changing `REGISTER_KEY`, **restart** `tool_server.py` so it reloads the variable.

**Compare lengths / audit:** on failure, stderr may show `[AUDIT] register_denied hmac_ok=… header_ok=…`. With **`register_hmac`**, ensure **`CAP_SIGNING_KEY` / `ACTION_CRED_SIGNING_KEY` / `REGISTER_KEY`** match on both processes (HMAC uses the same `REGISTER_KEY` and the same JSON canonicalization as `capability_issuer.canonical_json`).

**Same length but still 401?** The secrets can still differ (homoglyphs, invisible characters). Set **`REGISTER_KEY_FINGERPRINT_DEBUG=1`** in **both** shells, restart `tool_server.py`, run the orchestrator, and compare **`register_key_fp12_*`** lines on the server with **`client fp12`** on the client (first 12 hex chars of SHA-256 of the normalized key). Matching fp12 means the normalized keys match; if they differ, re-type `REGISTER_KEY` in both places (do not paste from rich text). Unset the variable when you are done debugging.

**Fingerprints match but still 401?** Another process may still be listening on **8799** (an older `tool_server` without `register_hmac`). Kill stray `python tool_server.py` jobs or use a free port: `$env:TOOL_SERVER_PORT = "18888"` on the server and `$env:TOOL_SERVER_URL = "http://127.0.0.1:18888"` in the orchestrator shell.

---

## Quick checklist

1. `ollama serve` + `ollama pull <model>`
2. Export env vars (`CAP_SIGNING_KEY`, `ACTION_CRED_SIGNING_KEY`, `REGISTER_KEY`, `OLLAMA_MODEL`)
3. `python tool_server.py`
4. `python orchestrator_safe.py` then `python orchestrator_unsafe.py`
