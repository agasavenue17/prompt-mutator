# Usage guide

This guide covers setup on each supported environment and the full
workflow end to end: write a threat model, generate prompt variants,
split the work across agents, collect signals, and run follow-up
rounds. The README is the short version. This file is the working
version.

## Setup

The tool needs Python 3.11+ and nothing else. It uses the Python
standard library only. No `pip install` step exists.

### Linux VPS (Ubuntu / Debian)

```bash
sudo apt update && sudo apt install -y python3 python3-venv
python3 --version   # must be 3.11 or newer
```

Create a virtual environment. It is optional, but it keeps the system
Python clean.

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### macOS

Install Python through Homebrew. The Python that ships with macOS is
too old for this tool.

```bash
brew install python@3.12
python3 --version   # must be 3.11 or newer
python3 -m venv .venv
source .venv/bin/activate
```

### WSL on Windows

Install Ubuntu from the Microsoft Store, then follow the Linux VPS
steps inside WSL. Keep the repo inside the WSL filesystem
(`~/prompt-mutator`), not under `/mnt/c`. Files under `/mnt/c` are
slower and file watching breaks there.

From Windows Explorer you can still reach the files at
`\\wsl$\Ubuntu\home\<user>\prompt-mutator`.

Environment variables set with `export` last only for the current
shell session. To keep them across sessions, add the export lines to
`~/.bashrc` (or `~/.zshrc` if you use zsh), then open a new terminal
or run `source ~/.bashrc`.

### Native Windows PowerShell

Install Python from python.org or with winget:

```powershell
winget install Python.Python.3.12
py --version   # must be 3.11 or newer
```

Create a virtual environment and activate it:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Use the `mutator.ps1` wrapper to run the tool. It finds `python` or
the `py` launcher for you:

```powershell
.\mutator.ps1 mutate --no-api --threat-model threat-models\TEMPLATE.md --target <TargetName>
```

If PowerShell refuses to run the script, check the execution policy
for the current user:

```powershell
Get-ExecutionPolicy -Scope CurrentUser
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

## API keys

Keys come from environment variables only. The tool never prints a
key and never stores one in a file. Two providers are built in.

| Provider | Default | Env vars |
| --- | --- | --- |
| OpenAI-compatible (default) | `gpt-4o-mini` at `https://api.openai.com/v1` | `OPENAI_API_KEY`, `OPENAI_MODEL`, `OPENAI_BASE_URL` |
| DeepSeek (alternative) | `deepseek-flash` at `https://api.deepseek.com/v1` | `DEEPSEEK_API_KEY`, `DEEPSEEK_MODEL`, `DEEPSEEK_BASE_URL` |

Set the key for the provider you use:

```bash
# Linux / macOS / WSL
export OPENAI_API_KEY="<your-api-key>"
```

```powershell
# Windows PowerShell, current session only
$env:OPENAI_API_KEY = "<your-api-key>"
```

To persist the key on Windows across sessions:

```powershell
[Environment]::SetEnvironmentVariable("OPENAI_API_KEY", "<your-api-key>", "User")
```

`OPENAI_BASE_URL` points the default provider at any OpenAI-compatible
endpoint, so the same provider entry works with other hosted models.
Use `--provider deepseek` to switch providers, or override per run:

```bash
python3 mutator.py mutate --provider deepseek --threat-model threat-models/TEMPLATE.md --target <TargetName>
python3 mutator.py mutate --api-key "<your-api-key>" --base-url "https://example.com/v1" --model-id "some-model" --threat-model threat-models/TEMPLATE.md --target <TargetName>
```

Key hygiene:

- Never paste a key into a threat model, a run file, or a chat log.
- Never commit a key. The repo has no place for one.
- Do not put keys in shell history if you can avoid it. On Linux and
  macOS, use `read -s OPENAI_API_KEY` and press Enter, type the key
  (it is not shown), then run `export OPENAI_API_KEY`. The value never
  lands in the history file. On Windows, prefer the persistent
  environment variable above.
- If a key leaks, revoke it at the provider and issue a new one. Do
  not try to clean it out of logs by hand.

No key is needed at all for template mode. See step 1 below.

## The workflow end to end

### 0. Fill in the threat model

Copy `threat-models/TEMPLATE.md` to a file named after the target,
for example `threat-models/example.md`. Fill in every section:

- `Target:` the project name.
- `Project type:` `web2`, `web3-contract`, or `wallet`. The type
  changes lens wording and attacker starting positions.
- `## Priority angle`: pick max 3 classes from the candidate list for
  that project type in `priority-classes.json`, highest impact first.
  Read `CHEAT-MAP-KELAS.md` before choosing. Only the top 3 are used
  in a run.
- `## Use cases`: one bullet per real user flow. Variants name the use
  case they target.
- `## Scope`, `## Out of scope`, `## Surfaces / assets / entry
  points`, `## Trust boundaries`, `## Auth / identity`,
  `## State model`: one bullet per item, short and factual.

The mutator is only as good as this file. An empty or wrong threat
model produces empty or wrong variants.

### 1. Mutate: generate prompt variants

Template mode first. It needs no key, costs nothing, and is
deterministic.

```bash
python3 mutator.py mutate --no-api --threat-model threat-models/example.md --target Example
```

What it produces:

- A run directory, `runs/Example-<date>/` by default. Use `--out` to
  pick a different directory.
- `runs/Example-<date>/run.json`: the run manifest. It holds the
  target, project type, threat model path, rounds, every prompt with
  its id, lens, surface, status, and API usage totals.
- `runs/Example-<date>/variants-round-1.md`: the round 1 variants as
  readable Markdown, one `##` section per variant.

The command prints one line per lens with the new variant count, then
a round summary: total new variants, total prompts in the run, the run
directory, and the variants file. Default is 3 variants per lens, 39
variants for all 13 lenses. Change it with `--variants-per-lens`.

API mode uses a cheap model to rewrite each lens against the threat
model instead of the built-in templates. Same command, no `--no-api`:

```bash
python3 mutator.py mutate --threat-model threat-models/example.md --target Example
```

It uses the default provider (`openai`, `OPENAI_API_KEY`). The run
manifest records the source as `llm:openai/<model>` and counts API
calls and tokens in and out. Default budget is 40 calls per command
(`--max-api-calls`).

Narrow a run without editing the threat model:

```bash
# only certain lenses
python3 mutator.py mutate --threat-model threat-models/example.md --target Example --lenses L01,L06,L07

# only certain classes (ids from priority-classes.json)
python3 mutator.py mutate --threat-model threat-models/example.md --target Example --classes tenant-isolation,payment-logic
```

Precedence: `--lenses` beats `--classes`, which beats the priority
angle in the threat model, which beats all 13 lenses. Running `mutate`
again on the same run directory starts a new round in the same run.
Add `--fresh` to start a new run even if the directory exists.

What to check after it runs: the `[classes] ...` line at the top of
the output. It tells you which classes were picked and which lenses
they map to. If it says `no priority classes in threat model`, the
threat model has no `### Class N - <name>` headings and all 13 lenses
were used instead.

### 2. Swarm: split the work across agents

```bash
python3 mutator.py swarm --run runs/Example-<date> --agents 8
```

What it produces:

- `runs/Example-<date>/swarm/agent-01.md` through `agent-08.md`:
  one task file per agent, each with its assigned prompts, the target,
  the threat model path, and the gate rules.
- `runs/Example-<date>/signals/`: an empty directory, ready for
  results.

The command prints one line per agent file and the count of prompts
assigned. Default is 8 agents, 1 prompt per agent. Change it with
`--agents` and `--prompts-per-agent`. Prompts already assigned are not
assigned again. If nothing is new, it prints `No new prompts to
assign` and you need a new round first.

Hand one file per agent. Each agent works its own file and nothing
else.

### 3. Collect signals

Each agent writes its result to `runs/Example-<date>/signals/agent-XX.md`
with one of two shapes:

- `## Finding` (or `No finding`) with evidence, for a confirmed or
  ruled-out candidate.
- `Lead: ...` lines for anything unconfirmed but worth a follow-up
  round.

A signal is not a finding. The gate rules in each task file say so:
verdicts are CONFIRMED / FALSIFIED / INCONCLUSIVE only, and a proven
mechanism is not a valid vulnerability without executed proof on an
in-scope target.

### 4. Ingest: follow-up rounds from signals

```bash
python3 mutator.py ingest --run runs/Example-<date> --signals runs/Example-<date>/signals
```

What it does:

- Reads every `Lead: ...` line and Finding section in the signals
  directory, dedupes them, and skips leads already ingested in an
  earlier round.
- Generates follow-up variants for each lead (default 2 per lead,
  `--variants-per-lens`) and caps the batch at 10 leads
  (`--max-leads`).
- Appends a new round to `run.json` and writes
  `variants-round-2.md`.

It prints the lead count, one line per lead with its follow-up count,
and `Next: swarm --run <run dir> --agents N` at the end. Add `--no-api`
for template-mode follow-ups, or leave it out for LLM follow-ups with
the same provider options as `mutate`.

Then run `swarm` again to assign the new round, collect signals
again, and repeat until paths run out or signals stop.

### 5. Status: check where a run stands

```bash
python3 mutator.py status --run runs/Example-<date>
```

What it prints: the target, the threat model path, the rounds with
their variant counts and sources, total prompts by status
(`new` vs `assigned`), the number of signals ingested, API calls and
tokens so far, and the run directory. Run it any time. It changes
nothing.

## Practical notes

### Long sessions on a VPS

API runs are short, but a full loop across many agents can run long.
An SSH disconnect kills a foreground process. Use tmux or nohup.

```bash
# tmux: start named, detach with Ctrl-b then d, reattach later
tmux new -s mutator
python3 mutator.py mutate --threat-model threat-models/example.md --target Example
tmux attach -t mutator

# nohup: run in the background, logs go to a file
nohup python3 mutator.py mutate --threat-model threat-models/example.md --target Example > mutate.log 2>&1 &
```

The tool writes state to `run.json` after each lens and after each
round, so an interrupted run keeps what it finished. Re-run the same
command to continue it as a new round.

### WSL

Keep the repo inside the WSL home directory. Do not run it from
`/mnt/c`: file access is slower and some tools misbehave there. Set
API keys in `~/.bashrc` or `~/.zshrc` so they persist across terminal
sessions. The `mutator.ps1` wrapper is for native Windows PowerShell,
not for WSL. Inside WSL, call `python3 mutator.py` directly.

### Windows

Use `mutator.ps1` as the entry point. It finds `python` or the `py`
launcher and forwards every argument to `mutator.py`. Activate the
virtual environment first, or the wrapper uses whatever Python is on
`PATH`. All flags are identical to the Linux form; only the paths use
backslashes (`threat-models\TEMPLATE.md`).

### Troubleshooting

- `no API key: set OPENAI_API_KEY or pass --api-key`: the provider
  has no key. Export it, or add `--no-api` for template mode.
- API error 401 or 403: the key is wrong, revoked, or lacks access to
  the model. Check the env var, then the provider dashboard.
- `[classes] no priority classes in threat model`: the threat model
  has no `### Class N - <name>` headings under `## Priority angle`.
  All 13 lenses were used. Fill in the section and re-run.
- `No new prompts to assign`: every prompt is already assigned. Run
  `mutate` or `ingest` for a new round first.
- `No leads found in <signals dir>`: the signals directory has no
  `Lead: ...` lines and no Finding or Lead sections. Check that
  agents wrote to `signals/agent-XX.md` in the run directory.
- `threat model not found`: the `--threat-model` path is wrong. Check
  the path from the repo root.
