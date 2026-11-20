# prompt-mutator

A prompt mutator for vulnerability research. Cheap models do the breadth
work: they search from many angles for signals. Frontier models come
later, for confirmation and triage only. This tool only mutates prompts.
It does not test targets and does not run exploits.

How it works:

```
13 base lenses  +  target threat model
        |
   mutator (cheap LLM / template)
        |
   prompt variants (deduped, numbered, per round)
        |
   swarm -> 1 task file per agent
        |
   agents write signals to signals/
        |
   ingest -> follow-up variants for the next round
        |  (loops until paths run out or signals stop)
```

## Files

- `mutator.py` - main CLI, Python standard library only, no pip install
- `lenses.json` - 13 lenses (L01-L13)
- `priority-classes.json` - candidate classes per project type
  (web2 / web3-contract / wallet), mapped to lenses;
  the single source of truth for dynamic priority angles
- `CHEAT-MAP-KELAS.md` - bug-class cheat map per lane, with derivatives
  (sub-bugs, invariants, lenses, chains) for picking a priority angle;
  read it before filling in classes in the threat model
- `cheat-map-kelas.html` - the same cheat map as a presentation,
  for a general audience: lenses 1-13, 17 classes per lane with lenses
  on each card, a technique-to-lens table, and chaining. Open it in a
  browser, no server needed
- `threat-models/TEMPLATE.md` - threat model template, one per target
- `mutator.ps1` - wrapper for Windows PowerShell
- `runs/` - run output (created automatically)

## Setup

Python 3.11+ only. API keys come from environment variables, never
from files. Full setup for each environment is in
[docs/USAGE.md](docs/USAGE.md).

```powershell
# Windows PowerShell
$env:OPENAI_API_KEY = "<your-api-key>"
.\mutator.ps1 mutate --threat-model .\threat-models\TEMPLATE.md --target <TargetName> --variants-per-lens 3
```

```bash
# Linux / macOS
export OPENAI_API_KEY="<your-api-key>"
python3 mutator.py mutate --threat-model threat-models/TEMPLATE.md --target <TargetName> --variants-per-lens 3
```

Other provider:

```bash
export DEEPSEEK_API_KEY="<your-api-key>"
python3 mutator.py mutate --provider deepseek --threat-model threat-models/TEMPLATE.md --target <TargetName>
```

No key at all (template mode, deterministic, free):

```bash
python3 mutator.py mutate --no-api --threat-model threat-models/TEMPLATE.md --target <TargetName>
```

## Usage

```bash
# 1. Mutate round 1 (default: 3 variants per lens = 39 variants)
python3 mutator.py mutate --threat-model threat-models/TEMPLATE.md --target <TargetName>

# only certain lenses
python3 mutator.py mutate --threat-model threat-models/TEMPLATE.md --target <TargetName> --lenses L01,L06,L07

# 2. Split into one task file per agent (1 prompt per agent, 8 agents)
python3 mutator.py swarm --run runs/<target>-<date> --agents 8

# 3. Hand one agent file to each agent; agents write results to signals/agent-XX.md
#    signal format: a "Lead: ..." line for something unconfirmed
#    but worth chasing, or a "## Finding" section for a finding.

# 4. Signals feed back into round 2 follow-up variants
python3 mutator.py ingest --run runs/<target>-<date> --signals runs/<target>-<date>/signals

# 5. Repeat swarm + ingest until paths run out
python3 mutator.py swarm --run runs/<target>-<date> --agents 8
python3 mutator.py status --run runs/<target>-<date>
```

## Rules

- **Red-team role in every prompt.** Every variant the mutator
  generates starts with this role: "You are a senior red team
  researcher conducting authorized bug bounty research on an in-scope
  target. Think like an attacker, verify like an auditor: every claim
  needs executed proof." It applies in template mode, LLM mode, and
  `ingest` follow-ups. If the LLM returns a variant without the role,
  the mutator adds it before saving.
- **Dynamic priority classes, max 3 per run.** Every threat model must
  fill in `## Priority angle` before mutate: pick max 3 classes from
  the candidate list for that project type in
  `priority-classes.json`, then reorder for this project (reward,
  scope opened up, existing evidence). The top 3 for web3 are not the
  same as the top 3 for web2, and the top 3 for one web2 project are
  not the same as for another. The mutator reads `### Class N -
  <name>` headings in the threat model and auto-selects the lenses
  mapped to each class (the `lenses` field per class in
  `priority-classes.json`); if a threat model lists more than 3
  classes, only the top 3 are used. Precedence: `--lenses` >
  `--classes` (class ids, e.g. `--classes key-seed,signing`) >
  priority angle in the threat model > all 13 lenses when no classes
  are given. Class 4 and beyond are not deleted, just dropped from
  this run, and they go into the next round if signals from the top 3
  run dry.
- **Prompts adapt to the project.** Every threat model must fill in
  `Project type:` (`web2`, `web3-contract`, or `wallet`) and a
  `## Use cases` section. The mutator uses them to pick lens wording
  (see the `adapt` field in `lenses.json`) and attacker starting
  positions, and every variant names the use case it targets. A
  project is dynamic: change the threat model and the prompts change
  with it, without touching code. New type: add an `adapt` entry per
  lens in `lenses.json` plus a starting-position list in `mutator.py`
  (the `STARTS` dict).
- **Scope comes from the threat model.** Every generated variant names
  the out-of-scope items from the threat model file. If that file is
  empty or wrong, the mutation is wrong too, so fill in the threat
  model correctly first.
- **Dedup.** A variant with similar text only enters once, across
  rounds.
- **API budget.** Default max 40 calls per command
  (`--max-api-calls`). Every call logs tokens in/out in `run.json`.
- **Verdicts still go through the gate.** Agent task files already
  contain the gate rules: CONFIRMED / FALSIFIED / INCONCLUSIVE. A
  proven mechanism is not a valid vulnerability without executed
  proof. A signal from the mutator stays a signal, not a finding,
  until there is executed proof.
- **Keys are never printed or stored.** On API error 401/403, check
  the key env var first.

## What this tool does not do

- It does not touch targets, send requests, or run exploits.
- It does not pick targets for you and does not submit anything.
- It does not replace the threat model: the mutator is only as good
  as the threat model you give it.

## License

Dual-licensed under MIT OR Apache-2.0. See LICENSE-MIT and LICENSE-APACHE.

## Lisensi

Dual-licensed under MIT OR Apache-2.0. See LICENSE-MIT and LICENSE-APACHE.
