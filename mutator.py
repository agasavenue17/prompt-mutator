#!/usr/bin/env python3
"""prompt-mutator: threat-model-driven prompt mutation for vuln research.

Idea (from the tweet the operator shared): cheap/open-weight models do the
broad search with narrow, goal-specific prompts; a mutator rewrites base
lenses against the target's threat model; a swarm of agents each gets a
different starting prompt; signals feed back into the mutator for the next
round. Frontier models are only used later, for confirmation/triage.

This tool is the harness: it mutates PROMPTS. It does not test targets,
send requests, or run exploits. Every generated prompt stays inside the
scope written in the threat model file.

Subcommands:
  mutate   lenses x threat model -> variant prompts (LLM or template mode)
  swarm    split new variants into per-agent task files for Hermes
  ingest   read agent signal files -> next-round follow-up variants
  status   show run state (rounds, counts, API usage)

Keys come from the environment only, never from files:
  STEPFUN_API_KEY  (+ STEPFUN_MODEL, STEPFUN_BASE_URL)
  DEEPSEEK_API_KEY (+ DEEPSEEK_MODEL, DEEPSEEK_BASE_URL)

Examples:
  python3 mutator.py mutate --threat-model threat-models/TEMPLATE.md --target <NamaTarget> --variants-per-lens 3
  python3 mutator.py mutate --no-api --threat-model threat-models/TEMPLATE.md --target <NamaTarget>
  python3 mutator.py swarm --run runs/<target>-<tanggal> --agents 8
  python3 mutator.py ingest --run runs/<target>-<tanggal> --signals runs/<target>-<tanggal>/signals
  python3 mutator.py status --run runs/<target>-<tanggal>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

VERSION = "1.0.0"
BASE_DIR = Path(__file__).resolve().parent
LENSES_FILE = BASE_DIR / "lenses.json"
CLASSES_FILE = BASE_DIR / "priority-classes.json"
MAX_CLASSES_PER_RUN = 3
MAX_TM_CHARS = 6000  # threat-model excerpt sent to the mutator LLM

PRESETS = {
    "stepfun": {
        "base_url": "https://api.stepfun.ai/step_plan/v1",
        "model": "step-5-preview",
        "key_env": "STEPFUN_API_KEY",
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "model": "deepseek-flash",
        "key_env": "DEEPSEEK_API_KEY",
    },
}

# Attacker starting positions, per project type. A project is dynamic:
# the same lens means a different attacker in a web2 app, a contract,
# or a wallet. The threat model picks the type; unknown types fall back
# to the web2 list.
STARTS = {
    "web2": [
        "unauthenticated visitor",
        "authenticated low-privilege user",
        "a second user (different account / tenant)",
        "a user whose access was just revoked",
    ],
    "web3-contract": [
        "external caller with no privileges",
        "another contract",
        "a token holder",
        "a user whose allowance was just revoked",
    ],
    "wallet": [
        "a malicious dApp / WalletConnect peer",
        "a malicious website or deep-link sender",
        "a previously connected dApp session",
        "an attacker who can send the user a crafted link or QR code",
    ],
}


def starts_for(project_type: str) -> list[str]:
    return STARTS.get(project_type, STARTS["web2"])


def adapted_lens(lens: dict, project_type: str) -> str:
    """Lens text tailored to the project type, or the base text as fallback."""
    adapt = lens.get("adapt") or {}
    return adapt.get(project_type, lens["lens"])

GATE_RULES = """- Work IN SCOPE ONLY. Never test anything listed under Out of scope in the threat model.
- Verdicts are CONFIRMED / FALSIFIED / INCONCLUSIVE only.
- A proven mechanism is NOT a valid vulnerability without executed proof on an in-scope target.
- Evidence required for CONFIRMED: exact operation/endpoint, request/response or code location, and reproduction steps.
- Stop and report after the first concrete candidate with evidence, or after exhausting the assigned surface."""


# ---------------------------------------------------------------- lenses
def load_lenses(path: Path = LENSES_FILE) -> list[dict]:
    if not path.exists():
        sys.exit(f"lenses file not found: {path}")
    with open(path, encoding="utf-8") as f:
        lenses = json.load(f)
    if not isinstance(lenses, list) or not lenses:
        sys.exit(f"lenses file is empty or invalid: {path}")
    return lenses


def lens_by_id(lenses: list[dict], lens_id: str) -> dict | None:
    for lens in lenses:
        if lens["id"].lower() == lens_id.lower():
            return lens
    return None


# ---------------------------------------------------------------- threat model
SECTION_KEYWORDS = [
    ("surfaces", ("surface", "asset", "endpoint", "entry point", "attack surface", "flow")),
    ("trust_boundaries", ("trust boundar", "boundary")),
    ("auth", ("auth", "session", "identity", "login", "permission", "role")),
    ("state", ("state", "lifecycle")),
    ("use_cases", ("use case", "user journey", "use-case")),
    ("out_of_scope", ("out of scope", "out-of-scope", "forbidden", "prohibited", "do not")),
    ("scope", ("scope", "in scope", "in-scope")),
    ("priority_classes", ("angle prioritas", "priority class", "kelas prioritas")),
]


def normalize_project_type(raw: str) -> str:
    text = raw.lower()
    if "wallet" in text:
        return "wallet"
    if "web3" in text or "contract" in text or "on-chain" in text or "onchain" in text:
        return "web3-contract"
    return "web2"


def _section_for_heading(heading: str) -> str | None:
    h = heading.lower()
    for name, keywords in SECTION_KEYWORDS:
        if any(k in h for k in keywords):
            return name
    return None


def parse_threat_model(text: str) -> dict:
    """Parse a threat-model markdown file into sections + raw excerpt."""
    model: dict = {
        "target": "",
        "project_type": "web2",
        "project_type_raw": "",
        "surfaces": [],
        "trust_boundaries": [],
        "auth": [],
        "state": [],
        "use_cases": [],
        "scope": [],
        "out_of_scope": [],
        "priority_classes": [],
        "raw": text[:MAX_TM_CHARS],
    }
    current: str | None = None
    for line in text.splitlines():
        stripped = line.strip()
        heading = re.match(r"^#{1,4}\s+(.+)$", stripped)
        if heading:
            htext = heading.group(1).strip()
            # Inside Angle prioritas, a "### Kelas N — <name>" heading
            # IS a class entry, not a new section. Keep the section.
            if current == "priority_classes":
                m = re.match(r"^[Kk]elas\s+\d+\s*[—\-–:]\s*(.+)$", htext)
                if m:
                    name = re.sub(r"\s*\(impact[^)]*\)\s*$", "",
                                  m.group(1).strip(), flags=re.I).strip()
                    if name and "<" not in name:
                        model["priority_classes"].append(name)
                    continue
            current = _section_for_heading(htext)
            continue
        target = re.match(r"^[Tt]arget\s*:\s*(.+)$", stripped)
        if target and not model["target"]:
            model["target"] = target.group(1).strip()
            continue
        ptype = re.match(r"^[Pp]roject type\s*:\s*(.+)$", stripped)
        if ptype:
            model["project_type_raw"] = ptype.group(1).strip()
            model["project_type"] = normalize_project_type(ptype.group(1))
            continue
        bullet = re.match(r"^[-*]\s+(.+)$", stripped) or re.match(r"^\d+[.)]\s+(.+)$", stripped)
        # Bullets under Angle prioritas are class details, not class
        # names — class names come only from "### Kelas N — <name>".
        if bullet and current and current in model and isinstance(model[current], list) \
                and current != "priority_classes":
            model[current].append(bullet.group(1).strip())
    return model


def load_priority_classes(path: Path = CLASSES_FILE) -> dict:
    """Candidate classes per project type (priority-classes.json)."""
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _match_candidate(name: str, candidates: list[dict]) -> dict | None:
    low = name.lower()
    for c in candidates:
        if any(k.lower() in low for k in c.get("match", [])):
            return c
    return None


def lenses_for_class_names(class_names: list[str], project_type: str,
                           classes_data: dict) -> tuple[list[str], list[str]]:
    """Resolve class names -> (matched candidate names, lens ids, deduped)."""
    types = (classes_data or {}).get("types", {})
    cands = types.get(project_type, {}).get("candidates", [])
    matched: list[str] = []
    lenses: list[str] = []
    for name in class_names:
        cand = _match_candidate(name, cands)
        if cand is None:  # fall back to any type's list
            for t in types.values():
                cand = _match_candidate(name, t.get("candidates", []))
                if cand:
                    break
        if cand is None:
            continue
        matched.append(cand["name"])
        for lid in cand.get("lenses", []):
            if lid not in lenses:
                lenses.append(lid)
    return matched, lenses


def lenses_for_class_ids(ids: list[str], project_type: str,
                         classes_data: dict) -> tuple[list[str], list[str]]:
    types = (classes_data or {}).get("types", {})
    cands = types.get(project_type, {}).get("candidates", [])
    matched: list[str] = []
    lenses: list[str] = []
    for cid in ids:
        cand = next((c for c in cands if c["id"] == cid), None)
        if cand is None:
            continue
        matched.append(cand["name"])
        for lid in cand.get("lenses", []):
            if lid not in lenses:
                lenses.append(lid)
    return matched, lenses


def scope_note(model: dict) -> str:
    parts = []
    if model["out_of_scope"]:
        parts.append("Out of scope (never touch): " + "; ".join(model["out_of_scope"][:6]) + ".")
    if model["scope"]:
        parts.append("In scope: " + "; ".join(model["scope"][:6]) + ".")
    if not parts:
        parts.append("Manual testing only; no automated scanning.")
    return " ".join(parts)


# ---------------------------------------------------------------- dedup
def _normalize(text: str) -> str:
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def prompt_hash(text: str) -> str:
    return hashlib.sha1(_normalize(text).encode("utf-8")).hexdigest()[:12]


# ---------------------------------------------------------------- LLM client
class LLMClient:
    """Minimal OpenAI-compatible chat client (stdlib only)."""

    def __init__(self, provider: str, api_key: str, base_url: str, model: str,
                 max_calls: int = 40):
        self.provider = provider
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.max_calls = max_calls
        self.calls = 0
        self.tokens_in = 0
        self.tokens_out = 0

    def chat(self, messages: list[dict], temperature: float = 0.7,
             max_tokens: int = 4000) -> str:
        if self.calls >= self.max_calls:
            raise RuntimeError(f"API call budget exhausted (max {self.max_calls})")
        url = f"{self.base_url}/chat/completions"
        body = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        self.calls += 1
        try:
            with urllib.request.urlopen(req, timeout=180) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:500]
            raise RuntimeError(f"{self.provider} API HTTP {e.code}: {detail}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"{self.provider} API unreachable: {e}") from e
        usage = data.get("usage") or {}
        self.tokens_in += int(usage.get("prompt_tokens") or 0)
        self.tokens_out += int(usage.get("completion_tokens") or 0)
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as e:
            raise RuntimeError(f"{self.provider} API unexpected response: {str(data)[:300]}") from e


def build_client(provider: str, api_key: str | None, base_url: str | None,
                 model_id: str | None, max_calls: int) -> LLMClient:
    preset = PRESETS.get(provider)
    if preset is None:
        sys.exit(f"unknown provider '{provider}' (use: {', '.join(PRESETS)})")
    key = api_key or os.environ.get(preset["key_env"], "")
    if not key:
        sys.exit(f"no API key: set {preset['key_env']} or pass --api-key "
                 f"(key is never printed or stored)")
    env_model = os.environ.get(f"{provider.upper()}_MODEL", "")
    env_base = os.environ.get(f"{provider.upper()}_BASE_URL", "")
    return LLMClient(
        provider=provider,
        api_key=key,
        base_url=base_url or env_base or preset["base_url"],
        model=model_id or env_model or preset["model"],
        max_calls=max_calls,
    )


# ---------------------------------------------------------------- variant generation
def _extract_json_array(text: str) -> list:
    """Pull a JSON array out of LLM output (raw, fenced, or embedded)."""
    candidates = [text]
    fenced = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", text, re.DOTALL)
    if fenced:
        candidates.append(fenced.group(1))
    bracket = re.search(r"(\[.*\])", text, re.DOTALL)
    if bracket:
        candidates.append(bracket.group(1))
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, list):
            return parsed
    raise ValueError("no JSON array found in model output")


ROLE_PREFIX = (
    "You are a senior red team operator and professional cyber security "
    "researcher conducting authorized bug bounty research on an in-scope "
    "target. Think like an attacker, verify like an auditor: every claim "
    "needs executed proof. "
)


def with_role(prompt: str) -> str:
    """Guarantee every generated prompt carries the red-team role."""
    text = (prompt or "").strip()
    if text.lower().startswith("you are a senior red team"):
        return text
    return ROLE_PREFIX + text


def template_variants(lens: dict, model: dict, target: str, count: int,
                      start_offset: int = 0) -> list[dict]:
    """Deterministic variants: adapted lens x surface x use case x start.

    The lens text and the attacker starting positions adapt to the
    project's type (web2 / web3-contract / wallet), and each variant
    names the use case it targets, so a dynamic project gets prompts
    that fit its actual flows instead of one generic sentence.
    """
    surfaces = model["surfaces"] or ["the whole application"]
    use_cases = model.get("use_cases") or [""]
    starts = starts_for(model.get("project_type", "web2"))
    lens_text = adapted_lens(lens, model.get("project_type", "web2"))
    note = scope_note(model)
    variants = []
    i = 0
    while len(variants) < count:
        surface = surfaces[(start_offset + i) % len(surfaces)]
        use_case = use_cases[(start_offset + i) % len(use_cases)]
        start = starts[(start_offset + i) % len(starts)]
        uc_text = f"Use case: {use_case}. " if use_case else ""
        prompt = with_role(
            f"[{lens['id']} - {lens['name']}] On {surface}: {uc_text}{lens_text} "
            f"Attacker starts as {start}. Narrow goal: find ONE concrete place on "
            f"this surface where this holds, name the exact operation or endpoint "
            f"and the check that should exist. Scope: {target} only. {note} "
            f"Stop and report after the first concrete candidate with evidence, "
            f"or after exhausting the surface."
        )
        variants.append({"surface": surface, "use_case": use_case,
                         "start": start, "prompt": prompt})
        i += 1
        if i > count * len(surfaces) * len(use_cases) * len(starts) + 10:
            break
    return variants[:count]


MUTATOR_SYSTEM = (
    "You are a prompt mutator for authorized vulnerability research "
    "(bug bounty programs, in-scope targets only). You rewrite a base hunting "
    "lens into distinct, concrete, narrow research prompts grounded in the "
    "given threat model. Every prompt you generate must start with this "
    "role: 'You are a senior red team operator and professional cyber "
    "security researcher conducting authorized bug bounty research on an "
    "in-scope target. Think like an attacker, verify like an auditor: "
    "every claim needs executed proof.' Never suggest out-of-scope actions. "
    "Return ONLY a JSON array, no other text."
)


def llm_variants(client: LLMClient, lens: dict, model: dict, target: str,
                 count: int) -> list[dict]:
    """Ask the cheap model to mutate one lens against the threat model."""
    ptype = model.get("project_type", "web2")
    lens_text = adapted_lens(lens, ptype)
    use_cases = model.get("use_cases") or []
    uc_block = ("Use cases:\n" + "\n".join(f"- {u}" for u in use_cases)
                if use_cases else "Use cases: (not listed in threat model)")
    user_msg = (
        f"Target: {target}\n"
        f"Project type: {ptype}\n"
        f"{uc_block}\n\n"
        f"Base lens ({lens['id']} - {lens['name']}): {lens_text}\n"
        f"What this lens hunts: {lens.get('hunts', '')}\n\n"
        f"Threat model (excerpt):\n{model['raw']}\n\n"
        f"Generate exactly {count} distinct mutated variants of this lens. "
        f"Each variant must:\n"
        f"- name ONE concrete surface, asset, or flow from the threat model "
        f"(different surface per variant)\n"
        f"- name the use case it targets (one of the use cases above)\n"
        f"- fit the project type ({ptype}): use its vocabulary and attacker "
        f"positions, not generic web wording\n"
        f"- state a narrow, testable goal (one place, one operation)\n"
        f"- state the attacker starting position\n"
        f"- start with the red-team role: 'You are a senior red team "
        f"operator and professional cyber security researcher conducting "
        f"authorized bug bounty research on an in-scope target. Think like "
        f"an attacker, verify like an auditor: every claim needs executed "
        f"proof.'\n"
        f"- stay inside the stated scope; never suggest out-of-scope actions\n"
        f"- be written as a direct instruction to a research agent\n\n"
        f"Return ONLY a JSON array of objects with keys "
        f'"surface", "use_case", "start", "prompt". No other text.'
    )
    content = client.chat(
        [{"role": "system", "content": MUTATOR_SYSTEM},
         {"role": "user", "content": user_msg}],
        temperature=0.8,
    )
    try:
        parsed = _extract_json_array(content)
    except ValueError:
        # One retry with a stricter reminder, then fail loud.
        content = client.chat(
            [{"role": "system", "content": MUTATOR_SYSTEM},
             {"role": "user", "content": user_msg + "\n\nReturn ONLY the JSON array."}],
            temperature=0.5,
        )
        parsed = _extract_json_array(content)
    variants = []
    for item in parsed:
        if not isinstance(item, dict) or not item.get("prompt"):
            continue
        variants.append({
            "surface": str(item.get("surface") or ""),
            "use_case": str(item.get("use_case") or ""),
            "start": str(item.get("start") or ""),
            "prompt": with_role(str(item["prompt"])),
        })
    return variants[:count]


def llm_followups(client: LLMClient, lead: str, lens: dict, model: dict,
                  target: str, count: int) -> list[dict]:
    """Mutate follow-up prompts from one ingested signal/lead."""
    ptype = model.get("project_type", "web2")
    lens_text = adapted_lens(lens, ptype)
    user_msg = (
        f"Target: {target}\n"
        f"Project type: {ptype}\n\n"
        f"Signal from a previous research round (unconfirmed lead, needs proof):\n"
        f"{lead}\n\n"
        f"Lens to apply ({lens['id']} - {lens['name']}): {lens_text}\n\n"
        f"Threat model (excerpt):\n{model['raw']}\n\n"
        f"Generate exactly {count} distinct follow-up research prompts that dig "
        f"deeper into this signal using the lens above. Each must start with "
        f"the red-team role: 'You are a senior red team operator and "
        f"professional cyber security researcher conducting authorized bug "
        f"bounty research on an in-scope target. Think like an attacker, "
        f"verify like an auditor: every claim needs executed proof.' Each must name one "
        f"concrete surface/operation, the use case it targets, one narrow goal, "
        f"and the attacker starting position, using the project type's ({ptype}) "
        f"vocabulary. Stay in scope; never suggest out-of-scope actions.\n\n"
        f"Return ONLY a JSON array of objects with keys "
        f'"surface", "use_case", "start", "prompt". No other text.'
    )
    content = client.chat(
        [{"role": "system", "content": MUTATOR_SYSTEM},
         {"role": "user", "content": user_msg}],
        temperature=0.8,
    )
    parsed = _extract_json_array(content)
    variants = []
    for item in parsed:
        if not isinstance(item, dict) or not item.get("prompt"):
            continue
        variants.append({
            "surface": str(item.get("surface") or ""),
            "use_case": str(item.get("use_case") or ""),
            "start": str(item.get("start") or ""),
            "prompt": with_role(str(item["prompt"])),
        })
    return variants[:count]


# ---------------------------------------------------------------- run manifest
def new_run_dir(out: str | None, target: str) -> Path:
    if out:
        return Path(out)
    slug = re.sub(r"[^a-z0-9]+", "-", target.lower()).strip("-") or "target"
    stamp = datetime.now().strftime("%Y%m%d")
    return BASE_DIR / "runs" / f"{slug}-{stamp}"


def load_manifest(run_dir: Path) -> dict:
    path = run_dir / "run.json"
    if not path.exists():
        sys.exit(f"no run manifest in {run_dir} (run 'mutate' first)")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_manifest(run_dir: Path, manifest: dict) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    with open(run_dir / "run.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)


def add_prompts(manifest: dict, variants: list[dict], round_no: int,
                source: str, lens_id: str, parent: str | None = None) -> int:
    """Append variants with dedup; returns number of new prompts added."""
    seen = {p["hash"] for p in manifest["prompts"]}
    counter = manifest.get("counter", 0)
    added = 0
    for v in variants:
        h = prompt_hash(v["prompt"])
        if h in seen:
            continue
        seen.add(h)
        counter += 1
        manifest["prompts"].append({
            "id": f"P-{counter:04d}",
            "hash": h,
            "round": round_no,
            "lens": lens_id,
            "surface": v.get("surface", ""),
            "use_case": v.get("use_case", ""),
            "start": v.get("start", ""),
            "source": source,
            "parent": parent,
            "status": "new",
            "prompt": v["prompt"],
        })
        added += 1
    manifest["counter"] = counter
    return added


# ---------------------------------------------------------------- commands
def cmd_mutate(args) -> int:
    lenses = load_lenses()
    tm_path = Path(args.threat_model)
    if not tm_path.exists():
        sys.exit(f"threat model not found: {tm_path}")
    model = parse_threat_model(tm_path.read_text(encoding="utf-8"))
    target = args.target or model["target"] or tm_path.stem
    # --- priority classes (dynamic per engagement) ---
    # Precedence: explicit --lenses > explicit --classes >
    # Angle prioritas in the threat model (top 3) > all 13 lenses.
    classes_data = load_priority_classes()
    ptype = model.get("project_type", "web2")
    chosen_classes: list[str] = []
    class_lenses: list[str] = []
    if args.lenses:
        wanted = {x.strip() for x in args.lenses.split(",")}
        lenses = [l for l in lenses if l["id"] in wanted]
        if not lenses:
            sys.exit(f"no lenses match: {args.lenses}")
    elif getattr(args, "classes", None):
        ids = [x.strip() for x in args.classes.split(",") if x.strip()]
        chosen_classes, class_lenses = lenses_for_class_ids(ids, ptype, classes_data)
        if not class_lenses:
            sys.exit(f"no classes match: {args.classes} (type: {ptype})")
        print(f"[classes] --classes ({ptype}): {', '.join(chosen_classes)} "
              f"-> lenses {', '.join(class_lenses)}")
        lenses = [l for l in lenses if l["id"] in class_lenses]
    else:
        priority = model.get("priority_classes", [])
        if priority:
            if len(priority) > MAX_CLASSES_PER_RUN:
                print(f"[classes] {len(priority)} classes listed, "
                      f"taking top {MAX_CLASSES_PER_RUN}: "
                      f"{', '.join(priority[:MAX_CLASSES_PER_RUN])} "
                      f"(skipped: {', '.join(priority[MAX_CLASSES_PER_RUN:])})")
            chosen_classes = priority[:MAX_CLASSES_PER_RUN]
            matched, class_lenses = lenses_for_class_names(
                chosen_classes, ptype, classes_data)
            if class_lenses:
                print(f"[classes] top {len(chosen_classes)} ({ptype}): "
                      f"{', '.join(matched)} -> lenses {', '.join(class_lenses)}")
                lenses = [l for l in lenses if l["id"] in class_lenses]
            else:
                print("[classes] no lens mapping matched the listed "
                      "classes; using all 13 lenses")
        else:
            print("[classes] no Angle prioritas in threat model; "
                  "using all 13 lenses")
    run_dir = new_run_dir(args.out, target)

    manifest: dict
    if (run_dir / "run.json").exists() and not args.fresh:
        manifest = load_manifest(run_dir)
        round_no = max((r["round"] for r in manifest["rounds"]), default=0) + 1
    else:
        manifest = {
            "target": target,
            "project_type": model.get("project_type", "web2"),
            "threat_model": str(tm_path),
            "created": datetime.now().isoformat(timespec="seconds"),
            "rounds": [],
            "prompts": [],
            "signals_ingested": [],
            "api_calls": 0,
            "tokens_in": 0,
            "tokens_out": 0,
            "counter": 0,
        }
        round_no = 1

    client = None
    source = "template"
    if not args.no_api:
        client = build_client(args.provider, args.api_key, args.base_url,
                              args.model_id, args.max_api_calls)
        source = f"llm:{client.provider}/{client.model}"

    total_new = 0
    per_lens: dict[str, int] = {}
    for idx, lens in enumerate(lenses):
        try:
            if client:
                variants = llm_variants(client, lens, model, target,
                                        args.variants_per_lens)
            else:
                variants = template_variants(
                    lens, model, target, args.variants_per_lens,
                    start_offset=idx * args.variants_per_lens)
        except (RuntimeError, ValueError) as e:
            print(f"[{lens['id']}] FAILED: {e}", file=sys.stderr)
            if client:
                manifest["api_calls"] = client.calls
                manifest["tokens_in"] = client.tokens_in
                manifest["tokens_out"] = client.tokens_out
            save_manifest(run_dir, manifest)
            return 1
        added = add_prompts(manifest, variants, round_no, source, lens["id"])
        per_lens[lens["id"]] = added
        total_new += added
        print(f"[{lens['id']}] {added} new variant(s)")

    if client:
        manifest["api_calls"] = client.calls
        manifest["tokens_in"] = client.tokens_in
        manifest["tokens_out"] = client.tokens_out
    manifest["rounds"].append({
        "round": round_no, "source": source,
        "lenses": [l["id"] for l in lenses], "new": total_new,
        "priority_classes": chosen_classes,
        "project_type": ptype,
    })
    save_manifest(run_dir, manifest)
    variants_path = run_dir / f"variants-round-{round_no}.md"
    with open(variants_path, "w", encoding="utf-8") as f:
        f.write(f"# Variants — {target} — round {round_no} ({source})\n\n")
        for p in manifest["prompts"]:
            if p["round"] == round_no:
                f.write(f"## {p['id']} [{p['lens']}] {p['surface']}\n\n{p['prompt']}\n\n")
    print(f"\nRound {round_no}: {total_new} new variant(s), "
          f"{len(manifest['prompts'])} total in run.")
    if client:
        print(f"API: {client.calls} call(s), {client.tokens_in} in / "
              f"{client.tokens_out} out tokens.")
    print(f"Run dir: {run_dir}")
    print(f"Variants: {variants_path}")
    return 0


def cmd_swarm(args) -> int:
    run_dir = Path(args.run)
    manifest = load_manifest(run_dir)
    new = [p for p in manifest["prompts"] if p["status"] == "new"]
    if not new:
        print("No new prompts to assign (all assigned already). "
              "Run 'mutate' or 'ingest' for a new round first.")
        return 0
    agents = max(1, args.agents)
    per_agent = max(1, args.prompts_per_agent)
    swarm_dir = run_dir / "swarm"
    swarm_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "signals").mkdir(exist_ok=True)

    agent_files = []
    idx = 0
    agent_no = 0
    while idx < len(new) and agent_no < agents:
        agent_no += 1
        chunk = new[idx:idx + per_agent]
        idx += len(chunk)
        agent_file = swarm_dir / f"agent-{agent_no:02d}.md"
        lines = [
            f"# Agent task - {manifest['target']} / run {run_dir.name} / agent {agent_no:02d}",
            "",
            f"Target: {manifest['target']}",
            f"Threat model: {manifest['threat_model']}",
            "",
            "## Assigned prompts",
            "",
        ]
        for p in chunk:
            lines.append(f"### {p['id']} [{p['lens']}] {p['surface']}")
            if p.get("use_case"):
                lines.append(f"Use case: {p['use_case']}")
            lines.append("")
            lines.append(p["prompt"])
            lines.append("")
            p["status"] = "assigned"
        lines += [
            "## Rules (non-negotiable)",
            "",
            GATE_RULES,
            "",
            "## Output",
            "",
            f"Write your result to `signals/agent-{agent_no:02d}.md` with:",
            "- `## Finding` (or `No finding`) with evidence, or",
            "- `Lead: ...` lines for anything unconfirmed but worth a follow-up round.",
            "",
        ]
        agent_file.write_text("\n".join(lines), encoding="utf-8")
        agent_files.append(str(agent_file))
    save_manifest(run_dir, manifest)
    print(f"{len(agent_files)} agent file(s) in {swarm_dir} "
          f"({len(new)} prompt(s) assigned, {len(manifest['prompts']) - len(new)} already assigned before).")
    for f in agent_files:
        print(f"  {f}")
    print("Hand one file per agent (paste to a Hermes instance).")
    return 0


LEAD_RE = re.compile(r"^\s*(Lead|Follow-up|Followup|Signal)\s*:\s*(.+)$", re.IGNORECASE)
HEADING_RE = re.compile(r"^#{1,3}\s+(Finding|Lead|Signal|Follow-up)\b", re.IGNORECASE)


def extract_leads(signals_dir: Path) -> list[dict]:
    leads = []
    if not signals_dir.exists():
        return leads
    for path in sorted(signals_dir.glob("*.md")):
        current_heading = ""
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if HEADING_RE.match(line):
                current_heading = line.strip("# ").strip()
            m = LEAD_RE.match(line)
            if m:
                leads.append({"file": path.name, "lead": m.group(2).strip()})
            elif current_heading.lower().startswith(("finding", "lead", "signal")) \
                    and line.strip().startswith("- ") and len(line.strip()) > 4:
                leads.append({"file": path.name, "lead": line.strip()[2:].strip()})
    seen = set()
    unique = []
    for lead in leads:
        h = prompt_hash(lead["lead"])
        if h not in seen:
            seen.add(h)
            unique.append(lead)
    return unique


def cmd_ingest(args) -> int:
    run_dir = Path(args.run)
    manifest = load_manifest(run_dir)
    tm_path = Path(manifest["threat_model"])
    model = parse_threat_model(tm_path.read_text(encoding="utf-8")) \
        if tm_path.exists() else {"surfaces": [], "scope": [], "out_of_scope": [], "raw": ""}
    target = manifest["target"]
    signals_dir = Path(args.signals)
    leads = extract_leads(signals_dir)
    if not leads:
        print(f"No leads found in {signals_dir} (expected 'Lead: ...' lines "
              f"or Finding/Lead sections in agent signal files).")
        return 0
    leads = leads[: args.max_leads]
    print(f"{len(leads)} lead(s) from {signals_dir}")

    lenses = load_lenses()
    round_no = max((r["round"] for r in manifest["rounds"]), default=0) + 1
    client = None
    source = "template"
    if not args.no_api:
        client = build_client(args.provider, args.api_key, args.base_url,
                              args.model_id, args.max_api_calls)
        source = f"llm:{client.provider}/{client.model}"

    total_new = 0
    for li, lead in enumerate(leads):
        parent = f"{lead['file']}:{prompt_hash(lead['lead'])}"
        if any(s.get("parent") == parent for s in manifest["signals_ingested"]):
            print(f"  skip (already ingested): {lead['lead'][:80]}")
            continue
        lens = lenses[li % len(lenses)]
        try:
            if client:
                variants = llm_followups(client, lead["lead"], lens, model,
                                         target, args.variants_per_lens)
            else:
                variants = template_variants(
                    {"id": lens["id"], "name": lens["name"],
                     "lens": f"Follow up on this signal: {lead['lead']}. "
                             f"{adapted_lens(lens, model.get('project_type', 'web2'))}"},
                    model, target, args.variants_per_lens, start_offset=li)
        except (RuntimeError, ValueError) as e:
            print(f"  FAILED on lead {li + 1}: {e}", file=sys.stderr)
            save_manifest(run_dir, manifest)
            return 1
        added = add_prompts(manifest, variants, round_no, source, lens["id"],
                            parent=parent)
        total_new += added
        manifest["signals_ingested"].append({"parent": parent, "lead": lead["lead"]})
        print(f"  lead {li + 1} [{lens['id']}]: {added} follow-up(s)")
    if client:
        manifest["api_calls"] = manifest.get("api_calls", 0) + client.calls
        manifest["tokens_in"] = manifest.get("tokens_in", 0) + client.tokens_in
        manifest["tokens_out"] = manifest.get("tokens_out", 0) + client.tokens_out
    manifest["rounds"].append({
        "round": round_no, "source": source + ":ingest",
        "leads": len(leads), "new": total_new,
    })
    save_manifest(run_dir, manifest)
    print(f"\nRound {round_no}: {total_new} new follow-up variant(s), "
          f"{len(manifest['prompts'])} total in run.")
    print(f"Next: swarm --run {run_dir} --agents N")
    return 0


def cmd_status(args) -> int:
    run_dir = Path(args.run)
    manifest = load_manifest(run_dir)
    prompts = manifest["prompts"]
    by_status: dict[str, int] = {}
    by_round: dict[int, int] = {}
    for p in prompts:
        by_status[p["status"]] = by_status.get(p["status"], 0) + 1
        by_round[p["round"]] = by_round.get(p["round"], 0) + 1
    print(f"Target: {manifest['target']}")
    print(f"Threat model: {manifest['threat_model']}")
    print(f"Rounds: {len(manifest['rounds'])}")
    for r in manifest["rounds"]:
        print(f"  round {r['round']}: {r.get('new', 0)} new ({r.get('source', '?')})")
    print(f"Prompts: {len(prompts)} total | " +
          " | ".join(f"{k}: {v}" for k, v in sorted(by_status.items())))
    print(f"Signals ingested: {len(manifest.get('signals_ingested', []))}")
    print(f"API: {manifest.get('api_calls', 0)} call(s), "
          f"{manifest.get('tokens_in', 0)} in / {manifest.get('tokens_out', 0)} out tokens")
    print(f"Run dir: {run_dir}")
    return 0


# ---------------------------------------------------------------- CLI
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mutator.py",
        description="Threat-model-driven prompt mutation for vuln research.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_llm_opts(p):
        p.add_argument("--provider", default="stepfun", choices=list(PRESETS),
                       help="cheap-model provider (default: stepfun)")
        p.add_argument("--api-key", default=None,
                       help="API key (prefer env var; never stored)")
        p.add_argument("--base-url", default=None)
        p.add_argument("--model-id", default=None)
        p.add_argument("--max-api-calls", type=int, default=40)
        p.add_argument("--no-api", action="store_true",
                       help="template-only mutation, no model calls")

    m = sub.add_parser("mutate", help="mutate lenses against a threat model")
    m.add_argument("--threat-model", required=True)
    m.add_argument("--target", default=None)
    m.add_argument("--out", default=None, help="run dir (default runs/<target>-<date>)")
    m.add_argument("--variants-per-lens", type=int, default=3)
    m.add_argument("--lenses", default=None, help="comma list, e.g. L01,L06,L07 (overrides classes)")
    m.add_argument("--classes", default=None,
                   help="comma list of class ids from priority-classes.json "
                        "for this project type, e.g. key-seed,signing "
                        "(overrides Angle prioritas in threat model)")
    m.add_argument("--fresh", action="store_true", help="start a new run even if run dir exists")
    add_llm_opts(m)
    m.set_defaults(func=cmd_mutate)

    s = sub.add_parser("swarm", help="split new prompts into per-agent task files")
    s.add_argument("--run", required=True)
    s.add_argument("--agents", type=int, default=8)
    s.add_argument("--prompts-per-agent", type=int, default=1)
    s.set_defaults(func=cmd_swarm)

    ing = sub.add_parser("ingest", help="leads from agent signals -> next-round variants")
    ing.add_argument("--run", required=True)
    ing.add_argument("--signals", required=True)
    ing.add_argument("--variants-per-lens", type=int, default=2)
    ing.add_argument("--max-leads", type=int, default=10)
    add_llm_opts(ing)
    ing.set_defaults(func=cmd_ingest)

    st = sub.add_parser("status", help="show run state")
    st.add_argument("--run", required=True)
    st.set_defaults(func=cmd_status)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
