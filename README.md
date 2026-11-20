# prompt-mutator

Mutator prompt buat riset vuln, sesuai pendekatan di tweet yang lu share:
model murah dipakai buat breadth (cari sinyal dari banyak sudut), model
frontier cuma buat konfirmasi/triage nanti. Tool ini cuma mutasi PROMPT,
bukan ngetes target dan bukan jalanin exploit.

Alurnya:

```
13 lensa dasar  +  threat model target
        |
   mutator (LLM murah / template)
        |
   varian prompt (dedup, ber-ID, per round)
        |
   swarm -> 1 file tugas per agent (buat Hermes)
        |
   agent nulis sinyal ke signals/
        |
   ingest -> varian follow-up round berikutnya
        |  (loop sampai path habis atau sinyal berhenti)
```

## File

- `mutator.py` — CLI utama, Python stdlib saja, tanpa pip install
- `lenses.json` — 13 lensa dari tweet (L01-L13)
- `priority-classes.json` — kandidat kelas per tipe project
  (web2 / web3-contract / wallet) + pemetaan tiap kelas ke lensa;
  single source of truth buat Angle prioritas dinamis
- `CHEAT-MAP-KELAS.md` — cheat map kelas bug per lane + turunannya
  (sub-bug, invariant, lensa, chain) buat nentuin Angle prioritas;
  baca ini dulu sebelum isi kelas di threat model
- `cheat-map-kelas.html` — versi presentasi dari cheat map yang sama,
  buat orang awam: lensa 1-13, 17 kelas per lane + lensa di tiap kartu,
  tabel teknik -> lensa, dan chaining. Buka di browser, tidak perlu server
- `threat-models/TEMPLATE.md` — template threat model per target
- `mutator.ps1` — wrapper buat Windows PowerShell
- `runs/` — hasil tiap run (dibuat otomatis)

## Setup

Python 3.11+ saja. Key API lewat environment variable, tidak pernah
disimpan di file:

```powershell
# Windows PowerShell (PC Hermes)
$env:STEPFUN_API_KEY = "isi-key-lu"
.\mutator.ps1 mutate --threat-model .\threat-models\TEMPLATE.md --target <NamaTarget> --variants-per-lens 3
```

```bash
# Linux / VM ini
export STEPFUN_API_KEY="isi-key-lu"
python3 mutator.py mutate --threat-model threat-models/TEMPLATE.md --target <NamaTarget> --variants-per-lens 3
```

Provider lain:

```bash
export DEEPSEEK_API_KEY="isi-key-lu"
python3 mutator.py mutate --provider deepseek --threat-model threat-models/TEMPLATE.md --target <NamaTarget>
```

Tanpa key sama sekali (mode template, deterministik, gratis):

```bash
python3 mutator.py mutate --no-api --threat-model threat-models/TEMPLATE.md --target <NamaTarget>
```

## Pakai

```bash
# 1. Mutasi round 1 (default: 3 varian per lensa = 39 varian)
python3 mutator.py mutate --threat-model threat-models/TEMPLATE.md --target <NamaTarget>

# cuma lensa tertentu
python3 mutator.py mutate --threat-model threat-models/TEMPLATE.md --target <NamaTarget> --lenses L01,L06,L07

# 2. Bagi jadi file tugas per agent (1 prompt per agent, 8 agent)
python3 mutator.py swarm --run runs/<target>-<tanggal> --agents 8

# 3. Kasih 1 file agent ke tiap Hermes, agent nulis hasil ke signals/agent-XX.md
#    format sinyal: baris "Lead: ..." buat hal yang belum terkonfirmasi
#    tapi layak dikejar, atau section "## Finding" buat temuan.

# 4. Sinyal balik jadi varian follow-up round 2
python3 mutator.py ingest --run runs/<target>-<tanggal> --signals runs/<target>-<tanggal>/signals

# 5. Ulangi swarm + ingest sampai path habis
python3 mutator.py swarm --run runs/<target>-<tanggal> --agents 8
python3 mutator.py status --run runs/<target>-<tanggal>
```

## Aturan main

- **Role red team di semua prompt.** Setiap varian yang dihasilkan
  mutator diawali role ini: "You are a senior red team operator and
  professional cyber security researcher conducting authorized bug
  bounty research on an in-scope target. Think like an attacker,
  verify like an auditor: every claim needs executed proof." Berlaku
  di mode template, mode LLM, dan follow-up `ingest`. Kalau LLM
  mengembalikan varian tanpa role, mutator menambahkannya sendiri
  sebelum disimpan.
- **Kelas prioritas dinamis, max 3 per run.** Tiap threat model wajib isi
  `## Angle prioritas` sebelum mutate: pilih max 3 kelas dari daftar
  kandidat tipe project itu di `priority-classes.json`, lalu urut ulang
  berdasarkan project ini (reward, scope, bukti yang sudah ada). Top 3
  web3 tidak sama dengan top 3 web2, dan top 3 satu web2 tidak sama
  dengan web2 lain. Mutator baca heading `### Kelas N — <nama>` di
  threat model dan auto-pilih lensa yang dipetakan ke kelas itu
  (field `lenses` per kelas di `priority-classes.json`); kalau threat
  model menulis lebih dari 3 kelas, yang dipakai cuma 3 teratas.
  Precedence: `--lenses` > `--classes` (id kelas, mis.
  `--classes key-seed,signing`) > Angle prioritas di threat model >
  semua 13 lensa kalau tidak ada kelas. Kelas ke-4+ bukan dihapus,
  cuma dicopot dari run ini dan masuk round berikutnya kalau signals
  top 3 kering.
- **Prompt menyesuaikan proyek.** Tiap threat model wajib isi
  `Project type:` (`web2`, `web3-contract`, atau `wallet`) dan section
  `## Use cases`. Mutator pakai itu buat milih kata-kata lensa
  (lihat field `adapt` di `lenses.json`) dan posisi awal attacker,
  dan tiap varian nyebutin use case yang ditarget. Proyek dinamis =
  threat model-nya yang diubah, prompt ikut berubah, tanpa utak-atik
  kode. Tipe baru: tambah entri `adapt` per lensa di `lenses.json`
  plus daftar starting position di `mutator.py` (dict `STARTS`).
- **Scope dari threat model.** Semua varian yang di-generate nyebutin
  out-of-scope dari file threat model. Kalau file-nya kosong atau salah,
  hasil mutasi ikut salah, jadi isi threat model dulu dengan benar.
- **Dedup.** Varian yang sama (teks mirip) cuma masuk sekali, lintas round.
- **Budget API.** Default maks 40 call per perintah (`--max-api-calls`).
  Setiap call dicatat token in/out di `run.json`.
- **Verdict tetap lewat gate.** File tugas agent sudah berisi aturan gate:
  CONFIRMED / FALSIFIED / INCONCLUSIVE, mekanisme terbukti bukan berarti
  vuln valid, bukti wajib ada. Sinyal dari mutator tetap sinyal, bukan
  temuan, sampai ada proof yang dieksekusi.
- **Key tidak pernah di-print atau disimpan.** Kalau API error 401/403,
  cek env var key-nya dulu.

## Yang tidak dilakukan tool ini

- Tidak menyentuh target, tidak kirim request, tidak jalanin exploit.
- Tidak milih target buat lu dan tidak submit apa pun.
- Tidak gantiin threat model: mutator cuma sebagus file threat model yang
  lu kasih.

## Lisensi

Dual-licensed under MIT OR Apache-2.0. See LICENSE-MIT and LICENSE-APACHE.
