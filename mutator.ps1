param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
# Thin wrapper so the mutator runs the same way on Windows PowerShell.
# Requires Python 3.11+ on PATH. API keys come from the environment only:
#   $env:STEPFUN_API_KEY = "..."   (cheap model, default provider)
#   $env:DEEPSEEK_API_KEY = "..."  (alternative provider, use --provider deepseek)
# Tries `python` first, then the `py` launcher (some installs only register `py`).
$python = Get-Command python -ErrorAction SilentlyContinue
if ($python) { python mutator.py @Args; exit $LASTEXITCODE }
$py = Get-Command py -ErrorAction SilentlyContinue
if ($py) { py mutator.py @Args; exit $LASTEXITCODE }
Write-Error "Python not found. Install it (winget install Python.Python.3.12), then reopen PowerShell."
exit 1
