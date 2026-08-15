<#
  deploy_attack_phase.ps1
  --------------------------------------------------------------------------
  Moves everything into the correct project folders automatically:
    - attack_phase_v2.zip   (attack phase files)
    - attack_charts.zip      (chart scripts + design image)
    - attack_driver.py       (updated version: jitter + session-pause)
  Then verifies that every expected file landed in the right place.

  Run (from inside the project root):
      powershell -ExecutionPolicy Bypass -File deploy_attack_phase.ps1
#>

$ErrorActionPreference = "Stop"

$Root      = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$Downloads = Join-Path $env:USERPROFILE "Downloads"
Write-Host "Project root : $Root"
Write-Host "Downloads    : $Downloads`n"

# --- Map: file name -> destination folder (relative to project root) ---
$Map = @{
  "attacker_personas.py"  = "src\attacks"
  "attack_payloads.py"    = "src\attacks"
  "attack_scenarios.py"   = "src\attacks"
  "attack_driver.py"      = "src\attacks"
  "run_attacks.sh"        = "src\attacks"
  "README_ATTACKS.md"     = "src\attacks"
  "__init__.py"           = "src\attacks"
  "merge_jsonl.py"        = "src\dataset"
  "diversity_audit.py"    = "tools"
  "plot_dedup.py"         = "tools"
  "plot_attack_design.py" = "tools"
  "plot_attacks.py"       = "tools"
  "attack_design.png"     = "data\merged"
  "docker-compose.yml"    = "."
  ".gitkeep"              = "data\raw_attack"
}

function Place-File($srcPath) {
  $name = Split-Path $srcPath -Leaf
  if (-not $Map.ContainsKey($name)) {
    Write-Host "[skip ] $name  (not in map - move it manually if needed)" -ForegroundColor Yellow
    return
  }
  $destDir = Join-Path $Root $Map[$name]
  New-Item -ItemType Directory -Force $destDir | Out-Null
  Copy-Item -Force $srcPath (Join-Path $destDir $name)
  Write-Host "[place] $name -> $($Map[$name])\" -ForegroundColor Green
}

function Deploy-Zip($zipName) {
  $zip = Join-Path $Downloads $zipName
  if (Test-Path $zip) {
    Write-Host "`n>>> extracting $zipName" -ForegroundColor Cyan
    $tmp = Join-Path $env:TEMP ("deploy_" + [guid]::NewGuid().ToString("N"))
    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    Get-ChildItem -Path $tmp -Recurse -File -Force | ForEach-Object { Place-File $_.FullName }
    Remove-Item -Recurse -Force $tmp
  } else {
    Write-Host "[warn ] $zipName not found in Downloads" -ForegroundColor Yellow
  }
}

# --- 1) extract the zips ---
Deploy-Zip "attack_phase_v2.zip"
Deploy-Zip "attack_charts.zip"

# --- 2) loose updated files in Downloads overwrite the zip copies ---
Write-Host "`n>>> loose updated files" -ForegroundColor Cyan
foreach ($loose in @("attack_driver.py", "plot_dedup.py", "plot_attack_design.py", "plot_attacks.py")) {
  $p = Join-Path $Downloads $loose
  if (Test-Path $p) { Place-File $p }
}

# --- 3) verification: is every expected file in its correct place? ---
Write-Host "`n============ VERIFICATION ============" -ForegroundColor Cyan
$expected = @(
  "src\attacks\attacker_personas.py",
  "src\attacks\attack_payloads.py",
  "src\attacks\attack_scenarios.py",
  "src\attacks\attack_driver.py",
  "src\attacks\run_attacks.sh",
  "src\attacks\README_ATTACKS.md",
  "src\attacks\__init__.py",
  "src\dataset\merge_jsonl.py",
  "tools\diversity_audit.py",
  "tools\plot_dedup.py",
  "tools\plot_attack_design.py",
  "tools\plot_attacks.py",
  "data\merged\attack_design.png",
  "docker-compose.yml",
  "data\raw_attack\.gitkeep"
)
$missing = 0
foreach ($rel in $expected) {
  $full = Join-Path $Root $rel
  if (Test-Path $full) {
    Write-Host "  [OK ] $rel" -ForegroundColor Green
  } else {
    Write-Host "  [MISSING] $rel" -ForegroundColor Red
    $missing++
  }
}

Write-Host "`n--------------------------------------"
if ($missing -eq 0) {
  Write-Host "All files are in the correct place. OK" -ForegroundColor Green
} else {
  Write-Host "$missing file(s) missing - see the [MISSING] lines above" -ForegroundColor Red
}
Write-Host "Final check:  python -m py_compile src\attacks\attack_driver.py"
