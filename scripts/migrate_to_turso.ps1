# One-time migration: Supabase (+ local backup) -> Turso.
# Rows are copied as-is (already ciphertext); safe to re-run (INSERT OR IGNORE).
# Requires env vars: Turso_Token, SUPABASE_URL, SUPABASE_KEY. Optional: Turso_URL.
$ErrorActionPreference = 'Stop'

$tursoUrl = if ($env:Turso_URL) { $env:Turso_URL } else { 'libsql://accounts-javenchen777.aws-ap-northeast-1.turso.io' }
$tursoUrl = $tursoUrl -replace '^libsql://', 'https://'
foreach ($n in 'Turso_Token', 'SUPABASE_URL', 'SUPABASE_KEY') {
    if (-not (Get-Item "env:$n" -ErrorAction SilentlyContinue)) { throw "Missing environment variable $n" }
}

function Invoke-Turso($statements) {
    $requests = @($statements | ForEach-Object {
        @{ type = 'execute'; stmt = @{ sql = $_.sql; args = @($_.args | ForEach-Object { @{ type = 'text'; value = [string]$_ } }) } }
    }) + @(@{ type = 'close' })
    $body = @{ requests = $requests } | ConvertTo-Json -Depth 10 -Compress
    $resp = Invoke-RestMethod -Method Post -Uri "$tursoUrl/v2/pipeline" `
        -Headers @{ Authorization = "Bearer $env:Turso_Token" } `
        -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body))
    foreach ($r in $resp.results) {
        if ($r.type -ne 'ok') { throw "Turso error: $($r.error.message)" }
    }
    $resp
}

$createSql = @"
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  product_name_url TEXT NOT NULL,
  username TEXT NOT NULL,
  password TEXT NOT NULL,
  additional TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
)
"@
Invoke-Turso @(@{ sql = $createSql; args = @() }) | Out-Null
Write-Host 'Table ensured.'

$rows = @{}

$base = $env:SUPABASE_URL.TrimEnd('/')
$headers = @{ apikey = $env:SUPABASE_KEY; Authorization = "Bearer $env:SUPABASE_KEY" }
$remote = Invoke-RestMethod -Uri "$base/rest/v1/accounts?select=*&order=created_at.desc" -Headers $headers
foreach ($r in @($remote)) { $rows[[string]$r.id] = $r }
Write-Host "Supabase rows: $(@($remote).Count)"

$backup = Join-Path $env:APPDATA 'AccountsKeeper\accounts_backup.json'
if (Test-Path $backup) {
    $local = Get-Content $backup -Raw -Encoding UTF8 | ConvertFrom-Json
    $added = 0
    foreach ($r in @($local)) {
        if (-not $rows.ContainsKey([string]$r.id)) { $rows[[string]$r.id] = $r; $added++ }
    }
    Write-Host "Local-backup-only rows: $added"
}

$stmts = @($rows.Values | ForEach-Object {
    @{
        sql  = 'INSERT OR IGNORE INTO accounts (id, product_name_url, username, password, additional, created_at) VALUES (?, ?, ?, ?, ?, ?)'
        args = @($_.id, $_.product_name_url, $_.username, $_.password, $_.additional, $_.created_at)
    }
})
if ($stmts.Count -gt 0) { Invoke-Turso $stmts | Out-Null }

$count = Invoke-Turso @(@{ sql = 'SELECT COUNT(*) FROM accounts'; args = @() })
Write-Host "Turso rows now: $($count.results[0].response.result.rows[0][0].value) (migrated candidates: $($rows.Count))"
