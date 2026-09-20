param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$SourceSha,

    [string]$Repo = 'E:\\Dockers\\MM-IBKR 1.16.26\\MM-IBKR',
    [string]$RuntimeRepo = 'https://github.com/XoticHaze/mm-ibkr-runtime.git',
    [string]$OutDir = 'E:\\Dockers\\MM-IBKR 1.16.26\\_patches\\inbox'
)

$ErrorActionPreference = 'Stop'
$SourceSha = $SourceSha.ToLowerInvariant()
if (-not (Test-Path -LiteralPath (Join-Path $Repo '.git'))) { throw "Private repo not found: $Repo" }
$resolved = (git -C $Repo rev-parse "$SourceSha^{commit}").Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $resolved -ne $SourceSha) { throw "Exact source SHA is not present in local repo: $SourceSha" }

$token = (gh auth token).Trim()
if (-not $token) { throw 'gh auth token returned no token' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$receipt = Join-Path $OutDir ("MM_IBKR_SOURCE_VAULT_{0}.json" -f $SourceSha.Substring(0,12))

$work = Join-Path $env:TEMP ("mmibkr-source-vault-" + [guid]::NewGuid().ToString('N'))
try {
    git clone --depth 1 $RuntimeRepo $work | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Failed to clone public runtime tooling' }

    docker run --rm `
      -e GH_TOKEN="$token" `
      -v "${Repo}:/private-mm:ro" `
      -v "${work}:/tool:ro" `
      -v "${OutDir}:/out" `
      -w /tool `
      python:3.11-slim `
      bash -lc "apt-get update -qq && apt-get install -y -qq --no-install-recommends git >/dev/null && pip install --disable-pip-version-check -q cryptography==46.0.1 && python scripts/mmibkr_source_vault_publish_v1.py --repo-root /private-mm --source-sha $SourceSha --source-ref $SourceSha --receipt /out/$([IO.Path]::GetFileName($receipt))"
    if ($LASTEXITCODE -ne 0) { throw 'Encrypted source-vault publication failed' }

    $node = Get-Content -Raw -LiteralPath $receipt | ConvertFrom-Json
    if (-not $node.ok -or $node.source_sha -ne $SourceSha) { throw 'Publication receipt identity mismatch' }
    if ($node.public_plaintext_included -ne $false -or $node.private_repository_token_used -ne $false) { throw 'Publication boundary violation' }
    Write-Host "SOURCE_VAULT_RECEIPT=$receipt"
    Write-Host "SOURCE_SHA=$($node.source_sha)"
    Write-Host "ARCHIVE_SHA256=$($node.archive_sha256)"
    Write-Host "ARCHIVE_BYTES=$($node.archive_bytes)"
    Write-Host "MANIFEST_SHA256=$($node.manifest_sha256)"
    Write-Host "PUBLIC_COMMIT=$($node.published_commit)"
} finally {
    Remove-Item Env:GH_TOKEN -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force -LiteralPath $work -ErrorAction SilentlyContinue
    $token = $null
}
