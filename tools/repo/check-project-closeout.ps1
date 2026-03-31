[CmdletBinding()]
param(
    [switch]$StagedOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Git {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $output = & git @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "git $($Arguments -join ' ') failed."
    }

    return @($output)
}

function Get-ChangedPaths {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$UseStagedOnly
    )

    if ($UseStagedOnly) {
        return @(Invoke-Git -Arguments @('diff', '--cached', '--name-only', '--diff-filter=ACMR'))
    }

    $tracked = @(Invoke-Git -Arguments @('diff', '--name-only', 'HEAD', '--diff-filter=ACMR'))
    $untracked = @(Invoke-Git -Arguments @('ls-files', '--others', '--exclude-standard'))
    return @($tracked + $untracked | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
}

function Get-MarkdownSection {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content,
        [Parameter(Mandatory = $true)]
        [string]$Heading
    )

    $escapedHeading = [regex]::Escape($Heading)
    $match = [regex]::Match(
        $Content,
        "(?ms)^## $escapedHeading\s*$\r?\n(?<body>.*?)(?=^## |\z)"
    )

    if (-not $match.Success) {
        return $null
    }

    return $match.Groups['body'].Value.Trim()
}

$repoRoot = @(Invoke-Git -Arguments @('rev-parse', '--show-toplevel'))[0]
if (-not $repoRoot) {
    throw 'Could not determine repo root.'
}

Set-Location $repoRoot

$changedPaths = @(Get-ChangedPaths -UseStagedOnly $StagedOnly.IsPresent)
$failures = New-Object System.Collections.Generic.List[string]

$requiredFiles = @(
    'AGENTS.md',
    'README.md',
    'ops/deploy-contract.v1.yaml',
    'tools/repo/check-project-closeout.ps1'
)

foreach ($requiredFile in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $repoRoot $requiredFile))) {
        $failures.Add("Required project-repo file missing: $requiredFile")
    }
}

$readmePath = Join-Path $repoRoot 'README.md'
$contractPath = Join-Path $repoRoot 'ops\deploy-contract.v1.yaml'

if (Test-Path -LiteralPath $readmePath) {
    $readmeText = Get-Content -LiteralPath $readmePath -Raw
    $requiredHeadings = @(
        'Charakter',
        'Aktueller Zustand',
        'Lokale Entwicklung',
        'Laufzeitverhalten'
    )

    foreach ($heading in $requiredHeadings) {
        if (-not ([regex]::IsMatch($readmeText, "(?m)^## $([regex]::Escape($heading))\s*$"))) {
            $failures.Add("README.md is missing required heading: ## $heading")
        }
    }

    if (-not (
            [regex]::IsMatch($readmeText, '(?m)^## Proof-Status\s*$') -or
            [regex]::IsMatch($readmeText, '(?m)^## Reale Evidence\s*$')
        )) {
        $failures.Add('README.md must contain either `## Proof-Status` or `## Reale Evidence`.')
    }

    $currentStateSection = Get-MarkdownSection -Content $readmeText -Heading 'Aktueller Zustand'
    if ($null -ne $currentStateSection -and $currentStateSection -match '(?i)\b(geplant\w*|spaeter\w*|wird|soll\w*|planned|later|will)\b') {
        $failures.Add('`## Aktueller Zustand` must describe the current verified state, not future plans.')
    }
}

if (Test-Path -LiteralPath $contractPath) {
    $contractText = Get-Content -LiteralPath $contractPath -Raw

    if (-not [regex]::IsMatch($contractText, '(?m)^\s*notes:\s*$')) {
        $failures.Add('`ops/deploy-contract.v1.yaml` must contain a `notes:` section.')
    }

    if ($contractText -notmatch 'Current steady state') {
        $failures.Add('`ops/deploy-contract.v1.yaml` notes must include a `Current steady state ...` line.')
    }
}

if ($changedPaths -contains 'ops/deploy-contract.v1.yaml' -and -not ($changedPaths -contains 'README.md')) {
    $failures.Add('Changes to `ops/deploy-contract.v1.yaml` require a matching README.md update in the same block.')
}

Write-Host 'Project repo closeout check'
Write-Host "Root: $repoRoot"

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'Failures:'
    foreach ($failure in $failures) {
        Write-Host "- $failure"
    }

    exit 1
}

Write-Host 'Project repo closeout clean.'
