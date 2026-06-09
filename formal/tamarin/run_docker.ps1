param(
    [string]$Image = "hybrid-wg-tamarin:1.12.0",
    [string]$Model = "formal/tamarin/hybrid_wireguard_v23.spthy",
    [int]$DerivCheckTimeout = 60,
    [switch]$NoBuild
)

$ErrorActionPreference = "Stop"

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptRoot "..\..")
$ResultsDir = Join-Path $ScriptRoot "results"
$ProofOutput = Join-Path $ResultsDir "tamarin-proof.txt"
$VersionOutput = Join-Path $ResultsDir "tamarin-version.txt"

New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null

function Invoke-DockerCaptured {
    param(
        [string[]]$ArgumentList,
        [string]$OutputPath
    )

    $stdoutPath = "$OutputPath.stdout.tmp"
    $stderrPath = "$OutputPath.stderr.tmp"

    Remove-Item -Force -ErrorAction SilentlyContinue $stdoutPath, $stderrPath

    $process = Start-Process `
        -FilePath "docker" `
        -ArgumentList $ArgumentList `
        -NoNewWindow `
        -Wait `
        -PassThru `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath

    $combined = @()
    if (Test-Path $stdoutPath) {
        $combined += Get-Content $stdoutPath
    }
    if (Test-Path $stderrPath) {
        $combined += Get-Content $stderrPath
    }

    Set-Content -Path $OutputPath -Value $combined
    foreach ($line in $combined) {
        Write-Host $line
    }

    Remove-Item -Force -ErrorAction SilentlyContinue $stdoutPath, $stderrPath

    return $process.ExitCode
}

if (-not $NoBuild) {
    docker build `
        --build-arg TAMARIN_VERSION=1.12.0 `
        -t $Image `
        $ScriptRoot

    if ($LASTEXITCODE -ne 0) {
        throw "Docker build failed for image '$Image'."
    }
}

$Mount = "$($RepoRoot.Path):/workspace"

$versionExit = Invoke-DockerCaptured `
    -ArgumentList @("run", "--rm", "-v", $Mount, "-w", "/workspace", $Image, "tamarin-prover", "--version") `
    -OutputPath $VersionOutput

if ($versionExit -ne 0) {
    throw "Failed to query tamarin-prover version from Docker image '$Image'."
}

$proofExit = Invoke-DockerCaptured `
    -ArgumentList @(
        "run", "--rm",
        "-v", $Mount,
        "-w", "/workspace",
        $Image,
        "tamarin-prover",
        "--derivcheck-timeout=$DerivCheckTimeout",
        "--prove",
        $Model
    ) `
    -OutputPath $ProofOutput

if ($proofExit -ne 0) {
    throw "Tamarin proof failed. See $ProofOutput for details."
}

Write-Host "Tamarin proof output written to $ProofOutput"
