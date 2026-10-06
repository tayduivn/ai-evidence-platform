# Run Enterprise Java SDK compilation and test suite
$ErrorActionPreference = "Stop"

$jdkBin = "C:\Program Files\Eclipse Adoptium\jdk-17.0.19.10-hotspot\bin"
if (Test-Path $jdkBin) {
    $env:PATH = "$jdkBin;" + $env:PATH
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

$targetClasses = Join-Path $scriptDir "target\classes"
$targetTestClasses = Join-Path $scriptDir "target\test-classes"

if (Test-Path (Join-Path $scriptDir "target")) {
    Remove-Item -Recurse -Force (Join-Path $scriptDir "target")
}

New-Item -ItemType Directory -Force -Path $targetClasses | Out-Null
New-Item -ItemType Directory -Force -Path $targetTestClasses | Out-Null

Write-Host ">>> Compiling Enterprise Java SDK main sources..." -ForegroundColor Cyan
$mainSources = Get-ChildItem -Path (Join-Path $scriptDir "src\main\java") -Filter "*.java" -Recurse | ForEach-Object { $_.FullName }
& javac -d $targetClasses $mainSources
if ($LASTEXITCODE -ne 0) {
    Write-Error "Main compilation failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host ">>> Compiling Enterprise Java SDK test sources..." -ForegroundColor Cyan
$testSources = Get-ChildItem -Path (Join-Path $scriptDir "src\test\java") -Filter "*.java" -Recurse | ForEach-Object { $_.FullName }
& javac -cp $targetClasses -d $targetTestClasses $testSources
if ($LASTEXITCODE -ne 0) {
    Write-Error "Test compilation failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host ">>> Executing Enterprise Java SDK TestRunner..." -ForegroundColor Green
& java -ea -cp "$targetClasses;$targetTestClasses" com.aievidence.sdk.TestRunner
exit $LASTEXITCODE
