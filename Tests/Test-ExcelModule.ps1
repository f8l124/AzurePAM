# Test the cleaned Excel module
Write-Host "Testing cleaned Excel Reporting module..." -ForegroundColor Cyan
Write-Host ""

$modulePath = ".\Modules\EntraChecks-ExcelReporting.psm1"

# Test 1: Import module
Write-Host "Test 1: Importing module..." -ForegroundColor Yellow
try {
    Import-Module $modulePath -Force -ErrorAction Stop
    Write-Host "  [OK] Module imported successfully" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Failed to import: $_" -ForegroundColor Red
    exit 1
}

# Test 2: Check function availability
Write-Host "Test 2: Checking function availability..." -ForegroundColor Yellow
$requiredFunctions = @('New-EnhancedExcelReport')
$allFound = $true

foreach ($func in $requiredFunctions) {
    $exists = Get-Command $func -ErrorAction SilentlyContinue
    if ($exists) {
        Write-Host "  [OK] Function $func is available" -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] Function $func not found!" -ForegroundColor Red
        $allFound = $false
    }
}

# Test 3: Run PSScriptAnalyzer
Write-Host "Test 3: Running PSScriptAnalyzer..." -ForegroundColor Yellow
try {
    $issues = Invoke-ScriptAnalyzer -Path $modulePath -ErrorAction Stop
    $total = $issues.Count

    # Group by severity
    $errors = @($issues | Where-Object Severity -eq 'Error').Count
    $warnings = @($issues | Where-Object Severity -eq 'Warning').Count
    $info = @($issues | Where-Object Severity -eq 'Information').Count

    Write-Host "  Total Issues: $total" -ForegroundColor Cyan
    Write-Host "    Errors: $errors" -ForegroundColor $(if ($errors -gt 0) { 'Red' } else { 'Green' })
    Write-Host "    Warnings: $warnings" -ForegroundColor $(if ($warnings -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "    Information: $info" -ForegroundColor Cyan

    # Show most common issues
    if ($total -gt 0) {
        Write-Host ""
        Write-Host "  Top issue types:" -ForegroundColor Cyan
        $issues | Group-Object RuleName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
            Write-Host "    $($_.Name): $($_.Count)" -ForegroundColor White
        }
    }
} catch {
    Write-Host "  [ERROR] PSScriptAnalyzer failed: $_" -ForegroundColor Red
}

Write-Host ""
if ($allFound -and $errors -eq 0) {
    Write-Host "SUCCESS: Excel module is functional!" -ForegroundColor Green
} else {
    Write-Host "WARNING: Some issues remain" -ForegroundColor Yellow
}
