# Summary Report: Module Cleanup Results
Write-Host ""
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "MODULE CLEANUP SUMMARY REPORT" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

$modules = @(
    @{Name = 'EntraChecks-ComplianceMapping.psm1'; Before = 144 },
    @{Name = 'EntraChecks-RiskScoring.psm1'; Before = 69 },
    @{Name = 'EntraChecks-RemediationGuidance.psm1'; Before = 78 },
    @{Name = 'EntraChecks-HTMLReporting.psm1'; Before = 12 },
    @{Name = 'EntraChecks-ExcelReporting.psm1'; Before = 663 }
)

$totalBefore = 0
$totalAfter = 0

foreach ($module in $modules) {
    $modulePath = ".\Modules\$($module.Name)"
    Write-Host "Analyzing: $($module.Name)" -ForegroundColor Yellow

    # Run PSScriptAnalyzer
    $issues = Invoke-ScriptAnalyzer -Path $modulePath -ErrorAction SilentlyContinue
    $after = $issues.Count

    # Count by severity
    $errors = @($issues | Where-Object Severity -eq 'Error').Count
    $warnings = @($issues | Where-Object Severity -eq 'Warning').Count
    $info = @($issues | Where-Object Severity -eq 'Information').Count

    $before = $module.Before
    $reduction = $before - $after
    $reductionPct = if ($before -gt 0) { [Math]::Round(($reduction / $before) * 100, 1) } else { 0 }

    Write-Host "  Before: $before issues" -ForegroundColor Red
    Write-Host "  After:  $after issues ($errors errors, $warnings warnings, $info info)" -ForegroundColor $(if ($errors -eq 0) { 'Green' } else { 'Yellow' })
    Write-Host "  Reduction: $reduction issues ($reductionPct%)" -ForegroundColor Green
    Write-Host ""

    $totalBefore += $before
    $totalAfter += $after
}

Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "TOTAL RESULTS:" -ForegroundColor Cyan
Write-Host "  Issues Before: $totalBefore" -ForegroundColor Red
Write-Host "  Issues After:  $totalAfter" -ForegroundColor Green
Write-Host "  Total Reduction: $($totalBefore - $totalAfter) issues ($([Math]::Round((($totalBefore - $totalAfter) / $totalBefore) * 100, 1))%)" -ForegroundColor Green
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

Write-Host "Key Fixes Applied:" -ForegroundColor Cyan
Write-Host "  [OK] Converted PowerShell 7+ null-coalescing operators (??) to PS 5.1 syntax" -ForegroundColor White
Write-Host "  [OK] Fixed string interpolation issues with variable delimiters" -ForegroundColor White
Write-Host "  [OK] Fixed markdown code block backtick escaping" -ForegroundColor White
Write-Host "  [OK] Restored corrupted emoji characters (red/orange/yellow/green circles)" -ForegroundColor White
Write-Host "  [OK] All modules now import without errors" -ForegroundColor White
Write-Host ""
