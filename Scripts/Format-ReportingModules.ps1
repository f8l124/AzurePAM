# Format all new reporting modules with Invoke-Formatter

Write-Host "Auto-formatting new reporting modules..." -ForegroundColor Cyan
Write-Host ""

$modules = @(
    'Modules\EntraChecks-ComplianceMapping.psm1',
    'Modules\EntraChecks-RiskScoring.psm1',
    'Modules\EntraChecks-RemediationGuidance.psm1',
    'Modules\EntraChecks-HTMLReporting.psm1',
    'Modules\EntraChecks-ExcelReporting.psm1'
)

$settingsPath = '.\PSScriptAnalyzerSettings.psd1'

foreach ($module in $modules) {
    Write-Host "Formatting $module..." -ForegroundColor Yellow

    try {
        # Read current content
        $content = Get-Content $module -Raw

        # Format with PSScriptAnalyzer
        $formatted = Invoke-Formatter -ScriptDefinition $content -Settings $settingsPath

        # Save formatted content
        $formatted | Set-Content $module -Encoding UTF8 -NoNewline

        Write-Host "  [OK] Formatted successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "  [ERROR] Failed to format: $_" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Done! Re-running PSScriptAnalyzer to verify..." -ForegroundColor Cyan
Write-Host ""

# Verify formatting
foreach ($module in $modules) {
    $issues = Invoke-ScriptAnalyzer -Path $module -Settings $settingsPath
    $formatIssues = $issues | Where-Object {
        $_.RuleName -in @('PSAlignAssignmentStatement', 'PSUseConsistentIndentation', 'PSUseConsistentWhitespace')
    }

    $moduleName = Split-Path $module -Leaf
    if ($formatIssues.Count -eq 0) {
        Write-Host "[OK] $moduleName - No formatting issues" -ForegroundColor Green
    }
    else {
        Write-Host "[!] $moduleName - $($formatIssues.Count) formatting issues remain" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Formatting complete!" -ForegroundColor Green
