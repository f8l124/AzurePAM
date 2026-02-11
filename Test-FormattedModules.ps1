# Test that all formatted modules still work correctly

Write-Host "Testing formatted modules..." -ForegroundColor Cyan
Write-Host ""

$modules = @(
    'Modules\EntraChecks-ComplianceMapping.psm1',
    'Modules\EntraChecks-RiskScoring.psm1',
    'Modules\EntraChecks-RemediationGuidance.psm1',
    'Modules\EntraChecks-HTMLReporting.psm1',
    'Modules\EntraChecks-ExcelReporting.psm1'
)

$allSuccess = $true

foreach ($module in $modules) {
    $moduleName = Split-Path $module -Leaf
    Write-Host "Testing $moduleName..." -ForegroundColor Yellow

    try {
        # Import module
        Import-Module ".\$module" -Force -ErrorAction Stop
        Write-Host "  [OK] Imported successfully" -ForegroundColor Green

        # Test a function from each module
        $testFunction = switch ($moduleName) {
            'EntraChecks-ComplianceMapping.psm1' { 'Get-ComplianceMapping' }
            'EntraChecks-RiskScoring.psm1' { 'Get-RiskLevel' }
            'EntraChecks-RemediationGuidance.psm1' { 'Get-RemediationGuidance' }
            'EntraChecks-HTMLReporting.psm1' { 'New-EnhancedHTMLReport' }
            'EntraChecks-ExcelReporting.psm1' { 'New-EnhancedExcelReport' }
        }

        $functionExists = Get-Command $testFunction -ErrorAction SilentlyContinue
        if ($functionExists) {
            Write-Host "  [OK] Function $testFunction is available" -ForegroundColor Green
        } else {
            Write-Host "  [ERROR] Function $testFunction not found!" -ForegroundColor Red
            $allSuccess = $false
        }
    }
    catch {
        Write-Host "  [ERROR] Failed: $_" -ForegroundColor Red
        $allSuccess = $false
    }

    Write-Host ""
}

if ($allSuccess) {
    Write-Host "SUCCESS: All modules formatted and working correctly!" -ForegroundColor Green
} else {
    Write-Host "WARNING: Some modules have issues" -ForegroundColor Yellow
}
