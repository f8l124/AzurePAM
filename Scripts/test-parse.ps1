$projectRoot = Split-Path $PSScriptRoot -Parent
$filesToCheck = @(
    (Join-Path $projectRoot 'Modules\EntraChecks-Compliance.psm1'),
    (Join-Path $PSScriptRoot 'New-ComprehensiveAssessmentReport.ps1')
)

foreach ($file in $filesToCheck) {
    $tokens = $null
    $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        $file,
        [ref]$tokens,
        [ref]$parseErrors
    )
    $shortName = Split-Path $file -Leaf
    if ($parseErrors.Count -eq 0) {
        Write-Output "[OK] $shortName - no parse errors"
    }
    else {
        Write-Output "[FAIL] $shortName - $($parseErrors.Count) parse error(s):"
        foreach ($e in $parseErrors) {
            Write-Output "  Line $($e.Extent.StartLineNumber): $($e.Message)"
        }
    }
}
