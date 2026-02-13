$projectRoot = Split-Path $PSScriptRoot -Parent
$files = @(
    (Join-Path $projectRoot 'Start-EntraChecks.ps1')
)
foreach ($file in $files) {
    $errors = $null
    $tokens = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errors)
    $name = Split-Path $file -Leaf
    if ($errors.Count -gt 0) {
        foreach ($e in $errors) { Write-Output "$name : $($e.ToString())" }
    } else {
        Write-Output "$name : Syntax OK"
    }
}
