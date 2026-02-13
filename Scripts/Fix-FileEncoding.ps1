<#
.SYNOPSIS
    Fix-FileEncoding.ps1
    Converts PowerShell scripts to UTF-8 with BOM

.DESCRIPTION
    Re-saves PowerShell files with UTF-8 encoding and BOM
    so PowerShell can properly parse Unicode characters.

.PARAMETER FilePath
    Path to the file to fix. If not specified, fixes all .ps1 files.

.EXAMPLE
    .\Fix-FileEncoding.ps1
    Fix all PowerShell files in current directory

.EXAMPLE
    .\Fix-FileEncoding.ps1 -FilePath "Grant-AdminConsent.ps1"
    Fix a specific file
#>

param(
    [string]$FilePath
)

function Repair-FileUTF8 {
    param([string]$Path)

    Write-Host "  Processing: $(Split-Path $Path -Leaf)" -ForegroundColor Cyan
    $content = Get-Content $Path -Raw -Encoding UTF8
    $utf8WithBom = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($Path, $content, $utf8WithBom)
    Write-Host "  [OK] Fixed" -ForegroundColor Green
}

Write-Host "`n=== PowerShell File Encoding Fixer ===" -ForegroundColor Yellow
Write-Host ""

if ($FilePath) {
    # Fix specific file
    $fullPath = Join-Path $PSScriptRoot $FilePath
    if (Test-Path $fullPath) {
        Repair-FileUTF8 -Path $fullPath
    }
    else {
        Write-Host "Error: File not found: $FilePath" -ForegroundColor Red
        exit 1
    }
}
else {
    # Fix all PS files
    Write-Host "Fixing all .ps1 files in current directory..." -ForegroundColor Yellow
    Write-Host ""

    $files = Get-ChildItem -Path $PSScriptRoot -Filter "*.ps1" | Where-Object { $_.Name -ne "Fix-FileEncoding.ps1" }

    foreach ($file in $files) {
        try {
            Repair-FileUTF8 -Path $file.FullName
        }
        catch {
            Write-Host "  [FAILED] $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "Done! Files have been re-saved with UTF-8 BOM encoding" -ForegroundColor Green
Write-Host ""
