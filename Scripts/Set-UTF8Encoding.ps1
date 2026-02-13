<#
.SYNOPSIS
    Set-UTF8Encoding.ps1
    Fixes PowerShell console encoding for EntraChecks

.DESCRIPTION
    Sets PowerShell console to UTF-8 encoding to properly display
    Unicode box-drawing characters in EntraChecks interface.

.EXAMPLE
    .\Set-UTF8Encoding.ps1
    .\Start-EntraChecks.ps1
#>

# Set console encoding to UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding = [System.Text.Encoding]::UTF8

# Also set PowerShell's default encoding
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'

Write-Host "✓ Console encoding set to UTF-8" -ForegroundColor Green
Write-Host "  You can now run Start-EntraChecks.ps1" -ForegroundColor Cyan
Write-Host ""
