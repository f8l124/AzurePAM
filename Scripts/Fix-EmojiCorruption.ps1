# Fix Emoji Corruption in HTML and Remediation Modules
Write-Host "Fixing emoji corruption..." -ForegroundColor Cyan

$fixes = @{
    'EntraChecks-HTMLReporting.psm1' = @(
        @{ Old = [char]0xF0 + [char]0x9F + [char]0x93 + [char]0x9D; New = [char]::ConvertFromUtf32(0x1F4DD) } # 📝
        @{ Old = [char]0xF0 + [char]0x9F + [char]0x92 + [char]0xBB; New = [char]::ConvertFromUtf32(0x1F4BB) } # 💻
        @{ Old = [char]0xE2 + [char]0x96 + [char]0xBC; New = [char]::ConvertFromUtf32(0x25BC) } # ▼
        @{ Old = [char]0xE2 + [char]0x96 + [char]0xB2; New = [char]::ConvertFromUtf32(0x25B2) } # ▲
        @{ Old = '>🟠' + [char]0xF0 + [char]0x9F + [char]0x9F + [char]0xA0 + ' High'; New = '>🟠 High' } # Remove duplicate orange
        @{ Old = '>🟡' + [char]0xF0 + [char]0x9F + [char]0x9F + [char]0xA1 + ' Medium'; New = '>🟡 Medium' } # Remove duplicate yellow
        @{ Old = '>🟢' + [char]0xF0 + [char]0x9F + [char]0x9F + [char]0xA2 + ' Low'; New = '>🟢 Low' } # Remove duplicate green
    )
    'EntraChecks-RemediationGuidance.psm1' = @(
        @{ Old = '- ' + [char]0xE2 + [char]0x9C + [char]0x85 + ' Positive'; New = '- ✅ Positive' } # ✅
        @{ Old = '- ' + [char]0xE2 + [char]0x9A + [char]0xA0 + [char]0xEF + [char]0xB8 + [char]0x8F + ' Considerations'; New = '- ⚠️ Considerations' } # ⚠️
    )
}

foreach ($file in $fixes.Keys) {
    $filePath = Join-Path '.\Modules' $file
    Write-Host "Processing $file..." -ForegroundColor Yellow

    if (-not (Test-Path $filePath)) {
        Write-Host "  [SKIP] File not found" -ForegroundColor Red
        continue
    }

    # Read file with UTF-8 encoding
    $content = Get-Content $filePath -Raw -Encoding UTF8
    $changesCount = 0

    foreach ($fix in $fixes[$file]) {
        $newContent = $content -replace [regex]::Escape($fix.Old), $fix.New
        if ($newContent -ne $content) {
            $content = $newContent
            $changesCount++
        }
    }

    if ($changesCount -gt 0) {
        # Write file back with UTF-8 encoding
        $content | Set-Content $filePath -Encoding UTF8 -NoNewline
        Write-Host "  [OK] Applied $changesCount fix(es)" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] No changes needed" -ForegroundColor Cyan
    }
}

Write-Host ""
Write-Host "Emoji cleanup complete!" -ForegroundColor Green
