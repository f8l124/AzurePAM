# EntraChecks Enhanced HTML Reporting Module
# Generates comprehensive HTML reports with executive dashboard

<#
.SYNOPSIS
    Generates enhanced HTML reports for EntraChecks findings.

.DESCRIPTION
    Creates interactive HTML reports with:
    - Executive dashboard with risk summary
    - Compliance framework mapping
    - Risk scoring and prioritization
    - Actionable remediation guidance
    - Interactive filtering and search
    - Professional styling for IT leadership

.NOTES
    Author: EntraChecks Team
    Version: 1.0.0
#>

# Import dependent modules
$modulePath = Split-Path -Parent $PSCommandPath
Import-Module (Join-Path $modulePath "EntraChecks-ComplianceMapping.psm1") -Force
Import-Module (Join-Path $modulePath "EntraChecks-RiskScoring.psm1") -Force
Import-Module (Join-Path $modulePath "EntraChecks-RemediationGuidance.psm1") -Force

#region HTML Generation Functions

function New-EnhancedHTMLReport {
    <#
    .SYNOPSIS
        Generates an enhanced HTML report with executive dashboard.

    .DESCRIPTION
        Creates a comprehensive HTML report integrating risk scoring, compliance mapping,
        and remediation guidance with interactive features.

    .PARAMETER Findings
        Array of finding objects to include in the report

    .PARAMETER OutputPath
        Path where the HTML report will be saved

    .PARAMETER TenantInfo
        Tenant information object (TenantId, TenantName, etc.)

    .PARAMETER PreviousAssessment
        Optional previous assessment data for delta comparison

    .PARAMETER IncludeSections
        Sections to include: All, Executive, Detailed, Compliance, Remediation

    .EXAMPLE
        New-EnhancedHTMLReport -Findings $findings -OutputPath "report.html" -TenantInfo $tenantInfo
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Findings,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [object]$TenantInfo,

        [object]$PreviousAssessment,

        [string[]]$IncludeSections = @('All')
    )

    # Enhance findings with risk scoring, compliance mapping, and remediation
    $enhancedFindings = @()
    foreach ($finding in $Findings) {
        $enhanced = $finding |
            Add-RiskScoring |
            Add-ComplianceMapping |
            Add-RemediationGuidance
        $enhancedFindings += $enhanced
    }

    # Calculate summaries
    $riskSummary = Get-RiskSummary -Findings $enhancedFindings
    $complianceGap = Get-ComplianceGapReport -Findings $enhancedFindings -Framework 'All'
    $quickWins = Get-QuickWins -Findings $enhancedFindings
    $prioritized = Get-PrioritizedFindings -Findings $enhancedFindings

    # Generate HTML sections
    $htmlHead = Get-HTMLHead
    $htmlNav = Get-HTMLNavigation
    $htmlExecutive = Get-ExecutiveDashboard -RiskSummary $riskSummary -ComplianceGap $complianceGap -TenantInfo $TenantInfo
    $htmlQuickWins = Get-QuickWinsSection -QuickWins $quickWins
    $htmlPriority = Get-PrioritySection -PrioritizedFindings $prioritized
    $htmlCompliance = Get-ComplianceSection -Findings $enhancedFindings -ComplianceGap $complianceGap
    $htmlDetailed = Get-DetailedFindingsSection -Findings $enhancedFindings
    $htmlJavaScript = Get-HTMLJavaScript

    # Assemble complete HTML
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft Entra ID Security Assessment - $($TenantInfo.TenantName)</title>
    $htmlHead
</head>
<body>
    $htmlNav
    <div class="container">
        <header class="report-header">
            <h1>🔒 Microsoft Entra ID Security Assessment</h1>
            <div class="tenant-info">
                <p><strong>Tenant:</strong> $($TenantInfo.TenantName)</p>
                <p><strong>Tenant ID:</strong> $($TenantInfo.TenantId)</p>
                <p><strong>Report Generated:</strong> $(Get-Date -Format "MMMM dd, yyyy 'at' HH:mm:ss")</p>
                <p><strong>Total Findings:</strong> $($Findings.Count)</p>
            </div>
        </header>

        $htmlExecutive
        $htmlQuickWins
        $htmlPriority
        $htmlCompliance
        $htmlDetailed
    </div>
    $htmlJavaScript
</body>
</html>
"@

    # Write to file
    $html | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Verbose "Enhanced HTML report generated: $OutputPath"

    return $OutputPath
}

function Get-HTMLHead {
    return @'
<style>
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }

    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background-color: #f5f7fa;
        color: #333;
        line-height: 1.6;
    }

    .container {
        max-width: 1400px;
        margin: 0 auto;
        padding: 20px;
    }

    .report-header {
        background: linear-gradient(135deg, #0078d4 0%, #0053a6 100%);
        color: white;
        padding: 30px;
        border-radius: 8px;
        margin-bottom: 30px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }

    .report-header h1 {
        font-size: 2.5em;
        margin-bottom: 15px;
    }

    .tenant-info {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 10px;
        margin-top: 15px;
    }

    .tenant-info p {
        background: rgba(255, 255, 255, 0.2);
        padding: 10px;
        border-radius: 4px;
    }

    /* Navigation */
    .nav-bar {
        background: white;
        padding: 15px 20px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        position: sticky;
        top: 0;
        z-index: 1000;
        margin-bottom: 20px;
    }

    .nav-bar ul {
        list-style: none;
        display: flex;
        gap: 20px;
        flex-wrap: wrap;
    }

    .nav-bar a {
        color: #0078d4;
        text-decoration: none;
        font-weight: 500;
        padding: 8px 15px;
        border-radius: 4px;
        transition: background 0.3s;
    }

    .nav-bar a:hover {
        background: #f0f0f0;
    }

    /* Executive Dashboard */
    .executive-dashboard {
        background: white;
        padding: 30px;
        border-radius: 8px;
        margin-bottom: 30px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .dashboard-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 20px;
        margin-top: 20px;
    }

    .metric-card {
        background: linear-gradient(135deg, #f5f7fa 0%, #ffffff 100%);
        padding: 20px;
        border-radius: 8px;
        border-left: 4px solid #0078d4;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }

    .metric-card.critical {
        border-left-color: #d13438;
    }

    .metric-card.high {
        border-left-color: #ff8c00;
    }

    .metric-card.medium {
        border-left-color: #ffb900;
    }

    .metric-card.low {
        border-left-color: #107c10;
    }

    .metric-value {
        font-size: 2.5em;
        font-weight: bold;
        margin: 10px 0;
    }

    .metric-label {
        font-size: 0.9em;
        color: #666;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    /* Risk Level Badges */
    .risk-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 0.85em;
        font-weight: 600;
        text-transform: uppercase;
    }

    .risk-badge.critical {
        background: #d13438;
        color: white;
    }

    .risk-badge.high {
        background: #ff8c00;
        color: white;
    }

    .risk-badge.medium {
        background: #ffb900;
        color: #000;
    }

    .risk-badge.low {
        background: #107c10;
        color: white;
    }

    .risk-badge.info {
        background: #0078d4;
        color: white;
    }

    /* Sections */
    .section {
        background: white;
        padding: 30px;
        border-radius: 8px;
        margin-bottom: 30px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .section-title {
        font-size: 1.8em;
        margin-bottom: 20px;
        color: #0078d4;
        border-bottom: 2px solid #0078d4;
        padding-bottom: 10px;
    }

    /* Quick Wins */
    .quick-wins-grid {
        display: grid;
        gap: 15px;
        margin-top: 20px;
    }

    .quick-win-card {
        background: #fff4ce;
        padding: 20px;
        border-radius: 8px;
        border-left: 4px solid #ffb900;
    }

    .quick-win-card h3 {
        color: #333;
        margin-bottom: 10px;
    }

    .quick-win-meta {
        display: flex;
        gap: 20px;
        margin-top: 10px;
        flex-wrap: wrap;
    }

    .quick-win-meta span {
        background: white;
        padding: 5px 10px;
        border-radius: 4px;
        font-size: 0.9em;
    }

    /* Priority Table */
    .priority-table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 20px;
    }

    .priority-table th {
        background: #0078d4;
        color: white;
        padding: 12px;
        text-align: left;
        font-weight: 600;
    }

    .priority-table td {
        padding: 12px;
        border-bottom: 1px solid #e0e0e0;
    }

    .priority-table tr:hover {
        background: #f5f7fa;
    }

    .priority-score {
        font-size: 1.2em;
        font-weight: bold;
        color: #0078d4;
    }

    /* Compliance Grid */
    .compliance-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
        gap: 20px;
        margin-top: 20px;
    }

    .compliance-card {
        background: linear-gradient(135deg, #f5f7fa 0%, #ffffff 100%);
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }

    .compliance-card h3 {
        color: #0078d4;
        margin-bottom: 15px;
    }

    .compliance-stat {
        display: flex;
        justify-content: space-between;
        padding: 8px 0;
        border-bottom: 1px solid #e0e0e0;
    }

    /* Detailed Findings */
    .finding-card {
        background: white;
        border: 1px solid #e0e0e0;
        border-radius: 8px;
        margin-bottom: 20px;
        overflow: hidden;
    }

    .finding-header {
        padding: 20px;
        background: #f5f7fa;
        cursor: pointer;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .finding-header:hover {
        background: #e8eef5;
    }

    .finding-title {
        font-weight: 600;
        font-size: 1.1em;
    }

    .finding-body {
        padding: 20px;
        display: none;
    }

    .finding-body.active {
        display: block;
    }

    .finding-meta {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 15px;
        margin: 15px 0;
        padding: 15px;
        background: #f5f7fa;
        border-radius: 4px;
    }

    .remediation-steps {
        background: #e7f3ff;
        padding: 15px;
        border-radius: 4px;
        margin-top: 15px;
    }

    .remediation-steps h4 {
        color: #0078d4;
        margin-bottom: 10px;
    }

    .remediation-steps ol {
        margin-left: 20px;
    }

    .remediation-steps li {
        margin-bottom: 8px;
    }

    /* Search and Filters */
    .controls-bar {
        background: white;
        padding: 20px;
        border-radius: 8px;
        margin-bottom: 20px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .controls-bar input,
    .controls-bar select {
        padding: 10px;
        border: 1px solid #ddd;
        border-radius: 4px;
        font-size: 1em;
        margin-right: 10px;
    }

    .controls-bar input {
        width: 300px;
    }

    /* Print Styles */
    @media print {
        .nav-bar,
        .controls-bar,
        .expand-all-btn {
            display: none;
        }

        .finding-body {
            display: block !important;
        }

        body {
            background: white;
        }

        .section {
            box-shadow: none;
            page-break-inside: avoid;
        }
    }

    /* Responsive */
    @media (max-width: 768px) {
        .dashboard-grid,
        .compliance-grid {
            grid-template-columns: 1fr;
        }

        .report-header h1 {
            font-size: 1.8em;
        }

        .controls-bar input {
            width: 100%;
            margin-bottom: 10px;
        }
    }

    .code-block {
        background: #1e1e1e;
        color: #d4d4d4;
        padding: 15px;
        border-radius: 4px;
        overflow-x: auto;
        font-family: 'Consolas', 'Monaco', monospace;
        font-size: 0.9em;
        margin: 10px 0;
    }

    .expand-all-btn {
        background: #0078d4;
        color: white;
        border: none;
        padding: 10px 20px;
        border-radius: 4px;
        cursor: pointer;
        font-size: 1em;
        margin-bottom: 15px;
    }

    .expand-all-btn:hover {
        background: #0053a6;
    }
</style>
'@
}

function Get-HTMLNavigation {
    return @'
<nav class="nav-bar">
    <ul>
        <li><a href="#executive">Executive Summary</a></li>
        <li><a href="#quick-wins">Quick Wins</a></li>
        <li><a href="#priority">Priority Findings</a></li>
        <li><a href="#compliance">Compliance Mapping</a></li>
        <li><a href="#detailed">Detailed Findings</a></li>
    </ul>
</nav>
'@
}

function Get-ExecutiveDashboard {
    param(
        [Parameter(Mandatory)]
        [object]$RiskSummary,

        [Parameter(Mandatory)]
        [object]$ComplianceGap,

        [Parameter(Mandatory)]
        [object]$TenantInfo
    )

    return @"
<section class="executive-dashboard" id="executive">
    <h2 class="section-title">📊 Executive Summary</h2>

    <div class="dashboard-grid">
        <div class="metric-card critical">
            <div class="metric-label">Critical Risk</div>
            <div class="metric-value">$($RiskSummary.CriticalCount)</div>
            <div>$($RiskSummary.CriticalPercent)% of findings</div>
        </div>

        <div class="metric-card high">
            <div class="metric-label">High Risk</div>
            <div class="metric-value">$($RiskSummary.HighCount)</div>
            <div>$($RiskSummary.HighPercent)% of findings</div>
        </div>

        <div class="metric-card medium">
            <div class="metric-label">Medium Risk</div>
            <div class="metric-value">$($RiskSummary.MediumCount)</div>
            <div>$($RiskSummary.MediumPercent)% of findings</div>
        </div>

        <div class="metric-card low">
            <div class="metric-label">Quick Wins Available</div>
            <div class="metric-value">$($RiskSummary.QuickWinsCount)</div>
            <div>High impact, low effort</div>
        </div>
    </div>

    <div style="margin-top: 30px;">
        <h3>📈 Risk Analysis</h3>
        <p><strong>Average Risk Score:</strong> $($RiskSummary.AverageRiskScore) / 100</p>
        <p><strong>Highest Risk Score:</strong> $($RiskSummary.MaxRiskScore) / 100</p>
        <p><strong>Top Priority Items:</strong> $($RiskSummary.TopPriorityCount) findings require immediate attention</p>
    </div>

    <div style="margin-top: 30px;">
        <h3>📋 Compliance Impact</h3>
        <div class="dashboard-grid">
            <div class="metric-card">
                <div class="metric-label">CIS M365 Controls</div>
                <div class="metric-value">$($ComplianceGap.FrameworkGaps.CIS.ControlsAffected)</div>
                <div>Controls with findings</div>
            </div>

            <div class="metric-card">
                <div class="metric-label">NIST CSF Functions</div>
                <div class="metric-value">$($ComplianceGap.FrameworkGaps.NIST.ControlsAffected)</div>
                <div>Functions with findings</div>
            </div>

            <div class="metric-card">
                <div class="metric-label">SOC 2 Criteria</div>
                <div class="metric-value">$($ComplianceGap.FrameworkGaps.SOC2.ControlsAffected)</div>
                <div>Criteria with findings</div>
            </div>

            <div class="metric-card">
                <div class="metric-label">PCI-DSS Requirements</div>
                <div class="metric-value">$($ComplianceGap.FrameworkGaps.PCIDSS.ControlsAffected)</div>
                <div>Requirements with findings</div>
            </div>
        </div>
    </div>
</section>
"@
}

function Get-QuickWinsSection {
    param(
        [Parameter(Mandatory)]
        [array]$QuickWins
    )

    if ($QuickWins.Count -eq 0) {
        return @"
<section class="section" id="quick-wins">
    <h2 class="section-title">⚡ Quick Wins</h2>
    <p>No quick wins identified - all findings require moderate to high effort.</p>
</section>
"@
    }

    $quickWinCards = ""
    $topQuickWins = $QuickWins | Select-Object -First 5

    foreach ($qw in $topQuickWins) {
        $quickWinCards += @"
<div class="quick-win-card">
    <h3>$($qw.Description -replace '<', '&lt;' -replace '>', '&gt;')</h3>
    <div class="quick-win-meta">
        <span><strong>Risk Score:</strong> <span class="risk-badge $($qw.RiskLevel.ToLower())">$($qw.RiskLevel)</span> $($qw.RiskScore)</span>
        <span><strong>Effort:</strong> $($qw.RemediationEffortDescription)</span>
        <span><strong>Priority Score:</strong> <span class="priority-score">$($qw.PriorityScore)</span></span>
    </div>
    <p style="margin-top: 10px;"><strong>Remediation:</strong> $($qw.Remediation -replace '<', '&lt;' -replace '>', '&gt;')</p>
</div>
"@
    }

    return @"
<section class="section" id="quick-wins">
    <h2 class="section-title">⚡ Quick Wins - High Impact, Low Effort</h2>
    <p>These findings provide significant security improvements with minimal implementation time. Prioritize these for immediate action.</p>
    <div class="quick-wins-grid">
        $quickWinCards
    </div>
</section>
"@
}

function Get-PrioritySection {
    param(
        [Parameter(Mandatory)]
        [array]$PrioritizedFindings
    )

    $topFindings = $PrioritizedFindings | Select-Object -First 15
    $tableRows = ""

    $rank = 1
    foreach ($finding in $topFindings) {
        $tableRows += @"
<tr>
    <td><strong>$rank</strong></td>
    <td>$($finding.Description -replace '<', '&lt;' -replace '>', '&gt;')</td>
    <td><span class="risk-badge $($finding.RiskLevel.ToLower())">$($finding.RiskLevel)</span></td>
    <td>$($finding.RiskScore)</td>
    <td>$($finding.RemediationEffortDescription)</td>
    <td class="priority-score">$($finding.PriorityScore)</td>
</tr>
"@
        $rank++
    }

    return @"
<section class="section" id="priority">
    <h2 class="section-title">🎯 Top Priority Findings - Recommended Remediation Order</h2>
    <p>Findings are prioritized by their Priority Score (Risk Score / Remediation Effort), providing the best return on investment.</p>

    <table class="priority-table">
        <thead>
            <tr>
                <th>Rank</th>
                <th>Finding</th>
                <th>Risk Level</th>
                <th>Risk Score</th>
                <th>Effort</th>
                <th>Priority Score</th>
            </tr>
        </thead>
        <tbody>
            $tableRows
        </tbody>
    </table>
</section>
"@
}

function Get-ComplianceSection {
    param(
        [Parameter(Mandatory)]
        [array]$Findings,

        [Parameter(Mandatory)]
        [object]$ComplianceGap
    )

    $cisCard = @"
<div class="compliance-card">
    <h3>CIS Microsoft 365 Foundations</h3>
    <div class="compliance-stat">
        <span>Controls Affected:</span>
        <span><strong>$($ComplianceGap.FrameworkGaps.CIS.ControlsAffected)</strong></span>
    </div>
    <div class="compliance-stat">
        <span>Total Findings:</span>
        <span><strong>$(($Findings | Where-Object { $_.ComplianceMappings.CIS_M365 }).Count)</strong></span>
    </div>
</div>
"@

    $nistCard = @"
<div class="compliance-card">
    <h3>NIST Cybersecurity Framework</h3>
    <div class="compliance-stat">
        <span>Functions Affected:</span>
        <span><strong>$($ComplianceGap.FrameworkGaps.NIST.ControlsAffected)</strong></span>
    </div>
    <div class="compliance-stat">
        <span>Total Findings:</span>
        <span><strong>$(($Findings | Where-Object { $_.ComplianceMappings.NIST_CSF }).Count)</strong></span>
    </div>
</div>
"@

    $soc2Card = @"
<div class="compliance-card">
    <h3>SOC 2 Trust Services</h3>
    <div class="compliance-stat">
        <span>Criteria Affected:</span>
        <span><strong>$($ComplianceGap.FrameworkGaps.SOC2.ControlsAffected)</strong></span>
    </div>
    <div class="compliance-stat">
        <span>Total Findings:</span>
        <span><strong>$(($Findings | Where-Object { $_.ComplianceMappings.SOC2 }).Count)</strong></span>
    </div>
</div>
"@

    $pciCard = @"
<div class="compliance-card">
    <h3>PCI-DSS v4.0.1</h3>
    <div class="compliance-stat">
        <span>Requirements Affected:</span>
        <span><strong>$($ComplianceGap.FrameworkGaps.PCIDSS.ControlsAffected)</strong></span>
    </div>
    <div class="compliance-stat">
        <span>Total Findings:</span>
        <span><strong>$(($Findings | Where-Object { $_.ComplianceMappings.PCI_DSS_4 }).Count)</strong></span>
    </div>
</div>
"@

    return @"
<section class="section" id="compliance">
    <h2 class="section-title">📋 Compliance Framework Mapping</h2>
    <p>This assessment maps findings to industry-standard compliance frameworks, helping you understand regulatory impact and compliance gaps.</p>

    <div class="compliance-grid">
        $cisCard
        $nistCard
        $soc2Card
        $pciCard
    </div>
</section>
"@
}

function Get-DetailedFindingsSection {
    param(
        [Parameter(Mandatory)]
        [array]$Findings
    )

    # Group findings by risk level
    $critical = @($Findings | Where-Object { $_.RiskLevel -eq 'Critical' })
    $high = @($Findings | Where-Object { $_.RiskLevel -eq 'High' })
    $medium = @($Findings | Where-Object { $_.RiskLevel -eq 'Medium' })
    $low = @($Findings | Where-Object { $_.RiskLevel -eq 'Low' -or $_.RiskLevel -eq 'Info' })

    $findingCards = ""

    # Helper function to generate finding card
    function Get-FindingCard {
        param($finding)

        $complianceRef = if ($finding.ComplianceReference) {
            "<p><strong>Compliance Frameworks:</strong> $($finding.ComplianceReference)</p>"
        } else { "" }

        $remediationGuidance = ""
        if ($finding.RemediationGuidance) {
            $rg = $finding.RemediationGuidance
            $stepsHtml = ($rg.StepsPortal | ForEach-Object { "<li>$_</li>" }) -join ""

            $remediationGuidance = @"
<div class="remediation-steps">
    <h4>ðŸ“ Remediation Steps (Azure Portal)</h4>
    <ol>
        $stepsHtml
    </ol>

    <h4 style="margin-top: 15px;">ðŸ’» PowerShell Remediation</h4>
    <div class="code-block">$($rg.StepsPowerShell -replace '<', '&lt;' -replace '>', '&gt;')</div>

    <p style="margin-top: 10px;"><strong>Impact:</strong> $($rg.Impact.Positive)</p>
    <p><strong>Considerations:</strong> $($rg.Impact.Negative)</p>
</div>
"@
        }

        return @"
<div class="finding-card">
    <div class="finding-header" onclick="toggleFinding(this)">
        <div>
            <span class="risk-badge $($finding.RiskLevel.ToLower())">$($finding.RiskLevel)</span>
            <span class="finding-title">$($finding.Description -replace '<', '&lt;' -replace '>', '&gt;')</span>
        </div>
        <span>â–¼</span>
    </div>
    <div class="finding-body">
        <div class="finding-meta">
            <div><strong>Object:</strong> $($finding.Object -replace '<', '&lt;' -replace '>', '&gt;')</div>
            <div><strong>Risk Score:</strong> $($finding.RiskScore) / 100</div>
            <div><strong>Priority Score:</strong> $($finding.PriorityScore)</div>
            <div><strong>Remediation Effort:</strong> $($finding.RemediationEffortDescription)</div>
        </div>

        $complianceRef

        <p style="margin: 15px 0;"><strong>Quick Remediation:</strong> $($finding.Remediation -replace '<', '&lt;' -replace '>', '&gt;')</p>

        $remediationGuidance
    </div>
</div>
"@
    }

    # Generate cards for each risk level
    if ($critical.Count -gt 0) {
        $findingCards += "<h3 style='color: #d13438; margin-top: 20px;'>🔴 Critical Risk Findings ($($critical.Count))</h3>"
        foreach ($f in $critical) {
            $findingCards += Get-FindingCard -finding $f
        }
    }

    if ($high.Count -gt 0) {
        $findingCards += "<h3 style='color: #ff8c00; margin-top: 30px;'>🟠ðŸŸ  High Risk Findings ($($high.Count))</h3>"
        foreach ($f in $high) {
            $findingCards += Get-FindingCard -finding $f
        }
    }

    if ($medium.Count -gt 0) {
        $findingCards += "<h3 style='color: #ffb900; margin-top: 30px;'>🟡ðŸŸ¡ Medium Risk Findings ($($medium.Count))</h3>"
        foreach ($f in $medium) {
            $findingCards += Get-FindingCard -finding $f
        }
    }

    if ($low.Count -gt 0) {
        $findingCards += "<h3 style='color: #107c10; margin-top: 30px;'>🟢ðŸŸ¢ Low Risk Findings ($($low.Count))</h3>"
        foreach ($f in $low) {
            $findingCards += Get-FindingCard -finding $f
        }
    }

    return @"
        <section class="section" id="detailed">
        <h2 class="section-title">ðŸ“‹ Detailed Findings</h2>
    <div class="controls-bar">
        <input type="text" id="searchBox" placeholder="Search findings..." onkeyup="searchFindings()">
        <select id="riskFilter" onchange="filterByRisk()">
            <option value="all">All Risk Levels</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
        </select>
        <button class="expand-all-btn" onclick="expandAll()">Expand All</button>
        <button class="expand-all-btn" onclick="collapseAll()">Collapse All</button>
    </div>

    $findingCards
</section>
"@
    }

    function Get-HTMLJavaScript {
        return @'
<script>
    // Toggle individual finding
    function toggleFinding(header) {
        const body = header.nextElementSibling;
        const arrow = header.querySelector('span:last-child');

        if (body.classList.contains('active')) {
            body.classList.remove('active');
            arrow.textContent = 'â–¼';
        } else {
            body.classList.add('active');
            arrow.textContent = 'â–²';
        }
    }

    // Expand all findings
    function expandAll() {
        document.querySelectorAll('.finding-body').forEach(body => {
            body.classList.add('active');
        });
        document.querySelectorAll('.finding-header span:last-child').forEach(arrow => {
            arrow.textContent = 'â–²';
        });
    }

    // Collapse all findings
    function collapseAll() {
        document.querySelectorAll('.finding-body').forEach(body => {
            body.classList.remove('active');
        });
        document.querySelectorAll('.finding-header span:last-child').forEach(arrow => {
            arrow.textContent = 'â–¼';
        });
    }

    // Search findings
    function searchFindings() {
        const searchTerm = document.getElementById('searchBox').value.toLowerCase();
        const cards = document.querySelectorAll('.finding-card');

        cards.forEach(card => {
            const text = card.textContent.toLowerCase();
            if (text.includes(searchTerm)) {
                card.style.display = '';
            } else {
                card.style.display = 'none';
            }
        });
    }

    // Filter by risk level
    function filterByRisk() {
        const riskLevel = document.getElementById('riskFilter').value;
        const cards = document.querySelectorAll('.finding-card');

        cards.forEach(card => {
            if (riskLevel === 'all') {
                card.style.display = '';
            } else {
                const badge = card.querySelector('.risk-badge');
                if (badge && badge.classList.contains(riskLevel)) {
                    card.style.display = '';
                } else {
                    card.style.display = 'none';
                }
            }
        });
    }

    // Smooth scrolling for navigation
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
</script>
'@
    }

    #endregion

    #region Export Module Members

    Export-ModuleMember -Function @(
        'New-EnhancedHTMLReport'
    )

    #endregion
