# EntraChecks — Microsoft Cloud Compliance Assessment Toolkit

**Version 1.0.0** · PowerShell 5.1+ · Windows 10/11 or Server 2016+

EntraChecks runs read-only security and compliance checks across your Microsoft 365
and Azure environment, then produces actionable HTML/CSV/JSON reports you can hand
to auditors, leadership, or your remediation team.

---

## What Gets Assessed

| Module               | What It Checks                                                        | License Needed            |
|----------------------|-----------------------------------------------------------------------|---------------------------|
| **Core**             | Conditional Access, MFA, password policies, admin roles, guest access | Azure AD Free (or higher) |
| **IdentityProtection** | Risky users, risky sign-ins, risk-based CA policies                 | Azure AD Premium P2       |
| **Devices**          | Intune compliance, BitLocker, device encryption, stale devices        | Microsoft Intune          |
| **SecureScore**      | Microsoft Secure Score breakdown and improvement actions               | Any M365 plan             |
| **Defender**         | Defender for Cloud regulatory compliance (CIS, NIST, etc.)            | Defender for Cloud        |
| **AzurePolicy**      | Azure Policy compliance state across subscriptions                    | Any Azure subscription    |
| **Purview**          | Compliance Manager assessment scores and improvement actions           | M365 E5 Compliance        |

> **All checks are read-only.** EntraChecks never modifies your tenant.

---

## Quick Start (5 Minutes)

### Step 1 — Install Prerequisites

Open **PowerShell as Administrator** and run:

```powershell
# Install the Microsoft Graph SDK (required for all modules)
Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber

# Install Azure modules (only if you plan to run AzurePolicy or Defender modules)
Install-Module Az.Accounts   -Scope CurrentUser -Force
Install-Module Az.PolicyInsights -Scope CurrentUser -Force
Install-Module Az.Resources  -Scope CurrentUser -Force
Install-Module Az.Security   -Scope CurrentUser -Force
```

Or just run the included helper script:

```powershell
.\Install-Prerequisites.ps1
```

### Step 2 — Unblock the Scripts (Windows Security)

After extracting the zip, Windows may block the downloaded scripts. Run this once
from the `EntraChecks` folder:

```powershell
Get-ChildItem -Recurse -Include *.ps1,*.psm1 | Unblock-File
```

### Step 3 — Run EntraChecks

```powershell
cd EntraChecks
.\Start-EntraChecks.ps1
```

That's it! The interactive menu walks you through everything from here.

A browser window will open for Microsoft sign-in. Sign in with a **Global Reader**
(minimum) or **Global Administrator** account, accept the permission consent prompt,
and the assessment begins.

---

## Running Modes

### Interactive (Default)

```powershell
.\Start-EntraChecks.ps1
```

A menu lets you pick individual modules, view reports, manage snapshots, and compare
results over time.

### Quick Mode

```powershell
.\Start-EntraChecks.ps1 -Mode Quick -TenantName "Contoso" -Modules All
```

Runs every module with minimal prompts. Great for a one-shot full assessment.

### Scheduled / CI-CD Mode

```powershell
.\Start-EntraChecks.ps1 -Mode Scheduled -Modules Core,SecureScore -SaveSnapshot
```

Silent execution with no prompts. Ideal for Task Scheduler or Azure DevOps pipelines.
Returns exit code 1 if any FAIL findings are detected.

---

## Parameters Reference

| Parameter            | Type       | Default         | Description                                           |
|----------------------|------------|-----------------|-------------------------------------------------------|
| `-Mode`              | String     | `Interactive`   | `Interactive`, `Quick`, or `Scheduled`                |
| `-TenantName`        | String     | *(prompted)*    | Friendly label for the tenant (used in report names)  |
| `-OutputDirectory`   | String     | `.\Output`      | Where reports are written                             |
| `-Modules`           | String[]   | *(all)*         | Which modules to run (see table above)                |
| `-SkipAuthentication`| Switch     | `$false`        | Reuse an existing Graph/Azure session                 |
| `-SaveSnapshot`      | Switch     | `$false`        | Save results for later comparison                     |
| `-CompareWithLast`   | Switch     | `$false`        | Auto-compare with the most recent snapshot            |
| `-ExportFormat`      | String     | `All`           | `HTML`, `CSV`, `JSON`, or `All`                       |

---

## Folder Structure

```
EntraChecks/
├── Start-EntraChecks.ps1          # Main entry point (run this)
├── Invoke-EntraChecks.ps1         # Core assessment engine (25 checks)
├── Install-Prerequisites.ps1      # One-click dependency installer
├── Modules/
│   ├── EntraChecks-Connection.psm1         # Authentication & permissions
│   ├── EntraChecks-Compliance.psm1         # Compliance framework engine
│   ├── EntraChecks-IdentityProtection.psm1 # Identity risk checks
│   ├── EntraChecks-Devices.psm1            # Intune & device checks
│   ├── EntraChecks-SecureScore.psm1        # Secure Score integration
│   ├── EntraChecks-DefenderCompliance.psm1 # Defender for Cloud
│   ├── EntraChecks-AzurePolicy.psm1        # Azure Policy compliance
│   ├── EntraChecks-PurviewCompliance.psm1  # Purview Compliance Manager
│   ├── EntraChecks-DeltaReporting.psm1     # Snapshot comparison engine
│   └── EntraChecks-Hybrid.psm1             # Hybrid identity checks
├── Output/                        # Reports land here (auto-created)
├── Snapshots/                     # Saved assessment snapshots
├── README.md                      # This file
├── CHANGELOG.md                   # Bug fixes and version history
└── EntraChecks-CodeReview.md      # Full technical code review
```

---

## Permissions Required

EntraChecks requests **read-only** Microsoft Graph permissions. The exact scopes
depend on which modules you run:

| Module               | Graph Scopes                                                                 |
|----------------------|------------------------------------------------------------------------------|
| Core                 | `Directory.Read.All`, `Policy.Read.All`, `AuditLog.Read.All`                |
| IdentityProtection   | `IdentityRiskEvent.Read.All`, `IdentityRiskyUser.Read.All`                  |
| Devices              | `Device.Read.All`, `DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All` |
| SecureScore          | `SecurityEvents.Read.All`                                                    |
| Purview              | `ComplianceManager.Read.All`, `InformationProtectionPolicy.Read`             |

For the **AzurePolicy** and **Defender** modules, you also need an Azure session
(`Connect-AzAccount`) with **Reader** access on the subscriptions you want to assess.

### Minimum Role

**Global Reader** is sufficient for all read-only checks. If you use an account with
fewer permissions, EntraChecks will still run — it simply skips checks it can't access
and tells you which ones were skipped.

---

## Understanding the Output

After an assessment, look in the `Output/` folder. You'll find a timestamped
subfolder containing:

- **HTML Report** — Open this in any browser. Color-coded findings with
  pass/fail/warning status, remediation guidance, and an executive summary.
- **CSV Export** — Every finding as a row. Import into Excel, Power BI, or a
  SIEM for further analysis.
- **JSON Export** — Machine-readable output for automation pipelines.
- **Unified Report** — A single consolidated report when multiple modules are run.

### Finding Severities

| Status    | Meaning                                                       |
|-----------|---------------------------------------------------------------|
| **FAIL**  | Security control is missing or misconfigured. Fix this.       |
| **WARNING** | Partial implementation or best-practice deviation. Review.  |
| **OK**    | Control is properly configured. No action needed.             |
| **INFO**  | Informational finding. No security impact.                    |

---

## Snapshots & Delta Reporting

EntraChecks can save assessment results as **snapshots** so you can track your
security posture over time:

```powershell
# Save a snapshot after running
.\Start-EntraChecks.ps1 -Mode Quick -Modules All -SaveSnapshot

# Compare with the last snapshot on the next run
.\Start-EntraChecks.ps1 -Mode Quick -Modules All -SaveSnapshot -CompareWithLast
```

The delta report highlights what improved, what regressed, and what's new since the
last assessment. This is invaluable for demonstrating progress to auditors.

In Interactive mode, the **Manage Snapshots** and **Compare Snapshots** menus give
you full control over snapshot selection and comparison.

---

## Troubleshooting

### "Running scripts is disabled on this system"

PowerShell's execution policy is blocking scripts. Run this once as Administrator:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### "The term 'Connect-MgGraph' is not recognized"

The Microsoft Graph module isn't installed. Run:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
```

### "Insufficient privileges" or blank results

Your account doesn't have the required Graph permissions. Either:
- Sign in with a **Global Reader** or **Global Administrator** account, or
- Ask your admin to grant the needed scopes (listed above) via admin consent.

### "Az.PolicyInsights module not found"

Only needed for Azure Policy checks. Install with:

```powershell
Install-Module Az.PolicyInsights -Scope CurrentUser -Force
```

### Browser doesn't open for sign-in

Try running PowerShell outside of ISE (use Windows Terminal or the regular
PowerShell console). ISE sometimes interferes with interactive authentication.

---

## Advanced: App Registration (Unattended)

For CI/CD or scheduled runs without interactive sign-in, register an app in
Azure AD:

1. Go to **Azure Portal → App registrations → New registration**
2. Add the API permissions listed above (Application type, not Delegated)
3. Grant admin consent
4. Create a certificate and upload the public key
5. Run EntraChecks with certificate auth:

```powershell
.\Invoke-EntraChecks.ps1 -NonInteractive `
    -AuthMode Application `
    -TenantId "your-tenant-id" `
    -ClientId "your-app-id" `
    -ClientCertificateThumbprint "your-cert-thumbprint"
```

---

## License & Disclaimer

EntraChecks is provided as-is for security assessment purposes. It performs
**read-only** operations and does not modify your tenant configuration. Always
review findings with your security team before making changes.
