# EntraChecks Azure Key Vault Integration Guide

## Overview

Azure Key Vault integration is an **optional** feature that provides secure, centralized secret management for EntraChecks. This guide is designed for consultants deploying EntraChecks in client environments where enhanced security is required.

## Important: This is Optional

**All EntraChecks functionality works without Azure Key Vault.** This integration is provided for clients who:
- Have Azure Key Vault already deployed
- Want centralized secret management
- Need to meet specific security compliance requirements
- Prefer not to use environment variables or interactive prompts

**If your client doesn't need this, skip it entirely.** EntraChecks will work perfectly with:
- Interactive authentication (browser-based)
- Environment variables
- Service Principal with certificates
- Direct credential input

## What is Azure Key Vault Integration?

Azure Key Vault integration allows EntraChecks to securely retrieve:
- Service Principal client secrets
- API keys
- Passwords
- Certificates

Instead of storing secrets in:
- ❌ Configuration files (insecure)
- ❌ Environment variables (less secure)
- ❌ Scripts (very insecure)

Secrets are stored in:
- ✅ Azure Key Vault (enterprise-grade security)
- ✅ Centrally managed
- ✅ Access audited
- ✅ RBAC-protected

## When to Use Key Vault Integration

### Use Key Vault When:

✅ **Client has existing Key Vault infrastructure**
- Already using Key Vault for other secrets
- Key Vault is part of their standard deployment

✅ **Compliance requirements demand it**
- Financial services, healthcare, government
- ISO 27001, SOC 2, FedRAMP compliance
- Audit trail for secret access required

✅ **Running in Azure**
- Azure VMs, Azure Functions, Azure Automation
- Can use Managed Identity (no credentials needed)
- Seamless integration with Azure ecosystem

✅ **Automated/scheduled execution**
- CI/CD pipelines
- Scheduled assessments
- No interactive user available

### Don't Use Key Vault When:

❌ **Client doesn't have Azure Key Vault**
- Additional infrastructure cost
- Additional complexity
- Not worth it for occasional use

❌ **One-time or ad-hoc assessments**
- Interactive authentication is simpler
- No need for automation

❌ **Development/testing**
- Environment variables are sufficient
- Interactive auth is faster

❌ **Client prefers certificate-based auth**
- Certificates stored in cert store work fine
- No need for Key Vault

## Prerequisites

### Required Azure Resources

1. **Azure Subscription** - Client must have an Azure subscription
2. **Azure Key Vault** - Client must have a Key Vault or be willing to create one
3. **Permissions** - Appropriate access to Key Vault (see RBAC section)

### Required PowerShell Modules

```powershell
# Install Az.KeyVault module (only needed if using Key Vault)
Install-Module Az.KeyVault -Scope CurrentUser -Force

# Verify installation
Get-Module Az.KeyVault -ListAvailable
```

### Required EntraChecks Modules

Key Vault integration is built-in:
- ✅ `EntraChecks-KeyVault.psm1` (included with EntraChecks)
- ✅ `EntraChecks-Connection.psm1` (updated with Key Vault support)
- ✅ `EntraChecks-Configuration.psm1` (includes Key Vault schema)

## Setup Guide

### Step 1: Create Azure Key Vault (if needed)

```powershell
# Login to Azure
Connect-AzAccount

# Variables
$keyVaultName = "entrachecks-kv-prod"
$resourceGroup = "rg-security-tools"
$location = "EastUS"

# Create Resource Group (if needed)
New-AzResourceGroup -Name $resourceGroup -Location $location

# Create Key Vault
New-AzKeyVault `
    -Name $keyVaultName `
    -ResourceGroupName $resourceGroup `
    -Location $location `
    -EnableRbacAuthorization  # Use RBAC instead of access policies
```

### Step 2: Store Secrets in Key Vault

```powershell
# Store Service Principal secret
$clientSecret = Read-Host "Enter Service Principal client secret" -AsSecureString
Set-AzKeyVaultSecret `
    -VaultName $keyVaultName `
    -Name "entrachecks-client-secret" `
    -SecretValue $clientSecret

# Verify secret was created
Get-AzKeyVaultSecret -VaultName $keyVaultName -Name "entrachecks-client-secret"
```

### Step 3: Configure Access (RBAC)

#### Option A: Using Managed Identity (Recommended for Azure-hosted)

```powershell
# Get the Managed Identity Object ID
# For Azure VM: Found in VM > Identity > Object (principal) ID
# For Azure Function: Found in Function App > Identity > Object (principal) ID
$managedIdentityObjectId = "12345678-1234-1234-1234-123456789012"

# Grant Key Vault Secrets User role
New-AzRoleAssignment `
    -ObjectId $managedIdentityObjectId `
    -RoleDefinitionName "Key Vault Secrets User" `
    -Scope "/subscriptions/{subscription-id}/resourceGroups/{rg-name}/providers/Microsoft.KeyVault/vaults/{vault-name}"
```

#### Option B: Using Service Principal

```powershell
# Get Service Principal Object ID
$sp = Get-AzADServicePrincipal -ApplicationId $clientId
$spObjectId = $sp.Id

# Grant Key Vault Secrets User role
New-AzRoleAssignment `
    -ObjectId $spObjectId `
    -RoleDefinitionName "Key Vault Secrets User" `
    -Scope "/subscriptions/{subscription-id}/resourceGroups/{rg-name}/providers/Microsoft.KeyVault/vaults/{vault-name}"
```

#### Option C: Using User Account (for development)

```powershell
# Get your user Object ID
$currentUser = Get-AzADUser -UserPrincipalName "admin@contoso.com"
$userObjectId = $currentUser.Id

# Grant Key Vault Secrets User role
New-AzRoleAssignment `
    -ObjectId $userObjectId `
    -RoleDefinitionName "Key Vault Secrets User" `
    -Scope "/subscriptions/{subscription-id}/resourceGroups/{rg-name}/providers/Microsoft.KeyVault/vaults/{vault-name}"
```

### Step 4: Configure EntraChecks

#### Method 1: Using Configuration File (Recommended)

Create or update `config/entrachecks.config.prod.json`:

```json
{
  "Version": "1.0.0",
  "Assessment": {
    "Scope": ["Core", "Compliance"],
    "Output": {
      "Directory": "C:\\EntraChecks\\Output",
      "Formats": ["HTML", "CSV"]
    }
  },
  "Authentication": {
    "Method": "ServicePrincipal",
    "ServicePrincipal": {
      "ClientId": "12345678-1234-1234-1234-123456789012",
      "KeyVaultName": "entrachecks-kv-prod",
      "SecretName": "entrachecks-client-secret"
    }
  },
  "KeyVault": {
    "Enabled": true,
    "VaultName": "entrachecks-kv-prod",
    "AuthenticationMethod": "ManagedIdentity",
    "Secrets": {
      "ServicePrincipalSecret": "entrachecks-client-secret"
    }
  },
  "Logging": {
    "Directory": "C:\\EntraChecks\\Logs",
    "MinimumLevel": "INFO"
  },
  "ErrorHandling": {
    "MaxRetries": 5
  }
}
```

#### Method 2: Using PowerShell Parameters

```powershell
# Connect using Key Vault
Connect-EntraChecks `
    -Modules Core,Compliance `
    -TenantId "tenant-guid" `
    -ClientId "client-guid" `
    -KeyVaultName "entrachecks-kv-prod" `
    -KeyVaultSecretName "entrachecks-client-secret"
```

### Step 5: Test Connection

```powershell
# Import module
Import-Module .\Modules\EntraChecks-KeyVault.psm1

# Test Key Vault availability
if (Test-KeyVaultAvailable) {
    Write-Host "Az.KeyVault module is available"
} else {
    Write-Host "Az.KeyVault module not found - install with: Install-Module Az.KeyVault"
}

# Test connection to Key Vault
try {
    Connect-EntraChecksKeyVault -KeyVaultName "entrachecks-kv-prod"
    Write-Host "Successfully connected to Key Vault"

    # Test secret retrieval
    $secret = Get-KeyVaultSecret -SecretName "entrachecks-client-secret"
    Write-Host "Successfully retrieved secret"

    Disconnect-EntraChecksKeyVault
} catch {
    Write-Host "Error: $_"
}
```

## Configuration Options

### Key Vault Configuration Schema

```json
{
  "KeyVault": {
    "Enabled": true,                          // Enable/disable Key Vault integration
    "VaultName": "entrachecks-kv-prod",      // Key Vault name
    "AuthenticationMethod": "ManagedIdentity", // Auth method: ManagedIdentity, ServicePrincipal, Interactive
    "TenantId": "tenant-guid",               // Required for ServicePrincipal/Interactive
    "ClientId": "client-guid",               // Required for ServicePrincipal
    "CertificateThumbprint": "thumbprint",   // Optional: for cert-based auth to Key Vault
    "Secrets": {
      "GraphAPISecret": "graph-api-secret",  // Secret name for Graph API credentials
      "ServicePrincipalSecret": "sp-secret"  // Secret name for Service Principal
    }
  }
}
```

### Authentication Methods to Key Vault

#### 1. Managed Identity (Recommended for Azure)

**Use when**: Running on Azure VM, Azure Function, Azure Automation

**Advantages**:
- No credentials needed
- Automatic authentication
- Most secure option
- Azure handles credential rotation

**Configuration**:
```json
{
  "KeyVault": {
    "Enabled": true,
    "VaultName": "my-keyvault",
    "AuthenticationMethod": "ManagedIdentity"
  }
}
```

#### 2. Service Principal with Certificate

**Use when**: Running outside Azure, need automated access

**Advantages**:
- More secure than client secret
- Certificate-based authentication
- Works from anywhere

**Configuration**:
```json
{
  "KeyVault": {
    "Enabled": true,
    "VaultName": "my-keyvault",
    "AuthenticationMethod": "ServicePrincipal",
    "TenantId": "tenant-guid",
    "ClientId": "client-guid",
    "CertificateThumbprint": "cert-thumbprint"
  }
}
```

#### 3. Interactive (Development Only)

**Use when**: Testing, development, one-time setup

**Advantages**:
- Easy to test
- No setup required
- Uses your user account

**Configuration**:
```json
{
  "KeyVault": {
    "Enabled": true,
    "VaultName": "my-keyvault",
    "AuthenticationMethod": "Interactive",
    "TenantId": "tenant-guid"
  }
}
```

## Usage Examples

### Example 1: Basic Key Vault Usage

```powershell
# Import modules
Import-Module .\Modules\EntraChecks-KeyVault.psm1
Import-Module .\Modules\EntraChecks-Connection.psm1

# Connect to Key Vault
Connect-EntraChecksKeyVault -KeyVaultName "entrachecks-kv-prod"

# Retrieve a secret
$clientSecret = Get-KeyVaultSecret -SecretName "entrachecks-client-secret"

# Use secret for authentication
Connect-EntraChecks `
    -Modules Core `
    -TenantId "tenant-guid" `
    -ClientId "client-guid" `
    -ClientSecret $clientSecret
```

### Example 2: Using Configuration File

```powershell
# Load configuration (includes Key Vault settings)
Import-Module .\Modules\EntraChecks-Configuration.psm1
$config = Import-Configuration -FilePath ".\config\entrachecks.config.prod.json"

# Run assessment (Key Vault integration is automatic)
.\Start-EntraChecks.ps1 -ConfigFile ".\config\entrachecks.config.prod.json"
```

### Example 3: Graceful Fallback

```powershell
# Try Key Vault, fall back to environment variable
$cred = Get-EntraChecksCredential `
    -CredentialName "GraphAPI" `
    -KeyVaultSecretName "graph-api-secret" `
    -EnvironmentVariable "GRAPH_API_SECRET" `
    -AllowInteractive

# Use credential
if ($cred) {
    # Authenticate with credential
} else {
    Write-Warning "No credentials available"
}
```

### Example 4: Store New Secret

```powershell
# Connect to Key Vault
Connect-EntraChecksKeyVault -KeyVaultName "entrachecks-kv-prod"

# Store a new secret
$newSecret = Read-Host "Enter new secret" -AsSecureString
Set-KeyVaultSecret `
    -SecretName "new-secret" `
    -SecretValue $newSecret `
    -ContentType "password" `
    -ExpiresOn (Get-Date).AddYears(1)

Write-Host "Secret stored successfully"
```

## Security Best Practices

### 1. Use Managed Identity When Possible

✅ **DO**: Use Managed Identity for Azure-hosted workloads
- No credentials in configuration
- Azure handles rotation
- Simplest and most secure

❌ **DON'T**: Use Service Principal secrets when Managed Identity is available

### 2. Use RBAC, Not Access Policies

✅ **DO**: Use Azure RBAC for Key Vault access
```powershell
New-AzRoleAssignment -RoleDefinitionName "Key Vault Secrets User"
```

❌ **DON'T**: Use legacy access policies (being deprecated)

### 3. Principle of Least Privilege

✅ **DO**: Grant minimum required permissions
- "Key Vault Secrets User" for read-only access
- Specific secrets, not entire vault

❌ **DON'T**: Grant "Key Vault Administrator" unnecessarily

### 4. Enable Audit Logging

```powershell
# Enable diagnostic settings
Set-AzDiagnosticSetting `
    -ResourceId $keyVaultId `
    -Name "KeyVaultAudit" `
    -Enabled $true `
    -Category AuditEvent `
    -WorkspaceId $logAnalyticsWorkspaceId
```

### 5. Set Secret Expiration

```powershell
# Set expiration when creating secrets
Set-AzKeyVaultSecret `
    -VaultName $vaultName `
    -Name $secretName `
    -SecretValue $secret `
    -Expires (Get-Date).AddYears(1)
```

### 6. Use Separate Key Vaults

✅ **DO**: Use different Key Vaults for:
- Development
- Staging
- Production

❌ **DON'T**: Share Key Vault across environments

### 7. Monitor Access

- Enable Azure Monitor alerts
- Review access logs regularly
- Alert on unusual access patterns

## Troubleshooting

### Issue: "Az.KeyVault module not found"

**Solution**:
```powershell
Install-Module Az.KeyVault -Scope CurrentUser -Force
Import-Module Az.KeyVault
```

### Issue: "Failed to connect to Key Vault"

**Possible Causes**:
1. Key Vault doesn't exist
2. No RBAC permissions
3. Network restrictions (firewall)

**Solution**:
```powershell
# Verify Key Vault exists
Get-AzKeyVault -VaultName "your-vault-name"

# Check your permissions
Get-AzRoleAssignment -Scope "/subscriptions/{sub-id}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{vault-name}"

# Test from Azure Cloud Shell (bypasses network issues)
```

### Issue: "Secret not found"

**Solution**:
```powershell
# List all secrets
Get-AzKeyVaultSecret -VaultName "your-vault-name"

# Check secret name (case-sensitive)
Get-AzKeyVaultSecret -VaultName "your-vault-name" -Name "exact-secret-name"
```

### Issue: "Access denied" or "Forbidden"

**Solution**:
```powershell
# Check RBAC assignment
Get-AzRoleAssignment -ObjectId "your-object-id"

# Grant required role
New-AzRoleAssignment `
    -ObjectId "your-object-id" `
    -RoleDefinitionName "Key Vault Secrets User" `
    -Scope "/subscriptions/{sub-id}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{vault-name}"
```

### Issue: "Managed Identity not working"

**Solution**:
```powershell
# Verify Managed Identity is enabled
# For VM:
$vm = Get-AzVM -ResourceGroupName $rgName -Name $vmName
$vm.Identity

# For Function App:
$function = Get-AzFunctionApp -ResourceGroupName $rgName -Name $functionName
$function.IdentityPrincipalId

# If not enabled, enable it:
Update-AzVM -ResourceGroupName $rgName -VM $vm -IdentityType SystemAssigned
```

## Cost Considerations

### Key Vault Pricing (As of 2026)

| Operation | Cost |
|-----------|------|
| Secret operations | $0.03 per 10,000 operations |
| Standard tier vault | $0.03 per vault per month |
| Premium tier vault | $0.25 per vault per month |

**Typical EntraChecks Usage**:
- ~10-20 secret retrievals per assessment
- ~1,000 assessments per month = ~20,000 operations
- **Estimated cost**: ~$0.10/month + vault cost

**Conclusion**: Cost is negligible compared to security benefits.

## Migration Guide

### From Environment Variables to Key Vault

```powershell
# Step 1: Get current environment variable
$currentSecret = $env:CLIENT_SECRET

# Step 2: Store in Key Vault
$secureSecret = ConvertTo-SecureString $currentSecret -AsPlainText -Force
Set-AzKeyVaultSecret -VaultName "my-vault" -Name "client-secret" -SecretValue $secureSecret

# Step 3: Update configuration
# Change from:
"Authentication": {
  "ServicePrincipal": {
    "ClientId": "${ENV:CLIENT_ID}",
    "ClientSecret": "${ENV:CLIENT_SECRET}"  // Old
  }
}

# To:
"Authentication": {
  "ServicePrincipal": {
    "ClientId": "${ENV:CLIENT_ID}",
    "KeyVaultName": "my-vault",
    "SecretName": "client-secret"  // New
  }
},
"KeyVault": {
  "Enabled": true,
  "VaultName": "my-vault",
  "AuthenticationMethod": "ManagedIdentity"
}

# Step 4: Remove environment variable
Remove-Item Env:CLIENT_SECRET
```

## Summary

### Key Takeaways

✅ **Optional**: Key Vault integration is completely optional
✅ **Secure**: Provides enterprise-grade secret management
✅ **Flexible**: Multiple authentication methods supported
✅ **Auditable**: Full audit trail of secret access
✅ **Scalable**: Works from local machines to Azure cloud

### When to Recommend to Clients

| Client Scenario | Recommendation |
|----------------|----------------|
| Has Azure Key Vault | ✅ Use it |
| Azure-hosted workload | ✅ Use it (with Managed Identity) |
| Compliance requirements | ✅ Use it |
| One-time assessment | ❌ Skip it |
| No Azure infrastructure | ❌ Skip it |
| Development/testing | ❌ Skip it |

### Resources

- **Azure Key Vault Documentation**: https://docs.microsoft.com/azure/key-vault/
- **Managed Identity**: https://docs.microsoft.com/azure/active-directory/managed-identities-azure-resources/
- **RBAC for Key Vault**: https://docs.microsoft.com/azure/key-vault/general/rbac-guide
- **EntraChecks Key Vault Module**: [EntraChecks-KeyVault.psm1](../Modules/EntraChecks-KeyVault.psm1)

---

**For questions or issues**, see the [troubleshooting section](#troubleshooting) or contact your EntraChecks implementation team.
