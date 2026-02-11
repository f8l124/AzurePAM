@{
    # PSScriptAnalyzer Configuration for EntraChecks
    # This file defines code quality rules and standards for the project

    # Include default rules
    IncludeDefaultRules = $true

    # Severity levels to include (Error, Warning, Information)
    Severity = @('Error', 'Warning')

    # Exclude specific rules
    # These are intentionally disabled for this project
    ExcludeRules = @(
        # We use Write-Host for user-facing output intentionally
        'PSAvoidUsingWriteHost',

        # We use aliases in some display functions for brevity
        'PSAvoidUsingCmdletAliases',

        # Some functions are intentionally verbose for clarity
        'PSUseShouldProcessForStateChangingFunctions'
    )

    # Rules to explicitly include
    IncludeRules = @(
        # Best Practices
        'PSAvoidUsingPlainTextForPassword',
        'PSAvoidUsingConvertToSecureStringWithPlainText',
        'PSAvoidUsingInvokeExpression',
        'PSAvoidGlobalVars',
        'PSUseDeclaredVarsMoreThanAssignments',
        'PSAvoidUsingPositionalParameters',

        # Cmdlet Design
        'PSUseApprovedVerbs',
        'PSReservedCmdletChar',
        'PSReservedParams',
        'PSShouldProcess',
        'PSUseSingularNouns',

        # Script Functions
        'PSAvoidDefaultValueSwitchParameter',
        'PSProvideCommentHelp',
        'PSUseCmdletCorrectly',
        'PSUseOutputTypeCorrectly',

        # Script Security
        'PSAvoidUsingComputerNameHardcoded',
        'PSAvoidUsingUsernameAndPasswordParams',

        # Code Style
        'PSUseConsistentIndentation',
        'PSUseConsistentWhitespace',
        'PSAlignAssignmentStatement',
        'PSUseCorrectCasing',

        # Performance
        'PSAvoidUsingEmptyCatchBlock',
        'PSUsePSCredentialType'
    )

    # Rule-specific settings
    Rules = @{
        # Consistent indentation (4 spaces)
        PSUseConsistentIndentation = @{
            Enable = $true
            IndentationSize = 4
            PipelineIndentation = 'IncreaseIndentationForFirstPipeline'
            Kind = 'space'
        }

        # Consistent whitespace
        PSUseConsistentWhitespace = @{
            Enable = $true
            CheckInnerBrace = $true
            CheckOpenBrace = $true
            CheckOpenParen = $true
            CheckOperator = $true
            CheckPipe = $true
            CheckPipeForRedundantWhitespace = $false
            CheckSeparator = $true
            CheckParameter = $false
        }

        # Alignment
        PSAlignAssignmentStatement = @{
            Enable = $true
            CheckHashtable = $true
        }

        # Correct casing for cmdlets
        PSUseCorrectCasing = @{
            Enable = $true
        }

        # Provide comment-based help
        PSProvideCommentHelp = @{
            Enable = $true
            ExportedOnly = $true
            BlockComment = $true
            VSCodeSnippetCorrection = $true
            Placement = 'before'
        }

        # Use compatible cmdlets for cross-platform
        PSUseCompatibleCmdlets = @{
            Enable = $true
            Compatibility = @('core-6.1.0-windows', 'desktop-5.1.14393.206-windows')
        }

        # Use compatible syntax
        PSUseCompatibleSyntax = @{
            Enable = $true
            TargetVersions = @('5.1', '6.2', '7.0', '7.1', '7.2')
        }

        # Avoid using cmdlet aliases
        PSAvoidUsingCmdletAliases = @{
            Enable = $false  # Disabled for this project
            Whitelist = @()
        }
    }
}
