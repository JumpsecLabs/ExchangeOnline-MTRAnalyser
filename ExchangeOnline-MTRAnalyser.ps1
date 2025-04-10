[CmdletBinding()]
param (
    [switch]$ShowDisabled
)

<#
.SYNOPSIS
    Exchange Online Mail Transport Rules Audit Script (by Fr4n)
.DESCRIPTION
    Connects to Exchange Online, audits transport rules and displays details.
    Use –ShowDisabled to display details for disabled rules in all sections (except the initial "Disabled Rules" section).
    If –Verbose is used, you will be prompted to confirm verbose output and optionally enable step‐by‐step pausing.
.PARAMETER ShowDisabled
    Displays audit details for disabled rules beyond the Disabled Rules section.
.EXAMPLE
    .\ExchangeOnline-MTRAnalyser.ps1 -ShowDisabled -Verbose
#>

# Suppress welcome/warning messages
$WarningPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

# Set global verbose flag based on the built-in -Verbose parameter.
if ($PSBoundParameters.ContainsKey("Verbose") -and $PSBoundParameters["Verbose"]) {
    $continueVerbose = Read-Host "Verbose mode is enabled. The output will be overly verbose. Continue? (y/n)"
    if ($continueVerbose -ne "y") { Write-Host "Exiting verbose mode."; exit }
    $stepInput = Read-Host "Pause after each rule's JSON output? (Press 'y' to enable step-by-step, any other key to disable)"
    if ($stepInput -eq "y") { $global:StepByStep = $true } else { $global:StepByStep = $false }
    $global:VerboseEnabled = $true
} else {
    $global:VerboseEnabled = $false
    $global:StepByStep = $false
}

# Prompt for Exchange Online account and connect
$userAccount = Read-Host "Enter Exchange Online account UPN"
Connect-ExchangeOnline -UserPrincipalName $userAccount -ShowBanner:$false

# Prompt to decide whether to scan for ASNs (may cause rate limiting)
$scanASNsChoice = Read-Host "Do you want to scan for ASNs? (y/n)"
$scanASNs = ($scanASNsChoice -eq "y")

# Prompt for trusted domains file (leave blank for none)
$trustedPath = Read-Host "Enter path to trusted domains file (leave blank for none)"
if (![string]::IsNullOrWhiteSpace($trustedPath) -and (Test-Path $trustedPath)) {
    $trustedDomains = Get-Content $trustedPath | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ -ne "" }
} else {
    $trustedDomains = @()
}

# Prompt for list of domain fronting/malicious domains or IP addresses (leave blank for none)
$domainFrontingFile = Read-Host "Enter path to list of domain fronting/malicious domains or IP addresses (leave blank for none)"
if (![string]::IsNullOrWhiteSpace($domainFrontingFile) -and (Test-Path $domainFrontingFile)) {
    $domainFrontingList = Get-Content $domainFrontingFile | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ -ne "" }
} else {
    $domainFrontingList = @()
}

# Helper: Determine the color for a rule's identity.
function Get-IdentityColor {
    param($rule)
    if ($rule.PSObject.Properties["Enabled"] -and $rule.Enabled -eq $false) { 
        return "DarkRed" 
    }
    elseif ($rule.PSObject.Properties["State"] -and $rule.State -ne "Enabled") { 
        return "DarkRed" 
    }
    else { 
        return "Cyan" 
    }
}

# Helper: Format a domain – if it exactly equals one in the domain fronting list, return Blue;
# if it exactly equals one in the trusted domains list, return Magenta; otherwise, return the provided default.
function Format-Domain {
    param(
        [string]$domain,
        [string]$defaultColor
    )
    $dLower = $domain.ToLower()
    if ($domainFrontingList -contains $dLower) {
         return @{ Text = $domain; Color = "Blue" }
    }
    elseif ($trustedDomains -contains $dLower) {
         return @{ Text = $domain; Color = "Magenta" }
    } else {
         return @{ Text = $domain; Color = $defaultColor }
    }
}

# Display Legend
Write-Host ""
Write-Host "LEGEND:" -ForegroundColor White
Write-Host "  Disabled Rule Identity: DarkRed" -ForegroundColor DarkRed
Write-Host "  Enabled Rule Identity: Cyan" -ForegroundColor Cyan
Write-Host "  Allow (domains): Green" -ForegroundColor Green
Write-Host "  Deny (domains): DarkYellow" -ForegroundColor DarkYellow
Write-Host "  Trusted Domain: Magenta" -ForegroundColor Magenta
Write-Host "  Domain Fronting Domain: Blue" -ForegroundColor Blue
Write-Host "  Fallback (Ignore/Wrap): Yellow" -ForegroundColor Yellow
Write-Host ""

# Function: Write a section heading.
function Write-Section {
    param([string]$title)
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor White
    Write-Host $title -ForegroundColor White
    Write-Host ("=" * 80) -ForegroundColor White
}

# Function: Strip HTML tags and replace common break tags with newlines.
function Strip-HTML {
    param([string]$html)
    if ([string]::IsNullOrWhiteSpace($html)) { return "" }
    $text = [regex]::Replace($html, "<style.*?>.*?</style>", "", [System.Text.RegularExpressions.RegexOptions]::Singleline -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $text = $text -replace "(?i)<br\s*/?>", "`n"
    $text = $text -replace "(?i)<p\s*/?>", "`n"
    $text = [regex]::Replace($text, "<[^>]+>", "")
    return [System.Web.HttpUtility]::HtmlDecode($text).Trim()
}

# Function: Classify IP (CIDR or single IP).
function Classify-IP {
    param([string]$ipRange)
    if ($ipRange -match "^(?<ip>[^/]+)/?(?<mask>\d*)$") {
        $ipStr = $matches['ip']
        try {
            $ip = [System.Net.IPAddress]::Parse($ipStr)
            if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                $bytes = $ip.GetAddressBytes()
                if ($bytes[0] -eq 10 -or ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or ($bytes[0] -eq 192 -and $bytes[1] -eq 168)) {
                    return "Private"
                } else {
                    return "External"
                }
            }
            elseif ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
                $ipStrLower = $ip.ToString().ToLower()
                if ($ipStrLower.StartsWith("fc") -or $ipStrLower.StartsWith("fd")) {
                    return "Private"
                } else {
                    return "External"
                }
            }
            return "External"
        } catch {
            return "Invalid"
        }
    }
    return "Invalid"
}

# Function: Get ASN info using HackerTarget API (returns last field).
function Get-ASNForIP {
    param([string]$ip)
    $url = "https://api.hackertarget.com/aslookup/?q=$ip"
    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10
        if ($response -and $response.Content) {
            $line = $response.Content.Trim()
            if ($line.StartsWith('"') -and $line.EndsWith('"')) {
                $line = $line.Substring(1, $line.Length - 2)
            }
            $parts = $line -split '","'
            if ($parts.Length -ge 4) {
                return $parts[3]
            }
        }
    } catch {
        return "Unknown ASN"
    }
    return "Unknown ASN"
}

# Modified Check-DomainFronting: Only return true if the domain exactly equals one in the provided list.
function Check-DomainFronting {
    param([string]$domain)
    foreach ($df in $domainFrontingList) {
        if ($domain.ToLower() -eq $df) { return $true }
    }
    return $false
}

# Retrieve rules from Exchange Online.
$rules = Get-TransportRule

# Function: Optionally display full JSON if verbose is enabled.
function Show-RuleJson {
    param($rule)
    if ($global:VerboseEnabled) {
        Write-Host "Full JSON:" -ForegroundColor Gray
        $rule | ConvertTo-Json -Depth 10 | Write-Host
        if ($global:StepByStep) {
            $resp = Read-Host "Press Enter to continue (or type 'n' to disable step-by-step pausing)"
            if ($resp -eq "n") { $global:StepByStep = $false }
        }
    }
}

# --- Disabled Rules ---
Write-Section "Disabled Rules"
$uniqueRules = @()
foreach ($rule in $rules) {
    if ( ($rule.PSObject.Properties["Enabled"] -and $rule.Enabled -eq $false) -or 
         ($rule.PSObject.Properties["State"] -and $rule.State -ne "Enabled") ) {
        if (-not ($uniqueRules -contains $rule.Name)) { $uniqueRules += $rule.Name }
        Write-Host "- " -NoNewline -ForegroundColor White
        Write-Host "[$($rule.Name)]" -NoNewline -ForegroundColor (Get-IdentityColor $rule)
        Write-Host " is DISABLED (State: Disabled)" -ForegroundColor White
        Show-RuleJson $rule
    }
}
Write-Host "Total unique disabled rules: $($uniqueRules.Count)" -ForegroundColor White

# --- Allowed and Denied Sender Domains ---
Write-Section "Allowed and Denied Sender Domains"
$uniqueRules = @()
foreach ($rule in $rules) {
    # Show details only if rule is enabled OR if -ShowDisabled is specified.
    if ((($rule.PSObject.Properties["Enabled"] -and $rule.Enabled -eq $false) -or ($rule.PSObject.Properties["State"] -and $rule.State -ne "Enabled")) -and (-not $ShowDisabled)) {
        continue
    }
    if ($rule.SenderDomainIs) {
        if (-not ($uniqueRules -contains $rule.Name)) { $uniqueRules += $rule.Name }
        Write-Host "- " -NoNewline -ForegroundColor White
        Write-Host "[$($rule.Name)]" -NoNewline -ForegroundColor (Get-IdentityColor $rule)
        Write-Host " allow:" -NoNewline -ForegroundColor Green
        Write-Host " " -NoNewline
        foreach ($domain in $rule.SenderDomainIs) {
            $d = Format-Domain $domain "White"
            Write-Host "$($d.Text)" -NoNewline -ForegroundColor $d.Color
            Write-Host " " -NoNewline
        }
        Write-Host ""
        Show-RuleJson $rule
    }
    if ($rule.ExceptIfSenderDomainIs) {
        if (-not ($uniqueRules -contains $rule.Name)) { $uniqueRules += $rule.Name }
        Write-Host "- " -NoNewline -ForegroundColor White
        Write-Host "[$($rule.Name)]" -NoNewline -ForegroundColor (Get-IdentityColor $rule)
        Write-Host " deny:" -NoNewline -ForegroundColor DarkYellow
        Write-Host " " -NoNewline
        foreach ($domain in $rule.ExceptIfSenderDomainIs) {
            $d = Format-Domain $domain "White"
            Write-Host "$($d.Text)" -NoNewline -ForegroundColor $d.Color
            Write-Host " " -NoNewline
        }
        Write-Host ""
        Show-RuleJson $rule
    }
}
Write-Host "Total unique rules (Allowed/Deny): $($uniqueRules.Count)" -ForegroundColor White

# --- Domains Susceptible to Domain Fronting ---
Write-Section "Domains Susceptible to Domain Fronting"
$uniqueRules = @()
foreach ($rule in $rules) {
    if ((($rule.PSObject.Properties["Enabled"] -and $rule.Enabled -eq $false) -or ($rule.PSObject.Properties["State"] -and $rule.State -ne "Enabled")) -and (-not $ShowDisabled)) {
        continue
    }
    $domains = @()
    if ($rule.SenderDomainIs) { $domains += $rule.SenderDomainIs }
    if ($rule.ExceptIfSenderDomainIs) { $domains += $rule.ExceptIfSenderDomainIs }
    foreach ($domain in $domains) {
        if (Check-DomainFronting $domain) {
            if (-not ($uniqueRules -contains $rule.Name)) { $uniqueRules += $rule.Name }
            Write-Host "- " -NoNewline -ForegroundColor White
            Write-Host "[$($rule.Name)]" -NoNewline -ForegroundColor (Get-IdentityColor $rule)
            Write-Host " references potentially abused domain:" -NoNewline -ForegroundColor White
            Write-Host " $domain" -ForegroundColor Blue
            Show-RuleJson $rule
        }
    }
}
Write-Host "Total unique rules (Domain Fronting): $($uniqueRules.Count)" -ForegroundColor White

# --- Conflicting Rule Priorities ---
Write-Section "Conflicting Rule Priorities"
$uniqueRules = @()
$priorityMap = @{}
foreach ($rule in $rules) {
    $prio = $rule.Priority
    if (-not $priorityMap.ContainsKey($prio)) { $priorityMap[$prio] = @() }
    $priorityMap[$prio] += $rule.Name
}
foreach ($key in $priorityMap.Keys) {
    if ($priorityMap[$key].Count -gt 1) {
        foreach ($name in $priorityMap[$key]) {
            if (-not ($uniqueRules -contains $name)) { $uniqueRules += $name }
        }
        Write-Host "- Priority $key is shared by rules:" -NoNewline -ForegroundColor Red
        Write-Host " $($priorityMap[$key] -join ', ')" -ForegroundColor Red
    }
}
Write-Host "Total unique rules (Conflicting Priorities): $($uniqueRules.Count)" -ForegroundColor White

# --- Sender IP Ranges Classification ---
Write-Section "Sender IP Ranges Classification"
$uniqueRules = @()
foreach ($rule in $rules) {
    if ((($rule.PSObject.Properties["Enabled"] -and $rule.Enabled -eq $false) -or ($rule.PSObject.Properties["State"] -and $rule.State -ne "Enabled")) -and (-not $ShowDisabled)) {
        continue
    }
    if ($rule.SenderIpRanges) {
        foreach ($ipRange in $rule.SenderIpRanges) {
            $kind = Classify-IP $ipRange
            if ($kind -eq "External") {
                if (-not ($uniqueRules -contains $rule.Name)) { $uniqueRules += $rule.Name }
                Write-Host "- " -NoNewline -ForegroundColor White
                Write-Host "[$($rule.Name)]" -NoNewline -ForegroundColor (Get-IdentityColor $rule)
                Write-Host " includes External IP range:" -NoNewline -ForegroundColor White
                if ($scanASNs) { $asnInfo = Get-ASNForIP $ipRange } else { $asnInfo = "ASN scan disabled" }
                Write-Host " $ipRange (ASN: $asnInfo)" -ForegroundColor Yellow
            }
            else {
                if (-not ($uniqueRules -contains $rule.Name)) { $uniqueRules += $rule.Name }
                Write-Host "- " -NoNewline -ForegroundColor White
                Write-Host "[$($rule.Name)]" -NoNewline -ForegroundColor (Get-IdentityColor $rule)
                Write-Host " includes $kind IP range:" -NoNewline -ForegroundColor White
                if ($scanASNs) { $asnInfo = Get-ASNForIP $ipRange } else { $asnInfo = "ASN scan disabled" }
                $col = if ($kind -eq "Private") { "Green" } else { "Yellow" }
                Write-Host " $ipRange (ASN: $asnInfo)" -ForegroundColor $col
            }
        }
    }
}
Write-Host "Total unique rules (Sender IP Classification): $($uniqueRules.Count)" -ForegroundColor White

# --- No Logging or Incident Reporting ---
Write-Section "No Logging or Incident Reporting"
$uniqueRules = @()
foreach ($rule in $rules) {
    # Only process enabled rules unless -ShowDisabled is set.
    if ((($rule.PSObject.Properties["Enabled"] -and $rule.Enabled -eq $false) -or ($rule.PSObject.Properties["State"] -and $rule.State -ne "Enabled")) -and (-not $ShowDisabled)) {
        continue
    }
    if (-not $rule.GenerateIncidentReport -and -not $rule.AuditSeverity) {
        if (-not ($uniqueRules -contains $rule.Name)) { $uniqueRules += $rule.Name }
        Write-Host "- " -NoNewline -ForegroundColor White
        Write-Host "[$($rule.Name)]" -NoNewline -ForegroundColor (Get-IdentityColor $rule)
        Write-Host " lacks logging/auditing configuration" -NoNewline -ForegroundColor White
        Write-Host " (Risk: Limited visibility)" -ForegroundColor Yellow
        Show-RuleJson $rule
    }
}
Write-Host "Total unique rules (No Logging/Incident Reporting): $($uniqueRules.Count)" -ForegroundColor White

# --- Rules Using Sender IP Predicate (review recommended for potential bypass risks) ---
Write-Section "Rules Using Sender IP Predicate (review recommended for potential bypass risks)"
$uniqueRules = @()
foreach ($rule in $rules) {
    if ((($rule.PSObject.Properties["Enabled"] -and $rule.Enabled -eq $false) -or ($rule.PSObject.Properties["State"] -and $rule.State -ne "Enabled")) -and (-not $ShowDisabled)) {
        continue
    }
    if ($rule.Conditions -and ($rule.Conditions | Where-Object { $_ -like "*SenderIpRangesPredicate*" })) {
        if ($rule.SenderIpRanges) {
            foreach ($ipRange in $rule.SenderIpRanges) {
                $kind = Classify-IP $ipRange
                if ($kind -eq "External") {
                    if (-not ($uniqueRules -contains $rule.Name)) { $uniqueRules += $rule.Name }
                    Write-Host "- " -NoNewline -ForegroundColor White
                    Write-Host "[$($rule.Name)]" -NoNewline -ForegroundColor (Get-IdentityColor $rule)
                    Write-Host " IP Range $ipRange classified as External (ASN: " -NoNewline -ForegroundColor White
                    if ($scanASNs) { $asnInfo = Get-ASNForIP $ipRange } else { $asnInfo = "ASN scan disabled" }
                    Write-Host "$asnInfo)" -ForegroundColor Yellow
                } else {
                    if (-not ($uniqueRules -contains $rule.Name)) { $uniqueRules += $rule.Name }
                    Write-Host "- " -NoNewline -ForegroundColor White
                    Write-Host "[$($rule.Name)]" -NoNewline -ForegroundColor (Get-IdentityColor $rule)
                    Write-Host " IP Range $ipRange classified as $kind (ASN: " -NoNewline -ForegroundColor White
                    if ($scanASNs) { $asnInfo = Get-ASNForIP $ipRange } else { $asnInfo = "ASN scan disabled" }
                    $col = if ($kind -eq "Private") { "Green" } else { "Yellow" }
                    Write-Host "$asnInfo)" -ForegroundColor $col
                }
            }
        }
        else {
            if (-not ($uniqueRules -contains $rule.Name)) { $uniqueRules += $rule.Name }
            Write-Host "- " -NoNewline -ForegroundColor White
            Write-Host "[$($rule.Name)]" -NoNewline -ForegroundColor (Get-IdentityColor $rule)
            Write-Host " has SenderIpRangesPredicate condition(s)" -ForegroundColor Yellow
        }
        Show-RuleJson $rule
    }
}
Write-Host "Total unique rules (Sender IP Predicate): $($uniqueRules.Count)" -ForegroundColor White

# --- Encryption / Rights Protection Enforcement ---
Write-Section "Encryption / Rights Protection Enforcement"
$uniqueRules = @()
foreach ($rule in $rules) {
    if ((($rule.PSObject.Properties["Enabled"] -and $rule.Enabled -eq $false) -or ($rule.PSObject.Properties["State"] -and $rule.State -ne "Enabled")) -and (-not $ShowDisabled)) {
        continue
    }
    if ($rule.ApplyOME -or $rule.ApplyRightsProtectionTemplate) {
        if (-not ($uniqueRules -contains $rule.Name)) { $uniqueRules += $rule.Name }
        Write-Host "- " -NoNewline -ForegroundColor White
        Write-Host "[$($rule.Name)]" -NoNewline -ForegroundColor (Get-IdentityColor $rule)
        Write-Host " applies encryption/IRM (Good practice)" -ForegroundColor Green
        Show-RuleJson $rule
    }
}
Write-Host "Total unique rules (Encryption/IRM): $($uniqueRules.Count)" -ForegroundColor White

# --- SCL Modifications ---
Write-Section "SCL Modifications"
$uniqueRules = @()
foreach ($rule in $rules) {
    if ((($rule.PSObject.Properties["Enabled"] -and $rule.Enabled -eq $false) -or ($rule.PSObject.Properties["State"] -and $rule.State -ne "Enabled")) -and (-not $ShowDisabled)) {
        continue
    }
    if ($null -ne $rule.SetSCL) {
        if (-not ($uniqueRules -contains $rule.Name)) { $uniqueRules += $rule.Name }
        Write-Host "- " -NoNewline -ForegroundColor White
        Write-Host "[$($rule.Name)]" -NoNewline -ForegroundColor (Get-IdentityColor $rule)
        Write-Host " sets SCL to: $($rule.SetSCL)" -NoNewline -ForegroundColor White
        if ($rule.SenderDomainIs) {
            $allowed = ""
            foreach ($domain in $rule.SenderDomainIs) {
                $d = Format-Domain $domain "Green"
                $allowed += "$($d.Text) "
            }
            Write-Host " | Allowed:" -NoNewline -ForegroundColor Green
            Write-Host " $allowed" -NoNewline -ForegroundColor Yellow
        }
        if ($rule.ExceptIfSenderDomainIs) {
            $denied = ""
            foreach ($domain in $rule.ExceptIfSenderDomainIs) {
                $d = Format-Domain $domain "DarkYellow"
                $denied += "$($d.Text) "
            }
            Write-Host " | Denied:" -NoNewline -ForegroundColor DarkYellow
            Write-Host " $denied" -NoNewline -ForegroundColor Yellow
        }
        if ($rule.SenderIpRanges) {
            Write-Host " | IPs:" -NoNewline -ForegroundColor White
            Write-Host " $($rule.SenderIpRanges -join ', ')" -NoNewline -ForegroundColor Yellow
        }
        if ($rule.SetSCL -eq -1) {
            Write-Host " (SCL -1 bypasses spam filtering - High risk)" -ForegroundColor Red
        } else {
            Write-Host " (SCL indicates the spam confidence level applied)" -ForegroundColor White
        }
        Show-RuleJson $rule
    }
}
Write-Host "Total unique rules (SCL Modifications): $($uniqueRules.Count)" -ForegroundColor White

# --- HTML Disclaimer Rules ---
Write-Section "HTML Disclaimer Rules"
$uniqueRules = @()
foreach ($rule in $rules) {
    if ((($rule.PSObject.Properties["Enabled"] -and $rule.Enabled -eq $false) -or ($rule.PSObject.Properties["State"] -and $rule.State -ne "Enabled")) -and (-not $ShowDisabled)) {
        continue
    }
    if ($rule.ApplyHtmlDisclaimerText) {
        if (-not ($uniqueRules -contains $rule.Name)) { $uniqueRules += $rule.Name }
        $loc = if ($rule.ApplyHtmlDisclaimerLocation) { $rule.ApplyHtmlDisclaimerLocation } else { "Unknown" }
        $fb = if ($rule.ApplyHtmlDisclaimerFallbackAction) { $rule.ApplyHtmlDisclaimerFallbackAction } else { "Unknown" }
        $cleaned = Strip-HTML $rule.ApplyHtmlDisclaimerText
        if ($loc -eq "Ignore" -or $loc -eq "Wrap") { $locColor = "Yellow" } else { $locColor = "White" }
        if ($fb -eq "Ignore" -or $fb -eq "Wrap") { $fbColor = "Yellow" } else { $fbColor = "White" }
        Write-Host "- " -NoNewline -ForegroundColor White
        Write-Host "[$($rule.Name)]" -NoNewline -ForegroundColor (Get-IdentityColor $rule)
        Write-Host " disclaimer at " -NoNewline -ForegroundColor White
        Write-Host "$loc" -NoNewline -ForegroundColor $locColor
        Write-Host " | fallback: " -NoNewline -ForegroundColor White
        Write-Host "$fb" -ForegroundColor $fbColor
        Write-Host "  >>> `"$cleaned`""
        Show-RuleJson $rule
    }
}
Write-Host "Total unique rules (HTML Disclaimer): $($uniqueRules.Count)" -ForegroundColor White

# --- Header Modification Rules ---
Write-Section "Header Modification Rules"
$uniqueRules = @()
foreach ($rule in $rules) {
    if ($rule.SetHeaderName -or $rule.SetHeaderValue -or $rule.RemoveHeader) {
        if (-not ($uniqueRules -contains $rule.Name)) { $uniqueRules += $rule.Name }
        $line = "- " + "[$($rule.Name)]" + " modifies headers:"
        if ($rule.SetHeaderName -and $rule.SetHeaderValue) {
            $line += " Sets [$($rule.SetHeaderName)] to [$($rule.SetHeaderValue)]"
        }
        if ($rule.RemoveHeader) {
            $line += " Removes header [$($rule.RemoveHeader)]"
        }
        Write-Host $line -ForegroundColor White
        Show-RuleJson $rule
    }
}
Write-Host "Total unique rules (Header Modification): $($uniqueRules.Count)" -ForegroundColor White

# --- Subject or Body Modifications ---
Write-Section "Subject or Body Modifications"
$uniqueRules = @()
foreach ($rule in $rules) {
    if ($rule.PrependSubject -or $rule.PrependBody) {
        if (-not ($uniqueRules -contains $rule.Name)) { $uniqueRules += $rule.Name }
        Write-Host "- " -NoNewline -ForegroundColor White
        Write-Host "[$($rule.Name)]" -NoNewline -ForegroundColor (Get-IdentityColor $rule)
        Write-Host " prepends content to subject/body (Check consistency)" -ForegroundColor Yellow
        Show-RuleJson $rule
    }
}
Write-Host "Total unique rules (Subject/Body Modification): $($uniqueRules.Count)" -ForegroundColor White

# --- Overly Permissive Rules (SCL = -1) ---
Write-Section "Overly Permissive Rules (SCL = -1)"
$uniqueRules = @()
foreach ($rule in $rules) {
    # Skip disabled rules unless -ShowDisabled is used.
    if ((($rule.PSObject.Properties["Enabled"] -and $rule.Enabled -eq $false) -or ($rule.PSObject.Properties["State"] -and $rule.State -ne "Enabled")) -and (-not $ShowDisabled)) {
        continue
    }
    if ($rule.SetSCL -eq -1) {
        if (-not ($uniqueRules -contains $rule.Name)) { $uniqueRules += $rule.Name }
        Write-Host "- " -NoNewline -ForegroundColor White
        Write-Host "[$($rule.Name)]" -NoNewline -ForegroundColor (Get-IdentityColor $rule)
        Write-Host " bypasses spam filtering (Triggered by: SetSCL = -1)" -ForegroundColor Red
        Show-RuleJson $rule
    }
}
Write-Host "Total unique rules (Overly Permissive): $($uniqueRules.Count)" -ForegroundColor White

# --- Rules That May Need Disclaimers or Stamping (External Sources) ---
Write-Section "Rules That May Need Disclaimers or Stamping (External Sources)"
$uniqueRules = @()
foreach ($rule in $rules) {
    # Skip disabled rules unless -ShowDisabled is used.
    if ((($rule.PSObject.Properties["Enabled"] -and $rule.Enabled -eq $false) -or ($rule.PSObject.Properties["State"] -and $rule.State -ne "Enabled")) -and (-not $ShowDisabled)) {
        continue
    }
    if (-not $rule.ApplyHtmlDisclaimerText -and -not $rule.PrependSubject -and -not $rule.PrependBody) {
        $externalList = @()
        if ($rule.SenderDomainIs) {
            foreach ($d in $rule.SenderDomainIs) {
                $formatted = Format-Domain $d "White"
                $externalList += $formatted
            }
        }
        if ($rule.SenderIpRanges) {
            foreach ($ip in $rule.SenderIpRanges) {
                if (Classify-IP $ip -eq "External") {
                    $externalList += @{ Text = $ip; Color = "Yellow" }
                }
            }
        }
        if ($externalList.Count -gt 0) {
            if (-not ($uniqueRules -contains $rule.Name)) { $uniqueRules += $rule.Name }
            Write-Host "- " -NoNewline -ForegroundColor White
            Write-Host "[$($rule.Name)]" -NoNewline -ForegroundColor (Get-IdentityColor $rule)
            Write-Host " has no stamping and targets external sources: " -NoNewline -ForegroundColor White
            $first = $true
            foreach ($item in $externalList) {
                if (-not $first) { Write-Host ", " -NoNewline -ForegroundColor White }
                Write-Host "$($item.Text)" -NoNewline -ForegroundColor $item.Color
                $first = $false
            }
            Write-Host ""
            Show-RuleJson $rule
        }
    }
}
Write-Host "Total unique rules (Stamping issues): $($uniqueRules.Count)" -ForegroundColor White
