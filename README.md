# MTR-Analyser - Exchange Online Transport Rules Audit Script

A PowerShell script that analyses Mail Transport Rules leveraging the Exchange Online PowerShell Module.

## Overview

This PowerShell script connects to Exchange Online, retrieves and audits Mail Transport Rules (MTRs), and provides detailed, color-coded analysis and recommendations. It's specifically designed to enhance visibility, security auditing, and compliance by identifying potentially insecure configurations, rule conflicts, domain fronting risks, and other best practice deviations.

## Features

- Connects securely to Exchange Online with interactive authentication.
- Audits rules for:
  - Enabled/disabled status
  - Allowed and denied sender domains
  - Domains susceptible to domain fronting attacks
  - Rule priority conflicts
  - IP range classification (Internal/External)
  - Logging and incident reporting configurations
  - Spam Confidence Level (SCL) modifications
  - HTML disclaimers
  - Header, subject, and body modifications
  - Overly permissive rules
  - Rules lacking proper disclaimers or stamping for external sources
- Optional verbose output with step-by-step review.
- ASN scanning for external IPs via HackerTarget API (Don't get rate-limited!).
- Allows submission of trusted domains and suspicious domains lists for easy highlighting.

## Installation

Clone or download the script from this repository:

```shell
git clone https://github.com/JumpsecLabs/MTR-Analyser.git
```

## Prerequisites

- **Exchange Online PowerShell module:**
  ```shell
  Install-Module ExchangeOnlineManagement
  ```

- **PowerShell Execution Policy:**
  ```shell
  Set-ExecutionPolicy RemoteSigned
  ```

---

## Usage

Run the script in PowerShell:

```powershell
.\Exchange-MTRAnalyser.ps1 [-ShowDisabled] [-Verbose]
```

### Parameters:

| Parameter      | Description                                           |
|----------------|-------------------------------------------------------|
| `-ShowDisabled`| Include disabled rules in all audit sections          |
| `-Verbose`     | Verbose output with optional step-by-step pausing     |

### Example:

```powershell
.\Exchange-MTRAnalyser.ps1 -ShowDisabled -Verbose
```

You will be interactively prompted for:
- Exchange Online credentials (UPN)
- Optional ASN scanning
- Paths for trusted domains and domain fronting lists (if available)

## Output Legend

| Color       | Meaning                            |
|-------------|------------------------------------|
| DarkRed     | Disabled rules                     |
| Cyan        | Enabled rules                      |
| Green       | Allowed domains                    |
| DarkYellow  | Denied domains                     |
| Magenta     | Trusted domains                    |
| Blue        | Domains susceptible to fronting    |
| Yellow      | Warnings and fallback conditions   |
| Red         | Critical security risks            |

## Author

Made by **Fr4n** @JUMPSEC

## Licence

Distributed under the MIT Licence. See `LICENSE` for more information.

