# Red Toys

## CAUTION

- **I vibe coded this project. Use at your own risk**

## Overview

Red Toys is a collection of custom PowerShell and Bash scripts designed to automate and streamline Red Team tasks, focusing on enumeration, credential discovery, and post-exploitation activities during authorized security assessments. These scripts assist penetration testers in reconnaissance, privilege escalation, and lateral movement discovery.

### Included Scripts

- **LHF_collector.ps1**: Scans Windows systems for common credential storage locations including browsers, Windows Credential Manager, SSH keys, configuration files, and more.

## Prerequisites

- PowerShell 5.1 or later (for Windows scripts)
- Bash 4.0 or later (for Linux scripts)
- Appropriate permissions for target system access
- **Written authorization** for security testing activities

## ⚠️ Legal Disclaimer

**IMPORTANT:** These scripts are provided for educational purposes and authorized security testing only.

- Only use these tools on systems you own or have explicit written permission to test
- Unauthorized access to computer systems is illegal
- The authors assume no liability for misuse of these tools
- Always ensure you have proper authorization before conducting any security testing

## Usage

### LHF_collector.ps1

**Low-Hanging Fruit Credential Collector** - Scans Windows systems for potential credential storage locations.

```powershell
.\LHF_collector.ps1 [-Verbose] [-OutputFile <output_filename>]

# Basic scan with default output
.\LHF_collector.ps1

# Verbose output with custom filename
.\LHF_collector.ps1 -Verbose -OutputFile "scan_results.txt"

# Quick scan with minimal output
.\LHF_collector.ps1 -OutputFile "quick_scan.txt"
```