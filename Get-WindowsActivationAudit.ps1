# Get-WindowsActivationAudit.ps1
# Version: 2.0.0
# Purpose: Comprehensive audit of Windows OS licensing on ANY Windows device.
#          Determines the edition (Enterprise, Pro, LTSC, IoT), HOW it was
#          licensed (M365 subscription, KMS, MAK, OEM/OA3, digital entitlement),
#          and WHY it is in that state. Outputs a text report to Azure Blob Storage.
# Target:  All Windows 10/11 devices — Enterprise, Professional, LTSC, IoT
# Runtime: PowerShell 5.1+
# Usage:   Deploy via Intune Win32, SCCM task sequence, or run locally as SYSTEM/admin.

# ============================================================================
# CONFIGURATION
# ============================================================================

$BlobBaseUrl = 'https://ldinfraopsintunesto8725.blob.core.windows.net/windows-activation-details'
$SasToken    = '?sv=2025-07-05&spr=https&st=2026-04-08T16%3A34%3A48Z&se=2031-10-15T16%3A34%3A00Z&sr=c&sp=racwdlf&sig=nSkih5KJGKEEnhhyVLx6ibbFHND1Xq27ToxRyAvP6wk%3D'

# ============================================================================
# COLLECTION
# ============================================================================

$computerName = $env:COMPUTERNAME
$timestamp    = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$fileName     = "WinLicenseAudit_${computerName}_${timestamp}.txt"
$localPath    = Join-Path $env:TEMP $fileName
$lines        = [System.Collections.Generic.List[string]]::new()

function Add-Line {
    param([string]$Text)
    $lines.Add($Text)
    Write-Host "[INFO] $Text"
}

# Collect all findings for the summary engine
$findings = @{
    Edition           = ''
    EditionId         = ''
    IsEnterprise      = $false
    IsPro             = $false
    IsLTSC            = $false
    IsIoT             = $false
    IsSubscription    = $false
    IsKMS             = $false
    IsMAK             = $false
    IsOEM             = $false
    IsRetail          = $false
    IsDigitalLicense  = $false
    HasOA3Key         = $false
    LicenseStatus     = ''
    LicenseChannel    = ''
    LicenseFamily     = ''
    LicenseDesc       = ''
    KMSServer         = ''
    KMSDiscovered     = ''
    AzureADJoined     = $false
    AzureADTenantName = ''
    UserUPN           = ''
    UserDisplayName   = ''
}

Add-Line '============================================================'
Add-Line "Windows Licensing & Activation Audit - $computerName"
Add-Line "Collected: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC$(if ((Get-Date).Kind -ne 'Utc') { ' (local)' })"
Add-Line '============================================================'
Add-Line ''

# ============================================================================
# SECTION 1 — HARDWARE IDENTITY
# ============================================================================
Add-Line '--- HARDWARE IDENTITY ---'
try {
    $bios = Get-WmiObject -Class Win32_BIOS -ErrorAction Stop
    $cs   = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
    $bb   = Get-WmiObject -Class Win32_BaseBoard -ErrorAction Stop

    Add-Line "Manufacturer:    $($cs.Manufacturer)"
    Add-Line "Model:           $($cs.Model)"
    Add-Line "Serial Number:   $($bios.SerialNumber)"
    Add-Line "BIOS Version:    $($bios.SMBIOSBIOSVersion)"
    Add-Line "Baseboard:       $($bb.Manufacturer) $($bb.Product)"
} catch {
    Add-Line "[ERROR] Failed to retrieve hardware info: $_"
}
Add-Line ''

# ============================================================================
# SECTION 2 — OPERATING SYSTEM EDITION DETECTION
# ============================================================================
Add-Line '--- OPERATING SYSTEM ---'
try {
    $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
    Add-Line "Caption:         $($os.Caption)"
    Add-Line "Version:         $($os.Version)"
    Add-Line "Build:           $($os.BuildNumber)"
    Add-Line "OS Architecture: $($os.OSArchitecture)"

    $editionId   = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction SilentlyContinue).EditionID
    $productName = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName -ErrorAction SilentlyContinue).ProductName
    $buildLabEx  = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name BuildLabEx -ErrorAction SilentlyContinue).BuildLabEx
    $ubr         = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR -ErrorAction SilentlyContinue).UBR
    $displayVer  = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name DisplayVersion -ErrorAction SilentlyContinue).DisplayVersion

    Add-Line "EditionID:       $editionId"
    Add-Line "ProductName:     $productName"
    Add-Line "Display Version: $displayVer"
    Add-Line "Full Build:      $($os.BuildNumber).$ubr"

    $findings.EditionId = $editionId
    $findings.Edition   = $productName

    # Classify edition
    if ($editionId -match 'IoT') {
        $findings.IsIoT = $true
        Add-Line "IoT Edition:     YES"
    }
    if ($editionId -match 'EnterpriseS' -or $productName -match 'LTSC|LTSB') {
        $findings.IsLTSC = $true
        Add-Line "LTSC/LTSB:       YES"
    }
    if ($editionId -match '^Enterprise' -and $editionId -notmatch 'EnterpriseS') {
        $findings.IsEnterprise = $true
        Add-Line "Enterprise:      YES"
    }
    if ($editionId -match 'Professional' -or $editionId -eq 'Pro') {
        $findings.IsPro = $true
        Add-Line "Professional:    YES"
    }
    # IoT + Enterprise but not LTSC is still enterprise-class
    if ($findings.IsIoT -and ($editionId -match 'Enterprise') -and -not $findings.IsLTSC) {
        $findings.IsEnterprise = $true
    }
} catch {
    Add-Line "[ERROR] Failed to retrieve OS info: $_"
}
Add-Line ''

# ============================================================================
# SECTION 3 — OA3 FIRMWARE-EMBEDDED KEY (BIOS/UEFI)
# ============================================================================
Add-Line '--- OA3 FIRMWARE KEY CHECK ---'
try {
    $sls = Get-WmiObject -Query 'SELECT OA3xOriginalProductKey FROM SoftwareLicensingService' -ErrorAction Stop
    $oa3Key = $sls.OA3xOriginalProductKey

    if ($oa3Key -and $oa3Key.Trim().Length -gt 0) {
        $maskedKey = 'XXXXX-XXXXX-XXXXX-XXXXX-' + $oa3Key.Substring($oa3Key.Length - 5)
        $findings.HasOA3Key = $true
        Add-Line "OA3 Key Present: YES"
        Add-Line "OA3 Key (masked): $maskedKey"
        Add-Line "MEANING:         The OEM burned a Windows product key into the device firmware."
        Add-Line "                 This key survives OS reinstalls on the same hardware."
    } else {
        Add-Line "OA3 Key Present: NO"
        Add-Line "MEANING:         No embedded OEM key in firmware. License came from another source."
    }
} catch {
    Add-Line "[ERROR] Failed to query OA3 key: $_"
}
Add-Line ''

# ============================================================================
# SECTION 4 — ACTIVATION STATUS & LICENSE CHANNEL (Core Detection)
# ============================================================================
Add-Line '--- ACTIVATION STATUS & LICENSE DETAILS ---'
$winProduct = $null
try {
    $slProducts = Get-WmiObject -Query "SELECT * FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL" -ErrorAction Stop

    foreach ($slp in $slProducts) {
        if ($slp.ApplicationId -eq '55c92734-d682-4d71-983e-d6ec3f16059f') {
            $winProduct = $slp

            $statusMap = @{
                0 = 'Unlicensed'
                1 = 'Licensed (Activated)'
                2 = 'OOBGrace (Out-of-Box Grace Period)'
                3 = 'OOTGrace (Out-of-Tolerance Grace Period)'
                4 = 'NonGenuineGrace'
                5 = 'Notification (Not Genuine)'
                6 = 'ExtendedGrace'
            }
            $statusText = $statusMap[[int]$slp.LicenseStatus]
            if (-not $statusText) { $statusText = "Unknown ($($slp.LicenseStatus))" }
            $findings.LicenseStatus = $statusText

            Add-Line "Product Name:         $($slp.Name)"
            Add-Line "Description:          $($slp.Description)"
            Add-Line "License Status:       $statusText"
            Add-Line "Partial Product Key:  XXXXX-$($slp.PartialProductKey)"
            Add-Line "Product Key Channel:  $($slp.ProductKeyChannel)"
            Add-Line "License Family:       $($slp.LicenseFamily)"
            Add-Line "Grace Period (min):   $($slp.GracePeriodRemaining)"
            Add-Line "Remaining Rearms:     $($slp.RemainingSkuReArmCount)"

            $findings.LicenseChannel = $slp.ProductKeyChannel
            $findings.LicenseFamily  = $slp.LicenseFamily
            $findings.LicenseDesc    = $slp.Description

            # --- Detect activation method from channel ---
            $channel = $slp.ProductKeyChannel
            switch -Regex ($channel) {
                'OEM_DM'     {
                    $findings.IsOEM = $true
                    Add-Line "Activation Method:    OEM:DM (OEM pre-activated via Digital Marker in firmware)"
                }
                'OEM'        {
                    $findings.IsOEM = $true
                    Add-Line "Activation Method:    OEM (factory-installed key from hardware vendor)"
                }
                'Retail'     {
                    $findings.IsRetail = $true
                    Add-Line "Activation Method:    Retail (individually purchased product key)"
                }
                'Volume:MAK' {
                    $findings.IsMAK = $true
                    Add-Line "Activation Method:    MAK (Multiple Activation Key — one-time activation against Microsoft)"
                }
                'Volume:GVLK' {
                    $findings.IsKMS = $true
                    Add-Line "Activation Method:    KMS Client (Generic Volume License Key — activates against a KMS server)"
                }
                'Volume'     {
                    Add-Line "Activation Method:    Volume License ($channel)"
                    if ($slp.Description -match 'KMS') { $findings.IsKMS = $true }
                    elseif ($slp.Description -match 'MAK') { $findings.IsMAK = $true }
                }
                default      {
                    Add-Line "Activation Method:    $channel"
                }
            }

            # --- KMS-specific details ---
            if ($slp.KeyManagementServiceMachine) {
                $findings.KMSServer = "$($slp.KeyManagementServiceMachine):$($slp.KeyManagementServicePort)"
                Add-Line "KMS Server (config):  $($findings.KMSServer)"
            }
            if ($slp.DiscoveredKeyManagementServiceMachineName) {
                $findings.KMSDiscovered = "$($slp.DiscoveredKeyManagementServiceMachineName):$($slp.DiscoveredKeyManagementServiceMachinePort)"
                Add-Line "KMS Server (SRV):     $($findings.KMSDiscovered)"
            }
            if ($slp.VLActivationInterval -and $slp.VLActivationInterval -gt 0) {
                Add-Line "KMS Renew Interval:   $($slp.VLActivationInterval) minutes"
            }
            if ($slp.VLRenewalInterval -and $slp.VLRenewalInterval -gt 0) {
                Add-Line "KMS Validity Period:  $($slp.VLRenewalInterval) minutes"
            }
            if ($slp.KeyManagementServiceProductKeyID) {
                Add-Line "KMS PKey ID:          $($slp.KeyManagementServiceProductKeyID)"
            }

            # --- Subscription / M365 Cloud Activation Detection ---
            if ($slp.LicenseFamily -match 'Subscription' -or
                $slp.Description -match 'Subscription' -or
                $slp.Name -match 'Subscription') {
                $findings.IsSubscription = $true
                Add-Line "Subscription License: YES — This device is activated via a cloud subscription"
            }
        }
    }

    if (-not $winProduct) {
        Add-Line "[WARN] No active Windows licensing product found with a partial product key."
    }
} catch {
    Add-Line "[ERROR] Failed to query activation status: $_"
}
Add-Line ''

# ============================================================================
# SECTION 5 — M365 / SUBSCRIPTION ACTIVATION DEEP DIVE
# ============================================================================
Add-Line '--- M365 / SUBSCRIPTION ACTIVATION CHECK ---'
try {
    # Check registry for Windows 10/11 Subscription Activation (SA) state
    $subRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ClipSVC\Volatile\PersistedSystemState'
    $subState = $null
    if (Test-Path $subRegPath) {
        $subState = Get-ItemProperty -Path $subRegPath -ErrorAction SilentlyContinue
        Add-Line "Subscription State Store: Present"
    }

    # Check for the Windows Enterprise E3/E5 subscription activation
    $saRegPath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\WindowsLicensing'
    if (Test-Path $saRegPath) {
        $saPolicy = Get-ItemProperty -Path $saRegPath -ErrorAction SilentlyContinue
        if ($saPolicy.SubscriptionType -ne $null) {
            Add-Line "Subscription Type:    $($saPolicy.SubscriptionType)"
        }
        if ($saPolicy.SubscriptionStatus -ne $null) {
            Add-Line "Subscription Status:  $($saPolicy.SubscriptionStatus)"
        }
    }

    # Another indicator: the Edition Upgrade CSP leaves breadcrumbs
    $upgradeRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $edUpgrade = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionSubstring -ErrorAction SilentlyContinue).EditionSubstring
    if ($edUpgrade) {
        Add-Line "Edition Substring:    $edUpgrade"
    }

    # License family is the most reliable subscription indicator
    if ($findings.LicenseFamily -match 'Subscription|sub') {
        $findings.IsSubscription = $true
        Add-Line "LICENSE FAMILY:       $($findings.LicenseFamily)"
        Add-Line "CONCLUSION:           This device is running Enterprise via M365 Subscription Activation."
        Add-Line "                      The user's M365 E3/E5/A3/A5 license entitles Pro -> Enterprise upgrade."
    }

    # Check if the device has a GVLK for an Enterprise Subscription edition
    if ($winProduct -and $winProduct.Description -match 'VOLUME_MAK.*Enterprise' -and $findings.IsSubscription) {
        Add-Line "NOTE:                 Enterprise subscription activated via cloud M365 entitlement."
    }

    if (-not $findings.IsSubscription) {
        Add-Line "Subscription Activation: NOT DETECTED"
        Add-Line "                      This device is NOT using M365 subscription activation."
    }
} catch {
    Add-Line "[ERROR] Failed to check subscription activation: $_"
}
Add-Line ''

# ============================================================================
# SECTION 6 — AZURE AD / ENTRA JOIN STATUS & USER IDENTITY
# ============================================================================
Add-Line '--- AZURE AD / ENTRA ID JOIN STATUS ---'
try {
    # Run dsregcmd and parse output (works on all Windows 10/11 builds)
    $dsregOutput = & dsregcmd /status 2>&1 | Out-String

    # Azure AD Join
    if ($dsregOutput -match 'AzureAdJoined\s*:\s*YES') {
        $findings.AzureADJoined = $true
        Add-Line "Azure AD Joined:     YES"
    } elseif ($dsregOutput -match 'AzureAdJoined\s*:\s*NO') {
        Add-Line "Azure AD Joined:     NO"
    }

    # Hybrid join
    if ($dsregOutput -match 'DomainJoined\s*:\s*YES') {
        Add-Line "AD Domain Joined:    YES"
    }

    # Tenant info
    if ($dsregOutput -match 'TenantName\s*:\s*(.+)') {
        $findings.AzureADTenantName = $Matches[1].Trim()
        Add-Line "Tenant Name:         $($findings.AzureADTenantName)"
    }
    if ($dsregOutput -match 'TenantId\s*:\s*(.+)') {
        Add-Line "Tenant ID:           $($Matches[1].Trim())"
    }

    # MDM enrollment (Intune)
    if ($dsregOutput -match 'MdmUrl\s*:\s*(.+)') {
        Add-Line "MDM (Intune) URL:    $($Matches[1].Trim())"
    }
} catch {
    Add-Line "[ERROR] Failed to run dsregcmd: $_"
}
Add-Line ''

# ============================================================================
# SECTION 7 — LOGGED-IN USER UPN (Critical for Pro -> Enterprise diagnosis)
# ============================================================================
Add-Line '--- LOGGED-IN USER IDENTITY ---'
try {
    # Method 1: Query the explorer.exe owner (interactive session user)
    $interactiveUser = $null
    try {
        # Use Get-CimInstance + Invoke-CimMethod which works in PS 5.1 and PS 7+
        $explorerProcs = Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue
        if ($explorerProcs) {
            foreach ($proc in $explorerProcs) {
                $owner = Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction SilentlyContinue
                if ($owner -and $owner.ReturnValue -eq 0) {
                    $interactiveUser = "$($owner.Domain)\$($owner.User)"
                    Add-Line "Interactive User:    $interactiveUser"
                    break
                }
            }
        }
    } catch {
        # Fallback for older systems: try quser
        try {
            $quserOutput = & quser 2>&1 | Out-String
            if ($quserOutput -match '>\s*(\S+)') {
                $interactiveUser = $Matches[1]
                Add-Line "Interactive User:    $interactiveUser (via quser)"
            }
        } catch { }
    }

    # Method 2: Get UPN from Azure AD token cache / dsregcmd SSO state
    $upn = $null

    # Try dsregcmd SSO state for UPN
    $dsregSSO = & dsregcmd /status 2>&1 | Out-String
    if ($dsregSSO -match 'UserEmail\s*:\s*(\S+@\S+)') {
        $upn = $Matches[1].Trim()
    }

    # Fallback: registry cached identity
    if (-not $upn) {
        $identityPath = 'HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache'
        if (Test-Path $identityPath) {
            $idSubkeys = Get-ChildItem $identityPath -Recurse -ErrorAction SilentlyContinue |
                Get-ItemProperty -ErrorAction SilentlyContinue |
                Where-Object { $_.UserName -match '@' } |
                Select-Object -First 1
            if ($idSubkeys) {
                $upn = $idSubkeys.UserName
            }
        }
    }

    # Fallback: whoami /upn
    if (-not $upn) {
        try {
            $upnResult = & whoami /upn 2>&1
            if ($upnResult -match '@') { $upn = $upnResult.Trim() }
        } catch { }
    }

    # Fallback: CloudAP cached user
    if (-not $upn) {
        $cloudApPath = 'HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache'
        if (Test-Path $cloudApPath) {
            $cloudUpn = Get-ChildItem $cloudApPath -Recurse -ErrorAction SilentlyContinue |
                Get-ItemProperty -ErrorAction SilentlyContinue |
                Where-Object { $_.IdentityName -match '@' } |
                Select-Object -ExpandProperty IdentityName -First 1 -ErrorAction SilentlyContinue
            if ($cloudUpn) { $upn = $cloudUpn }
        }
    }

    if ($upn) {
        $findings.UserUPN = $upn
        Add-Line "User UPN:            $upn"
    } else {
        Add-Line "User UPN:            COULD NOT BE DETERMINED"
        if ($interactiveUser) {
            Add-Line "                     Logged-in user is '$interactiveUser' but no Azure AD UPN was found."
            Add-Line "                     This may indicate the user has not signed in with an M365 account."
        }
    }
} catch {
    Add-Line "[ERROR] Failed to determine user identity: $_"
}
Add-Line ''

# ============================================================================
# SECTION 8 — DIGITAL LICENSE / ENTITLEMENT CHECK
# ============================================================================
Add-Line '--- DIGITAL LICENSE CHECK ---'
try {
    $entitlementStore = 'HKLM:\SYSTEM\CurrentControlSet\Control\{7746D80F-97E0-4E26-9543-26B41FC22F79}\{A25AE4F2-1B96-4CED-8007-AA30E9B1A218}'
    if (Test-Path $entitlementStore) {
        $findings.IsDigitalLicense = $true
        Add-Line "Digital License Store: Present"
        Add-Line "MEANING:              Device has a digital entitlement (HWID-based license from Microsoft)."
    } else {
        Add-Line "Digital License Store: Not found"
    }

    $clipSvc = Get-Service -Name ClipSVC -ErrorAction SilentlyContinue
    if ($clipSvc) {
        Add-Line "ClipSVC Status:       $($clipSvc.Status)"
    }
} catch {
    Add-Line "[ERROR] Failed to check digital license: $_"
}
Add-Line ''

# ============================================================================
# SECTION 9 — KMS vs MAK DETAILED EXPLANATION
# ============================================================================
Add-Line '--- KMS / MAK ACTIVATION DETAILS ---'
if ($findings.IsKMS) {
    Add-Line "ACTIVATION TYPE:     KMS (Key Management Service)"
    Add-Line ""
    Add-Line "HOW IT WORKS:"
    Add-Line "  - The device has a Generic Volume License Key (GVLK) installed."
    Add-Line "  - It contacts a KMS host server (on-premises or via DNS SRV records) to activate."
    Add-Line "  - Activation is valid for 180 days and the device must renew by contacting KMS."
    Add-Line "  - If the device cannot reach KMS for 180 days, it enters grace/unlicensed state."
    if ($findings.KMSServer) {
        Add-Line "  - KMS server (manually configured): $($findings.KMSServer)"
    }
    if ($findings.KMSDiscovered) {
        Add-Line "  - KMS server (auto-discovered via DNS _vlmcs._tcp SRV): $($findings.KMSDiscovered)"
    }
    if (-not $findings.KMSServer -and -not $findings.KMSDiscovered) {
        Add-Line "  - [WARN] No KMS server discovered. Device may fail to renew activation."
    }
    Add-Line ""
    Add-Line "WHY THIS DEVICE USES KMS:"
    Add-Line "  - The organization deploys a GVLK via imaging, GPO, or MDM policy."
    Add-Line "  - This is typical for domain-joined enterprise PCs managed centrally."
}
elseif ($findings.IsMAK) {
    Add-Line "ACTIVATION TYPE:     MAK (Multiple Activation Key)"
    Add-Line ""
    Add-Line "HOW IT WORKS:"
    Add-Line "  - A unique Volume License key was entered on this device."
    Add-Line "  - The device activated ONCE against Microsoft activation servers."
    Add-Line "  - MAK activation is permanent for the hardware — no renewal needed."
    Add-Line "  - Each MAK key has a limited number of activations (count tracked by Microsoft)."
    Add-Line ""
    Add-Line "WHY THIS DEVICE USES MAK:"
    Add-Line "  - MAK is used when devices cannot regularly reach a KMS server."
    Add-Line "  - Common for disconnected, air-gapped, or low-count deployments."
}
elseif ($findings.IsOEM) {
    Add-Line "ACTIVATION TYPE:     OEM (Original Equipment Manufacturer)"
    Add-Line ""
    Add-Line "HOW IT WORKS:"
    if ($findings.HasOA3Key) {
        Add-Line "  - The device manufacturer (OEM) embedded a product key in UEFI/BIOS firmware."
        Add-Line "  - Windows reads this OA3 key at install time and auto-activates."
        Add-Line "  - The key is tied to the hardware and survives OS reinstalls."
    } else {
        Add-Line "  - The OEM pre-activated Windows at the factory."
        Add-Line "  - No firmware key was found — the activation may have used an OEM SLP key"
        Add-Line "    or a COA sticker on the device chassis."
    }
}
elseif ($findings.IsRetail) {
    Add-Line "ACTIVATION TYPE:     Retail"
    Add-Line ""
    Add-Line "HOW IT WORKS:"
    Add-Line "  - An individually purchased product key was entered on this device."
    Add-Line "  - Retail keys can be transferred to different hardware (one active device at a time)."
}
else {
    Add-Line "ACTIVATION TYPE:     Could not classify from available data."
    if ($winProduct) {
        Add-Line "Channel reported:    $($findings.LicenseChannel)"
        Add-Line "Description:         $($findings.LicenseDesc)"
    }
}
Add-Line ''

# ============================================================================
# SECTION 10 — COMPREHENSIVE ANALYSIS & VERDICT
# ============================================================================
Add-Line '============================================================'
Add-Line 'ANALYSIS & VERDICT'
Add-Line '============================================================'
Add-Line ''

# --- ENTERPRISE ---
if ($findings.IsEnterprise -and -not $findings.IsLTSC) {
    Add-Line "EDITION:  Windows Enterprise"
    Add-Line ''
    if ($findings.IsSubscription) {
        Add-Line "WHY ENTERPRISE:"
        Add-Line "  This device is running Enterprise via M365 SUBSCRIPTION ACTIVATION."
        Add-Line "  A qualifying M365 E3/E5/A3/A5 or Windows Enterprise E3/E5 license assigned"
        Add-Line "  to a user causes an eligible Windows Pro device to automatically upgrade"
        Add-Line "  to Enterprise when that user signs in."
        Add-Line ''
        Add-Line "  REQUIREMENTS FOR THIS TO WORK:"
        Add-Line "    1. Device must be Azure AD joined (or Hybrid Azure AD joined)."
        Add-Line "    2. Device must start as Windows 10/11 Pro (or Pro for Workstations/Education)."
        Add-Line "    3. User must have an M365 E3/E5 (or equivalent) license in Entra ID."
        Add-Line "    4. User signs in -> ClipSVC fetches a subscription entitlement from Microsoft."
        Add-Line ''
        if ($findings.UserUPN) {
            Add-Line "  LICENSED USER:  $($findings.UserUPN)"
            Add-Line "  This user's M365 license is providing the Enterprise entitlement."
        }
        if ($findings.AzureADTenantName) {
            Add-Line "  TENANT:         $($findings.AzureADTenantName)"
        }
        Add-Line ''
        Add-Line "  RISK: If the user's M365 license is removed or the user signs out for an"
        Add-Line "        extended period, the device may revert to Windows Pro."
    }
    elseif ($findings.IsKMS) {
        Add-Line "WHY ENTERPRISE:"
        Add-Line "  This device was deployed with a KMS client key (GVLK) for Windows Enterprise."
        Add-Line "  It activates against your organization's KMS infrastructure."
        Add-Line "  This is a traditional Volume License deployment — NOT M365 subscription."
    }
    elseif ($findings.IsMAK) {
        Add-Line "WHY ENTERPRISE:"
        Add-Line "  This device was activated with a MAK key for Windows Enterprise."
        Add-Line "  This is a one-time Volume License activation — NOT M365 subscription."
    }
    else {
        Add-Line "WHY ENTERPRISE:"
        Add-Line "  Channel: $($findings.LicenseChannel)"
        Add-Line "  The specific mechanism could not be definitively classified."
        Add-Line "  Review the ACTIVATION STATUS section above for details."
    }
}

# --- PROFESSIONAL ---
elseif ($findings.IsPro) {
    Add-Line "EDITION:  Windows Professional"
    Add-Line ''
    Add-Line "WHY THIS DEVICE IS PRO (NOT ENTERPRISE):"
    Add-Line ''
    if ($findings.UserUPN) {
        Add-Line "  Logged-in user UPN: $($findings.UserUPN)"
        Add-Line ''
        Add-Line "  POSSIBLE REASONS IT IS NOT ENTERPRISE:"
        Add-Line "    1. The user ($($findings.UserUPN)) may not have an M365 E3/E5 license assigned."
        Add-Line "       -> Check Entra ID > Users > $($findings.UserUPN) > Licenses"
        Add-Line "    2. The device may not be Azure AD joined (required for subscription activation)."
        if (-not $findings.AzureADJoined) {
            Add-Line "       -> CONFIRMED: This device is NOT Azure AD joined. Subscription activation"
            Add-Line "          requires Azure AD join or Hybrid Azure AD join."
        }
        Add-Line "    3. Group-based licensing may not include this user."
        Add-Line "    4. Conditional Access policies may be blocking the entitlement claim."
        Add-Line "    5. ClipSVC service issue — try: net stop ClipSVC && net start ClipSVC"
    }
    elseif (-not $findings.AzureADJoined) {
        Add-Line "  This device is NOT Azure AD joined and no user UPN was found."
        Add-Line "  M365 Subscription Activation requires:"
        Add-Line "    1. Azure AD join (or Hybrid Azure AD join)"
        Add-Line "    2. A user with M365 E3/E5 license to sign in"
        Add-Line "  Neither condition appears to be met."
    }
    else {
        Add-Line "  The device IS Azure AD joined but no user UPN could be determined."
        Add-Line "  Check if a licensed M365 E3/E5 user has signed into this device."
    }
    Add-Line ''
    if ($findings.IsOEM) {
        Add-Line "  LICENSE SOURCE: OEM — the device shipped with Windows Pro from the manufacturer."
    }
    elseif ($findings.HasOA3Key) {
        Add-Line "  LICENSE SOURCE: OA3 firmware key — Pro key embedded in UEFI by manufacturer."
    }
}

# --- LTSC / IoT ---
elseif ($findings.IsLTSC -or $findings.IsIoT) {
    $ltscLabel = if ($findings.IsIoT -and $findings.IsLTSC) { "IoT Enterprise LTSC" }
                 elseif ($findings.IsIoT) { "IoT Enterprise" }
                 elseif ($findings.IsLTSC) { "Enterprise LTSC" }
                 else { "LTSC/IoT" }

    Add-Line "EDITION:  Windows $ltscLabel"
    Add-Line ''
    Add-Line "HOW THIS DEVICE OBTAINED ITS LICENSE:"
    Add-Line ''
    if ($findings.HasOA3Key) {
        Add-Line "  PRIMARY SOURCE: OA3 FIRMWARE KEY (UEFI/BIOS EMBEDDED)"
        Add-Line "  The device manufacturer (OEM) burned an $ltscLabel product key into the firmware."
        Add-Line "  This is the standard method for specialty/fixed-function devices (POS, kiosk,"
        Add-Line "  pharmacy, photo lab, digital signage, thin clients)."
        Add-Line ''
        Add-Line "  REIMAGE SAFE: YES — The firmware key will automatically activate a clean install"
        Add-Line "                of the matching $ltscLabel edition on this hardware."
    }
    elseif ($findings.IsKMS) {
        Add-Line "  PRIMARY SOURCE: KMS (Key Management Service)"
        Add-Line "  A GVLK was deployed on this device, and it activates against a KMS server."
        Add-Line "  This is typical for organizations that purchased $ltscLabel volume licenses"
        Add-Line "  and manage activation centrally."
        if ($findings.KMSServer -or $findings.KMSDiscovered) {
            Add-Line "  KMS Server: $(if ($findings.KMSServer) { $findings.KMSServer } else { $findings.KMSDiscovered })"
        }
        Add-Line ''
        Add-Line "  REIMAGE SAFE: YES (if KMS server remains reachable after reimage)."
    }
    elseif ($findings.IsMAK) {
        Add-Line "  PRIMARY SOURCE: MAK (Multiple Activation Key)"
        Add-Line "  A Volume License MAK key was entered on this device."
        Add-Line "  This is used for devices that cannot reach a KMS server."
        Add-Line ''
        Add-Line "  REIMAGE SAFE: The same MAK key must be re-entered after reimage"
        Add-Line "                (consumes another activation from the key's pool)."
    }
    elseif ($findings.IsOEM -and -not $findings.HasOA3Key) {
        Add-Line "  PRIMARY SOURCE: OEM PRE-ACTIVATION (No firmware key)"
        Add-Line "  The OEM activated this device at the factory, but did NOT embed an OA3 key."
        Add-Line "  This could mean the activation used an OEM SLP method or a COA sticker."
        Add-Line ''
        Add-Line "  REIMAGE SAFE: UNCERTAIN — Without an OA3 key, a reinstall may not auto-activate."
        Add-Line "  Check for a physical COA sticker on the device."
    }
    else {
        Add-Line "  SOURCE: Could not definitively determine licensing source."
        Add-Line "  Channel: $($findings.LicenseChannel)"
        Add-Line "  Description: $($findings.LicenseDesc)"
    }
    Add-Line ''
    Add-Line "  NOTE ON $($ltscLabel.ToUpper()) LICENSING:"
    Add-Line "  $ltscLabel is NOT available through M365 subscription activation."
    Add-Line "  It must be licensed separately via OEM embedding, Volume License (KMS/MAK),"
    Add-Line "  or retail purchase. It is intended for fixed-function/specialty devices."
}

# --- ANYTHING ELSE ---
else {
    Add-Line "EDITION:  $($findings.Edition) ($($findings.EditionId))"
    Add-Line ''
    Add-Line "This edition was not classified as Enterprise, Professional, or LTSC/IoT."
    Add-Line "Channel: $($findings.LicenseChannel)"
    Add-Line "License Family: $($findings.LicenseFamily)"
    Add-Line "Description: $($findings.LicenseDesc)"
}

Add-Line ''
Add-Line '--- END OF AUDIT ---'

# ============================================================================
# OUTPUT TO FILE AND UPLOAD TO AZURE BLOB
# ============================================================================

$lines | Out-File -FilePath $localPath -Encoding UTF8

Write-Host "[INFO] Local report saved to $localPath"

# Upload to Azure Blob Storage via REST PUT
$blobUrl = "$BlobBaseUrl/$fileName$SasToken"

try {
    $fileBytes   = [System.IO.File]::ReadAllBytes($localPath)
    $headers     = @{
        'x-ms-blob-type' = 'BlockBlob'
        'Content-Type'   = 'text/plain; charset=utf-8'
    }

    $response = Invoke-WebRequest -Uri $blobUrl -Method PUT -Headers $headers -Body $fileBytes -UseBasicParsing -ErrorAction Stop

    if ($response.StatusCode -eq 201) {
        Write-Host "[INFO] Successfully uploaded to Azure Blob Storage"
    } else {
        Write-Host "[WARN] Upload returned status $($response.StatusCode)"
    }
} catch {
    Write-Host "[ERROR] Failed to upload to Azure Blob Storage: $_"
    Write-Host "[INFO] Local file remains at $localPath for manual retrieval"
}