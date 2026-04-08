# Get-WindowsActivationAudit.ps1
# Version: 3.0.0
# Purpose: Comprehensive audit of Windows OS licensing on ANY Windows device.
#          Determines the edition (Enterprise, Pro, LTSC, IoT), HOW it was
#          licensed (M365 subscription, KMS, MAK, OEM/OA3, digital entitlement),
#          and WHY it is in that state. Outputs a CSV row to Azure Blob Storage.
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
$fileName     = "WinLicenseAudit_${computerName}_${timestamp}.csv"
$localPath    = Join-Path $env:TEMP $fileName

# CSV row object — every field that will appear as a column
$csv = [ordered]@{
    ComputerName        = $computerName
    CollectedUTC        = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    Manufacturer        = ''
    Model               = ''
    SerialNumber        = ''
    BIOSVersion         = ''
    Baseboard           = ''
    OSCaption           = ''
    OSVersion           = ''
    OSBuild             = ''
    FullBuild           = ''
    DisplayVersion      = ''
    EditionID           = ''
    ProductName         = ''
    IsEnterprise        = $false
    IsPro               = $false
    IsLTSC              = $false
    IsIoT               = $false
    LicenseStatus       = ''
    LicenseChannel      = ''
    LicenseFamily       = ''
    LicenseDescription  = ''
    PartialProductKey   = ''
    GracePeriodMin      = ''
    RemainingRearms     = ''
    ActivationMethod    = ''
    IsKMS               = $false
    IsMAK               = $false
    IsOEM               = $false
    IsRetail            = $false
    IsSubscription      = $false
    IsDigitalLicense    = $false
    HasOA3FirmwareKey   = $false
    OA3KeyLast5         = ''
    KMSServerConfigured = ''
    KMSServerDiscovered = ''
    KMSRenewalMin       = ''
    KMSValidityMin      = ''
    SubscriptionType    = ''
    SubscriptionStatus  = ''
    AzureADJoined       = $false
    DomainJoined        = $false
    TenantName          = ''
    TenantID            = ''
    MDMEnrolled         = $false
    InteractiveUser     = ''
    UserUPN             = ''
    ClipSVCStatus       = ''
    ReimageRisk         = ''
    Verdict             = ''
    VerdictDetail       = ''
}

# ============================================================================
# SECTION 1 — HARDWARE IDENTITY
# ============================================================================
Write-Host '[INFO] --- HARDWARE IDENTITY ---'
try {
    $bios = Get-WmiObject -Class Win32_BIOS -ErrorAction Stop
    $cs   = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
    $bb   = Get-WmiObject -Class Win32_BaseBoard -ErrorAction Stop

    $csv.Manufacturer = $cs.Manufacturer
    $csv.Model        = $cs.Model
    $csv.SerialNumber = $bios.SerialNumber
    $csv.BIOSVersion  = $bios.SMBIOSBIOSVersion
    $csv.Baseboard    = "$($bb.Manufacturer) $($bb.Product)"

    Write-Host "[INFO] Manufacturer: $($csv.Manufacturer)"
    Write-Host "[INFO] Model:        $($csv.Model)"
    Write-Host "[INFO] Serial:       $($csv.SerialNumber)"
} catch {
    Write-Host "[ERROR] Failed to retrieve hardware info: $_"
}

# ============================================================================
# SECTION 2 — OPERATING SYSTEM EDITION DETECTION
# ============================================================================
Write-Host '[INFO] --- OPERATING SYSTEM ---'
try {
    $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop

    $editionId   = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction SilentlyContinue).EditionID
    $productName = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName -ErrorAction SilentlyContinue).ProductName
    $ubr         = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR -ErrorAction SilentlyContinue).UBR
    $displayVer  = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name DisplayVersion -ErrorAction SilentlyContinue).DisplayVersion

    $csv.OSCaption      = $os.Caption
    $csv.OSVersion      = $os.Version
    $csv.OSBuild        = $os.BuildNumber
    $csv.FullBuild      = "$($os.BuildNumber).$ubr"
    $csv.DisplayVersion = $displayVer
    $csv.EditionID      = $editionId
    $csv.ProductName    = $productName

    # Classify edition
    if ($editionId -match 'IoT')                                                  { $csv.IsIoT = $true }
    if ($editionId -match 'EnterpriseS' -or $productName -match 'LTSC|LTSB')     { $csv.IsLTSC = $true }
    if ($editionId -match '^Enterprise' -and $editionId -notmatch 'EnterpriseS')  { $csv.IsEnterprise = $true }
    if ($editionId -match 'Professional' -or $editionId -eq 'Pro')                { $csv.IsPro = $true }
    if ($csv.IsIoT -and ($editionId -match 'Enterprise') -and -not $csv.IsLTSC)  { $csv.IsEnterprise = $true }

    Write-Host "[INFO] Edition: $productName ($editionId)"
    Write-Host "[INFO] Build:   $($csv.FullBuild) ($displayVer)"
} catch {
    Write-Host "[ERROR] Failed to retrieve OS info: $_"
}

# ============================================================================
# SECTION 3 — OA3 FIRMWARE-EMBEDDED KEY (BIOS/UEFI)
# ============================================================================
Write-Host '[INFO] --- OA3 FIRMWARE KEY CHECK ---'
try {
    $sls = Get-WmiObject -Query 'SELECT OA3xOriginalProductKey FROM SoftwareLicensingService' -ErrorAction Stop
    $oa3Key = $sls.OA3xOriginalProductKey

    if ($oa3Key -and $oa3Key.Trim().Length -gt 0) {
        $csv.HasOA3FirmwareKey = $true
        $csv.OA3KeyLast5      = $oa3Key.Substring($oa3Key.Length - 5)
        Write-Host "[INFO] OA3 Key Present: YES (last 5: $($csv.OA3KeyLast5))"
    } else {
        Write-Host "[INFO] OA3 Key Present: NO"
    }
} catch {
    Write-Host "[ERROR] Failed to query OA3 key: $_"
}

# ============================================================================
# SECTION 4 — ACTIVATION STATUS & LICENSE CHANNEL
# ============================================================================
Write-Host '[INFO] --- ACTIVATION STATUS ---'
$winProduct = $null
try {
    $slProducts = Get-WmiObject -Query "SELECT * FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL" -ErrorAction Stop

    foreach ($slp in $slProducts) {
        if ($slp.ApplicationId -eq '55c92734-d682-4d71-983e-d6ec3f16059f') {
            $winProduct = $slp

            $statusMap = @{
                0 = 'Unlicensed'
                1 = 'Licensed'
                2 = 'OOBGrace'
                3 = 'OOTGrace'
                4 = 'NonGenuineGrace'
                5 = 'Notification'
                6 = 'ExtendedGrace'
            }
            $statusText = $statusMap[[int]$slp.LicenseStatus]
            if (-not $statusText) { $statusText = "Unknown($($slp.LicenseStatus))" }

            $csv.LicenseStatus     = $statusText
            $csv.LicenseChannel    = $slp.ProductKeyChannel
            $csv.LicenseFamily     = $slp.LicenseFamily
            $csv.LicenseDescription = $slp.Description
            $csv.PartialProductKey = $slp.PartialProductKey
            $csv.GracePeriodMin    = $slp.GracePeriodRemaining
            $csv.RemainingRearms   = $slp.RemainingSkuReArmCount

            # Detect activation method
            $channel = $slp.ProductKeyChannel
            switch -Regex ($channel) {
                'OEM_DM'      { $csv.IsOEM = $true;    $csv.ActivationMethod = 'OEM_DM' }
                'OEM'         { $csv.IsOEM = $true;    $csv.ActivationMethod = 'OEM' }
                'Retail'      { $csv.IsRetail = $true; $csv.ActivationMethod = 'Retail' }
                'Volume:MAK'  { $csv.IsMAK = $true;    $csv.ActivationMethod = 'MAK' }
                'Volume:GVLK' { $csv.IsKMS = $true;    $csv.ActivationMethod = 'KMS' }
                'Volume'      {
                    if ($slp.Description -match 'KMS') { $csv.IsKMS = $true; $csv.ActivationMethod = 'KMS' }
                    elseif ($slp.Description -match 'MAK') { $csv.IsMAK = $true; $csv.ActivationMethod = 'MAK' }
                    else { $csv.ActivationMethod = $channel }
                }
                default       { $csv.ActivationMethod = $channel }
            }

            # KMS details
            if ($slp.KeyManagementServiceMachine) {
                $csv.KMSServerConfigured = "$($slp.KeyManagementServiceMachine):$($slp.KeyManagementServicePort)"
            }
            if ($slp.DiscoveredKeyManagementServiceMachineName) {
                $csv.KMSServerDiscovered = "$($slp.DiscoveredKeyManagementServiceMachineName):$($slp.DiscoveredKeyManagementServiceMachinePort)"
            }
            if ($slp.VLActivationInterval -and $slp.VLActivationInterval -gt 0) {
                $csv.KMSRenewalMin = $slp.VLActivationInterval
            }
            if ($slp.VLRenewalInterval -and $slp.VLRenewalInterval -gt 0) {
                $csv.KMSValidityMin = $slp.VLRenewalInterval
            }

            # Subscription detection
            if ($slp.LicenseFamily -match 'Subscription' -or
                $slp.Description -match 'Subscription' -or
                $slp.Name -match 'Subscription') {
                $csv.IsSubscription = $true
                $csv.ActivationMethod = 'M365 Subscription'
            }

            Write-Host "[INFO] Status: $statusText | Channel: $channel | Method: $($csv.ActivationMethod)"
        }
    }

    if (-not $winProduct) {
        Write-Host "[WARN] No active Windows licensing product found."
    }
} catch {
    Write-Host "[ERROR] Failed to query activation status: $_"
}

# ============================================================================
# SECTION 5 — M365 / SUBSCRIPTION ACTIVATION DEEP DIVE
# ============================================================================
Write-Host '[INFO] --- M365 SUBSCRIPTION CHECK ---'
try {
    $saRegPath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\WindowsLicensing'
    if (Test-Path $saRegPath) {
        $saPolicy = Get-ItemProperty -Path $saRegPath -ErrorAction SilentlyContinue
        if ($null -ne $saPolicy.SubscriptionType)   { $csv.SubscriptionType   = $saPolicy.SubscriptionType }
        if ($null -ne $saPolicy.SubscriptionStatus)  { $csv.SubscriptionStatus = $saPolicy.SubscriptionStatus }
    }

    if ($csv.LicenseFamily -match 'Subscription|sub') {
        $csv.IsSubscription   = $true
        $csv.ActivationMethod = 'M365 Subscription'
        Write-Host "[INFO] Subscription Activation: YES"
    } else {
        Write-Host "[INFO] Subscription Activation: NOT DETECTED"
    }
} catch {
    Write-Host "[ERROR] Failed to check subscription activation: $_"
}

# ============================================================================
# SECTION 6 — AZURE AD / ENTRA JOIN STATUS
# ============================================================================
Write-Host '[INFO] --- AZURE AD / ENTRA ID JOIN STATUS ---'
try {
    $dsregOutput = & dsregcmd /status 2>&1 | Out-String

    if ($dsregOutput -match 'AzureAdJoined\s*:\s*YES')   { $csv.AzureADJoined = $true }
    if ($dsregOutput -match 'DomainJoined\s*:\s*YES')     { $csv.DomainJoined  = $true }
    if ($dsregOutput -match 'TenantName\s*:\s*(.+)')      { $csv.TenantName = $Matches[1].Trim() }
    if ($dsregOutput -match 'TenantId\s*:\s*(.+)')        { $csv.TenantID   = $Matches[1].Trim() }
    if ($dsregOutput -match 'MdmUrl\s*:\s*(.+)')          { $csv.MDMEnrolled = $true }

    Write-Host "[INFO] AzureAD: $($csv.AzureADJoined) | Domain: $($csv.DomainJoined) | Tenant: $($csv.TenantName)"
} catch {
    Write-Host "[ERROR] Failed to run dsregcmd: $_"
}

# ============================================================================
# SECTION 7 — LOGGED-IN USER UPN
# ============================================================================
Write-Host '[INFO] --- LOGGED-IN USER IDENTITY ---'
try {
    # Method 1: explorer.exe owner
    try {
        $explorerProcs = Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue
        if ($explorerProcs) {
            foreach ($proc in $explorerProcs) {
                $owner = Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction SilentlyContinue
                if ($owner -and $owner.ReturnValue -eq 0) {
                    $csv.InteractiveUser = "$($owner.Domain)\$($owner.User)"
                    break
                }
            }
        }
    } catch {
        try {
            $quserOutput = & quser 2>&1 | Out-String
            if ($quserOutput -match '>\s*(\S+)') { $csv.InteractiveUser = $Matches[1] }
        } catch { }
    }

    # Method 2: UPN from dsregcmd
    $upn = $null
    $dsregSSO = & dsregcmd /status 2>&1 | Out-String
    if ($dsregSSO -match 'UserEmail\s*:\s*(\S+@\S+)') { $upn = $Matches[1].Trim() }

    # Fallback: Identity Store
    if (-not $upn) {
        $identityPath = 'HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache'
        if (Test-Path $identityPath) {
            $idSubkeys = Get-ChildItem $identityPath -Recurse -ErrorAction SilentlyContinue |
                Get-ItemProperty -ErrorAction SilentlyContinue |
                Where-Object { $_.UserName -match '@' } |
                Select-Object -First 1
            if ($idSubkeys) { $upn = $idSubkeys.UserName }
        }
    }

    # Fallback: whoami /upn
    if (-not $upn) {
        try {
            $upnResult = & whoami /upn 2>&1
            if ($upnResult -match '@') { $upn = $upnResult.Trim() }
        } catch { }
    }

    # Fallback: CloudAP LogonCache
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

    if ($upn) { $csv.UserUPN = $upn }
    Write-Host "[INFO] User: $($csv.InteractiveUser) | UPN: $($csv.UserUPN)"
} catch {
    Write-Host "[ERROR] Failed to determine user identity: $_"
}

# ============================================================================
# SECTION 8 — DIGITAL LICENSE / ClipSVC CHECK
# ============================================================================
Write-Host '[INFO] --- DIGITAL LICENSE CHECK ---'
try {
    $entitlementStore = 'HKLM:\SYSTEM\CurrentControlSet\Control\{7746D80F-97E0-4E26-9543-26B41FC22F79}\{A25AE4F2-1B96-4CED-8007-AA30E9B1A218}'
    if (Test-Path $entitlementStore) { $csv.IsDigitalLicense = $true }

    $clipSvc = Get-Service -Name ClipSVC -ErrorAction SilentlyContinue
    if ($clipSvc) { $csv.ClipSVCStatus = $clipSvc.Status.ToString() }

    Write-Host "[INFO] DigitalLicense: $($csv.IsDigitalLicense) | ClipSVC: $($csv.ClipSVCStatus)"
} catch {
    Write-Host "[ERROR] Failed to check digital license: $_"
}

# ============================================================================
# SECTION 9 — VERDICT & REIMAGE RISK
# ============================================================================
Write-Host '[INFO] --- BUILDING VERDICT ---'

# --- ENTERPRISE ---
if ($csv.IsEnterprise -and -not $csv.IsLTSC) {
    if ($csv.IsSubscription) {
        $csv.Verdict       = 'Enterprise via M365 Subscription'
        $csv.VerdictDetail = "User $($csv.UserUPN) M365 E3/E5 license upgrades Pro to Enterprise via subscription activation (tenant: $($csv.TenantName)). Risk: reverts to Pro if license removed."
        $csv.ReimageRisk   = 'Low — will re-upgrade after reimage if user signs in with valid M365 license'
    }
    elseif ($csv.IsKMS) {
        $csv.Verdict       = 'Enterprise via KMS'
        $kmsHost = if ($csv.KMSServerConfigured) { $csv.KMSServerConfigured } else { $csv.KMSServerDiscovered }
        $csv.VerdictDetail = "Enterprise activated via KMS (GVLK). KMS server: $kmsHost. Renews every $($csv.KMSRenewalMin) min; expires if unreachable for 180 days."
        $csv.ReimageRisk   = 'Low — KMS GVLK re-activates automatically if KMS server is reachable'
    }
    elseif ($csv.IsMAK) {
        $csv.Verdict       = 'Enterprise via MAK'
        $csv.VerdictDetail = 'Enterprise activated with a MAK key (one-time Volume License activation). Permanent for this hardware.'
        $csv.ReimageRisk   = 'Medium — MAK key must be re-entered after reimage (consumes pool activation)'
    }
    else {
        $csv.Verdict       = "Enterprise via $($csv.ActivationMethod)"
        $csv.VerdictDetail = "Enterprise license channel: $($csv.LicenseChannel). Method could not be further classified."
        $csv.ReimageRisk   = 'Unknown'
    }
}
# --- PROFESSIONAL ---
elseif ($csv.IsPro) {
    $reasons = @()
    if (-not $csv.AzureADJoined)                         { $reasons += 'Device not Azure AD joined' }
    if (-not $csv.UserUPN)                               { $reasons += 'No user UPN detected (no M365 sign-in)' }
    elseif ($csv.UserUPN)                                { $reasons += "User $($csv.UserUPN) may lack M365 E3/E5 license" }
    if ($csv.ClipSVCStatus -eq 'Stopped' -and $csv.AzureADJoined) { $reasons += 'ClipSVC stopped — subscription activation cannot run' }

    $csv.Verdict       = 'Professional — NOT Enterprise'
    $csv.VerdictDetail = "Pro device. Likely reasons not Enterprise: $($reasons -join '; '). Check Entra ID user licenses and Azure AD join status."

    if ($csv.IsOEM -or $csv.HasOA3FirmwareKey) {
        $csv.ReimageRisk = 'Low — OEM/OA3 Pro key will auto-activate after reimage'
    } else {
        $csv.ReimageRisk = 'Medium — verify license source before reimaging'
    }
}
# --- LTSC / IoT ---
elseif ($csv.IsLTSC -or $csv.IsIoT) {
    $label = if ($csv.IsIoT -and $csv.IsLTSC) { 'IoT Enterprise LTSC' }
             elseif ($csv.IsIoT) { 'IoT Enterprise' }
             elseif ($csv.IsLTSC) { 'Enterprise LTSC' }
             else { 'LTSC/IoT' }

    if ($csv.HasOA3FirmwareKey) {
        $csv.Verdict       = "$label via OA3 Firmware Key"
        $csv.VerdictDetail = "OEM burned $label key into UEFI firmware (last 5: $($csv.OA3KeyLast5)). Standard for specialty/fixed-function devices."
        $csv.ReimageRisk   = 'None — firmware key auto-activates on reimage'
    }
    elseif ($csv.IsKMS) {
        $kmsHost = if ($csv.KMSServerConfigured) { $csv.KMSServerConfigured } else { $csv.KMSServerDiscovered }
        $csv.Verdict       = "$label via KMS"
        $csv.VerdictDetail = "$label activated via KMS (GVLK). Server: $kmsHost. Must renew within 180 days."
        $csv.ReimageRisk   = 'Low — re-activates if KMS server reachable'
    }
    elseif ($csv.IsMAK) {
        $csv.Verdict       = "$label via MAK"
        $csv.VerdictDetail = "$label activated with MAK Volume License key. One-time activation, permanent on this hardware."
        $csv.ReimageRisk   = 'Medium — MAK key must be re-entered after reimage'
    }
    elseif ($csv.IsOEM) {
        $csv.Verdict       = "$label via OEM (no firmware key)"
        $csv.VerdictDetail = "OEM pre-activated at factory but no OA3 key in firmware. May have used SLP or COA sticker."
        $csv.ReimageRisk   = 'High — no firmware key means reimage may not auto-activate. Check for physical COA.'
    }
    else {
        $csv.Verdict       = "$label — source unclear"
        $csv.VerdictDetail = "Channel: $($csv.LicenseChannel). Description: $($csv.LicenseDescription). Could not classify source."
        $csv.ReimageRisk   = 'Unknown'
    }

    $csv.VerdictDetail += " NOTE: $label is NOT available via M365 subscription. Must be licensed via OEM/VL/retail."
}
# --- ANYTHING ELSE ---
else {
    $csv.Verdict       = "$($csv.ProductName) ($($csv.EditionID))"
    $csv.VerdictDetail = "Unclassified edition. Channel: $($csv.LicenseChannel). Family: $($csv.LicenseFamily)."
    $csv.ReimageRisk   = 'Unknown'
}

Write-Host "[INFO] VERDICT: $($csv.Verdict)"
Write-Host "[INFO] DETAIL:  $($csv.VerdictDetail)"
Write-Host "[INFO] REIMAGE: $($csv.ReimageRisk)"

# ============================================================================
# OUTPUT CSV AND UPLOAD TO AZURE BLOB
# ============================================================================

# Build CSV — single row with headers
$csvObject = [PSCustomObject]$csv
$csvObject | Export-Csv -Path $localPath -NoTypeInformation -Encoding UTF8

Write-Host "[INFO] Local CSV saved to $localPath"

# Upload to Azure Blob Storage via REST PUT
$blobUrl = "$BlobBaseUrl/$fileName$SasToken"

try {
    $fileBytes = [System.IO.File]::ReadAllBytes($localPath)
    $headers   = @{
        'x-ms-blob-type' = 'BlockBlob'
        'Content-Type'   = 'text/csv; charset=utf-8'
    }

    $response = Invoke-WebRequest -Uri $blobUrl -Method PUT -Headers $headers -Body $fileBytes -UseBasicParsing -ErrorAction Stop

    if ($response.StatusCode -eq 201) {
        Write-Host "[INFO] Successfully uploaded CSV to Azure Blob Storage"
    } else {
        Write-Host "[WARN] Upload returned status $($response.StatusCode)"
    }
} catch {
    Write-Host "[ERROR] Failed to upload to Azure Blob Storage: $_"
    Write-Host "[INFO] Local file remains at $localPath for manual retrieval"
}