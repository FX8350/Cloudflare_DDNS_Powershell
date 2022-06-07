Param (
    # Hostname
    [Parameter()]
    [string[]]
    $Hostname = @(
        "example.com"
        "www.example.com"
    ),

    # TTL, Must be between 60 and 86400, or 1, or 0
    [Parameter()]
    [int32]
    [ValidateRange(0, 86400)]
    $Ttl = 0,

    # Proxied
    [Parameter()]
    [validateset("Auto", "True", "False")]
    $Proxied = "Auto",

    # IPv4 address (Optional)
    [Parameter()]
    [string]
    $IPAddr = "",

    # IPv6 address (Optional)
    [Parameter()]
    [string]
    $IPv6Addr = "",

    # Cloudflare API Token
    [Parameter()]
    [string]
    $Token = "api_token",

    # Create New Record
    [Parameter()]
    [switch]
    $Y,

    # Disable IPv4
    [Parameter()]
    [switch]
    $NoIPv4,

    # Enable IPv6
    [Parameter()]
    [switch]
    $UseIPv6,

    # IPv6 address Source
    [Parameter()]
    [string]
    [ValidateSet("Windows", "Web")]
    $IPv6Source = "Windows",
    
    # Index of IPv6 address source interface
    [Parameter()]
    [int32]
    $IPv6Index,

    # Use Temporary (Privacy) IPv6 address
    [Parameter()]
    [switch]
    $UseTemp,

    # Disable logging
    [Parameter()]
    [switch]
    $NoLog,

    # Log Level
    [Parameter()]
    [string]
    [ValidateSet("Info", "Error")]
    $LogLevel = "Error",

    # Log file name
    [Parameter()]
    [string]
    $LogName,

    # Deley for TaskScheduler
    [Parameter()]
    [int32]
    $Delay,

    # Cloudflare API URI
    [Parameter()]
    [string]
    $Api = "https://api.cloudflare.com/client/v4/zones",

    # External IPv4 address API URI
    [Parameter()]
    [string]
    $CheckIP = "https://checkip.amazonaws.com",

    # External IPv6 addres API URI
    [Parameter()]
    [string]
    $CheckIPv6 = "https://domains.google.com/checkip"
)

if ($Delay) {
    Write-Host "-Delay $($Delay) が指定されているため、$($Delay)秒間スクリプトの進行を停止しています。"
    Write-Host "不要な場合は -Delay を削除してください。このコンソール出力はログファイルには記載されません。"
    Start-Sleep -s $Delay
}

function Write-Log {
    [CmdletBinding()]
    Param (
        [Parameter()]
        [string]
        $Message,

        [Parameter()]
        [switch]
        $Info
    )
    if (-not(($LogLevel -eq "Error") -and ($Info))) {
        Write-Host $Message
        if ($NoLog) { return }
        $TimeStamp = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
        if (-not($LogName)) { $LogName = "$([System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)).log" }
        Write-Output "$($TimeStamp) $($Message)" | Out-File -FilePath "$($PSScriptRoot)$($LogName)" -Append
    }
}

function Exit-Script {
    [CmdletBinding()]
    Param ()
    Write-Log "必要な情報を得られませんでした。 スクリプトを終了します。"
    Write-Log "スクリプトを終了しています..."
    Write-Log "------------------------------"
    Exit 1
}

function Show-ApiError {
    [CmdletBinding()]
    Param (
        [Parameter()]
        [string]
        $Source
    )
    $ErrorMessage = "($($Source)) Cloudflare APIからの応答が正しくありません。"
    $HttpStatuCode = "HTTP ステータスコード: $($Response.StatusCode) $($Response.StatusDescription)"
    $CloudflareErrorCode = "Cloudflare エラーコード: $($ResponseBody.errors.code) $($ResponseBody.errors.message) | $($ResponseBody.errors.error_chain.code) $($ResponseBody.errors.error_chain.message)"
    Write-Log "$($ErrorMessage) $($HttpStatuCode) | $($CloudflareErrorCode)"
}

# Start Script
Write-Log "------------------------------"
Write-Log "スクリプトを開始しています..."

# Check parameter
if (-not($Hostname)) {
    Write-Log "対象のホストが指定されていません。"
    Exit-Script
}

if (-not($Token)) {
    Write-Log "APIトークンが指定されていません。"
    Exit-Script
}

$Headers = @{
    "Authorization" = "Bearer $($Token)"
}

if (($Ttl -lt 60) -and ($Ttl -ge 2)) {
    Write-Log "TTLに有効な値が指定されていません。 (TTL=$($Ttl))"
    Write-Log "60-86400(秒)の間、 1 (Cloudflareの自動)、もしくは 0 (更新時はDNSレコードのTTLの引き継ぎ、新規作成時は 1 )を指定してください。"
    Exit-Script
}

if (-not($UseIPv6)) {
    if ($NoIPv4) {
        Write-Log "IPv4が無効化されていますが、IPv6が有効化されていません。 最低でもどちらかを有効にしてください。"
        Exit-Script
    }
    if (($IPv6Addr) -or ($UseTemp) -or ($IPv6Index) -or ($IPv6Source -eq "Web")) {
        Write-Log "IPv6用のパラメーターが指定されていますが、IPv6が有効化されていません。 -UseIPv6 を指定してください。"
        Exit-Script
    }
}
elseif (($IPv6Source -eq "Windows") -and (-not($IPv6Index)) -and (-not($IPv6Addr))) {
    Write-Log "IPv6アドレス取得に必要な情報が指定されていません。"
    Write-Log "Windowsから取得する場合は -IPv6Index <数字> でインターフェース番号を指定してください。"
    Write-Log "Webから取得する場合は -IPv6Source Web を指定してください。"
    Exit-Script
}

function Get-IPAddress {
    [CmdletBinding()]
    Param(
        [Parameter()]
        [string]
        $Address,

        [Parameter()]
        [string]
        $IP
    )
    $IPRegex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    $IPv6Regex = "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"
    if ($IP -eq "IPv4") {
        $IPUri = $CheckIP; $IPMatch = $IPRegex 
    }
    elseif ($IP -eq "IPv6") {
        $IPUri = $CheckIPv6; $IPMatch = $IPv6Regex; 
        if (-not($UseTemp)) { $Origin = "Link" } else { $Origin = "Random" }
    }
    if ($Address) {
        if ($Address -match $IPMatch) {
            Write-Log "パラメーターに指定された$($IP)アドレス($($Address))を使用します。" -Info
            Return $Address
        }
        else {
            Write-Log "パラメーターに指定された$($IP)アドレス($($Address))が無効な値です。"
            Exit-Script
        }
    }
    else {
        Write-Log "$($IP)アドレスを取得します。" -info
        if (($IP -eq "IPv4") -or ($IPv6Source -eq "Web")) {
            Try {
                $Address = Invoke-RestMethod -Uri $IPUri
            }
            catch {
                Write-Log "$($IP)アドレスの取得に失敗しました。 $($IPUri) にアクセスできません。"
                Write-Log "エラーメッセージ: ($_)"
                Exit-Script
            }
        }
        elseif ($IPv6Source -eq "Windows") {
            try { 
                $Address = (Get-NetIPAddress -InterfaceIndex $IPv6Index -AddressFamily IPv6 -PrefixOrigin RouterAdvertisement -ErrorAction Stop | Where-Object { $_.SuffixOrigin -eq $Origin }).IPAddress
            }
            catch {
                Write-Log "WindowsからのIPv6アドレスの取得に失敗しました。"
                Write-Log "エラーメッセージ: $($_)" 
                Exit-Script
            }
        }
        $Address = $Address.ReplaceLineEndings("")
        $Address = $Address.Trim()  
        if (($Address -match $IPMatch) -and ($Address.Count -eq 1)) {
            Write-Log "$($IP)アドレスの取得に成功しました。" -info
            Return $Address
        }
        else {
            Write-Log "$($IP)アドレスの取得に失敗しました。 有効な$($IP)アドレスを確認できませんでした。"
            Write-Log "$($Address)"
            Exit-Script
        }
    }
}

# Get IP address
if (-not($NoIPv4)) { $IPAddr = Get-IPAddress $IPAddr IPv4 }
if ($UseIPv6) { $IPv6Addr = Get-IPAddress $IPv6Addr IPv6 }


# Get Zone ID
Write-Log "Zone IDを取得します。" -info
$ZoneUri = "$($Api)/"
Try {
    $Response = Invoke-WebRequest -Method Get -Uri $ZoneUri -Headers $Headers -ContentType 'application/json' -SkipHttpErrorCheck
}
Catch {
    Write-Log "Zone IDの取得に失敗しました。 Cloudflare APIにアクセスできません。"
    Write-Log "エラーメッセージ: $($_)"
    Exit-Script
}
$ResponseBody = $Response.Content | ConvertFrom-Json -AsHashtable
if (-not($ResponseBody.success)) {
    Show-ApiError ZoneID
    Write-Log "Zone IDの取得に失敗しました。"
    Exit-Script
}
elseif (-not($ResponseBody.result.id)) {
    Write-Log "Zone IDの取得に失敗しました。 Cloudflare APIがZone IDを応答していません。"
    Exit-Script
}
else {
    $ZoneId = $ResponseBody.result.id
    $ZoneName = $ResponseBody.result.name
    $ZoneRegex = "^.*$($ZoneName.Replace(".", "\."))$"
    Write-Log "Zone IDの取得に成功しました。" -info
    Remove-Variable Response; Remove-Variable ResponseBody
}

function Invoke-DDNS {
    [CmdletBinding()]
    Param(
        [Parameter()]
        [string]
        $Hosts,

        [Parameter()]
        [string]
        $IP
    )
    Write-Log "($($IP)) $($Hosts) の処理を開始します。" -info
    if ($Hosts -notmatch $ZoneRegex) {
        Write-Log "($($IP)) $($Hosts) がゾーン名($($ZoneName))と一致しません。"
        Return @{ "Success" = $false }
    }
    if ($IP -eq "IPv6") { $Type = "AAAA"; $Content = $IPv6Addr } elseif ($IP -eq "IPv4") { $Type = "A"; $Content = $IPAddr }
    $RecordUri = "$($Api)/$($ZoneId)/dns_records?name=$($Hosts)&type=$($Type)"
    Try {
        $Response = Invoke-WebRequest -Method Get -Uri $RecordUri -Headers $Headers -ContentType 'application/json' -SkipHttpErrorCheck
    }
    Catch {
        Write-Log "($($IP)) $($Hosts) のDNSレコードの取得に失敗しました。 Cloudflare APIにアクセスできません。"
        Write-Log "エラーメッセージ：$($_)"
        Return @{ "Success" = $false }
    }
    $ResponseBody = $Response.Content | ConvertFrom-Json -AsHashtable
    if (-not($ResponseBody.success)) {
        Show-ApiError $IP
        Write-Log "($($IP)) $($Hosts) のDNSレコードの取得に失敗しました。"
        Return @{ "Success" = $false }
    }
    elseif (-not($ResponseBody.result.id)) {
        if (-not($Y)) {
            Write-Log "($($IP)) $($Hosts) のDNSレコードが存在しません。 新たに作成するには -Y を指定して再度実行してください。"
            Return @{ "Success" = $false }
        }
        else {
            Write-Log "($($IP)) $($Hosts) のDNSレコードが存在しません。 $($IP)アドレス($($Content),TTL=$($Ttl),Proxied=$($Proxied))のDNSレコードを新たに作成します。"
            if ($Ttl -eq 0) { $CreateTtl = 1 } else { $CreateTtl = $Ttl }
            $CreateUri = "$($Api)/$($ZoneId)/dns_records"
            $Body = @{
                "type"    = "$($Type)"
                "name"    = "$($Hosts)"
                "content" = "$($Content)"
                "ttl"     = "$($CreateTtl)"
            }
            if (-not($Proxied -eq "Auto")) {
                if ($Proxied -eq "True") { $CreateProxied = $true }
                elseif ($Proxied -eq "False") { $CreateProxied = $false }
                $Body.add("proxied", $CreateProxied)
            }
            $Body = $Body | ConvertTo-Json
            Try {
                $Response = Invoke-WebRequest -Uri $CreateUri -Method Post -Body $Body -Headers $Headers -ContentType 'application/json' -SkipHttpErrorCheck
            }
            Catch {
                Write-Log "($($IP)) $($Hosts) のDNSレコードの作成に失敗しました。 Cloudflare APIにアクセスできません。"
                Write-Log "エラーメッセージ: $($_)"
                Return @{ "Success" = $false }
            }
            $ResponseBody = $Response.Content | ConvertFrom-Json -AsHashtable
            if (-not($ResponseBody.success)) {
                Show-ApiError $IP
                Write-Log "($($IP)) $($Hosts) のDNSレコードの作成に失敗しました。"
                Return @{ "Success" = $false }
            }
            else {
                Write-Log "($($IP)) $($Hosts) のDNSレコードの作成に成功しました。" -info
                Return @{ "Success" = $true; "CreateRecord" = $true }
            }
        }
    }
    else {
        Write-Log "($($IP)) $($Hosts) のDNSコードIDの取得に成功しました。" -info
        if ($Ttl -eq 0) { $UpdateTtl = $ResponseBody.result.ttl } else { $UpdateTtl = $Ttl }
        if ($Proxied -eq "Auto") { $UpdateProxied = $ResponseBody.result.proxied } elseif ($Proxied -eq "True") { $UpdateProxied = $true } elseif ($Proxied -eq "flase") { $UpdateProxied = $false }
        if (($ResponseBody.result.content -eq $Content) -and ($ResponseBody.result.ttl -eq $UpdateTtl) -and ($ResponseBody.result.proxied -eq $UpdateProxied)) {
            Write-Log "($($IP)) $($Hosts) のDNSレコード($($ResponseBody.result.content),TTL=$($ResponseBody.result.ttl),Proxied=$($ResponseBody.result.proxied))と指定された$($IP)アドレス($($Content),TTL=$($Ttl),Proxied=$($Proxied))が一致しました。 DNSレコードの更新は必要ありません。" -info
            Return @{ "Success" = 1; "NoUpdate" = 1 }
        }
        else {
            Write-Log "($($IP)) $($Hosts) のDNSレコード($($ResponseBody.result.content),TTL=$($ResponseBody.result.ttl),Proxied=$($ResponseBody.result.proxied))と指定された$($IP)アドレス($($Content),TTL=$($Ttl),Proxied=$($Proxied))が一致しません。 DNSレコードの更新を行います。"
            $UpdateUri = "$($Api)/$($ZoneId)/dns_records/$($ResponseBody.result.id)"
            $Body = @{
                "type"    = "$($Type)"
                "name"    = "$($Hosts)"
                "content" = "$($Content)"
                "ttl"     = "$($UpdateTtl)"
                "proxied" = $UpdateProxied
            } | ConvertTo-Json
            Try {
                $Response = Invoke-WebRequest -Uri $UpdateUri -Method Put -Body $Body -Headers $Headers -ContentType 'application/json' -SkipHttpErrorCheck
            }
            Catch {
                Write-Log "($($IP)) $($Hosts) のDNSレコードの更新に失敗しました。 Cloudflare APIにアクセスできません。"
                Write-Log "エラーメッセージ: $($_)"
                Return @{ "Success" = $false }
            }
            $ResponseBody = $Response.Content | ConvertFrom-Json -AsHashtable
            if (-not($ResponseBody.success)) {
                Show-ApiError $IP
                Write-Log "($($IP)) $($Hosts) のDNSレコードの更新に失敗しました。"
                Return @{ "Success" = $false }
            }
            else {
                Write-Log "($($IP)) $($Hosts) のDNSレコードの更新に成功しました。" -info
                Return @{ "Success" = $true; "UpdateRecord" = $true }
            }

        }
    }
}

# 変数の初期化
$Counts = @{
    "v4" = @{
        "NoUpdate" = 0
        "Update"   = 0
        "Create"   = 0
        "Error"    = 0 
    }
    "v6" = @{
        "NoUpdate" = 0
        "Update"   = 0
        "Create"   = 0
        "Error"    = 0 
    } 
}
$ResultHost = @{
    "v4" = @{ "Success" = @(); "Error" = @() }
    "v6" = @{ "Success" = @(); "Error" = @() }
}

# Get DNS record and Update
$Hostname | ForEach-Object {
    if (-not($NoIPv4)) { 
        $Result = Invoke-DDNS $_ IPv4
        if ($Result.Success) {
            Write-Log "(IPv4) $($_) の処理に成功しました。" -info
            if ($Result.NoUpdate) { $Counts.v4.NoUpdate ++ }
            if ($Result.UpdateRecord) { $Counts.v4.Update ++ }
            if ($Result.CreateRecord) { $Counts.v4.Create ++ }
            $ResultHost.v4.Success += @($_)
        }
        else {
            Write-Log "(IPv4) $($_) の処理に失敗しました。"
            $Counts.v4.Error ++
            $ResultHost.v4.Error += @($_)
        }
    }
    if ($UseIPv6) {
        $Result = Invoke-DDNS $_ IPv6
        if ($Result.Success) {
            Write-Log "(IPv6) $($_) の処理に成功しました。" -info
            if ($Result.NoUpdate) { $Counts.v6.NoUpdate ++ }
            if ($Result.UpdateRecord) { $Counts.v6.Update ++ }
            if ($Result.CreateRecord) { $Counts.v6.Create ++ }
            $ResultHost.v6.Success += @($_)
        }
        else {
            Write-Log "(IPv6) $($_) の処理に失敗しました。"
            $Counts.v6.Error ++
            $ResultHost.v6.Error += @($_)
        }
    }
    Remove-Variable Result
}
Write-Log "全てのホスト($($Hostname.Count)件)の処理が終了しました。" -info
if (-not($NoIPv4)) { 
    Write-Log "(IPv4) 更新不要: $($Counts.v4.NoUpdate) | 更新: $($Counts.v4.Update) | 作成: $($Counts.v4.Create) | 失敗: $($Counts.v4.Error) |"
    if ($ResultHost.v4.Success) { Write-Log "(IPv4) ホスト名: $($ResultHost.v4.Success)" }
    if ($Counts.v4.Error) { Write-Log "(IPv4) 失敗したホスト名: $($ResultHost.v4.Error)" }
}
if ($UseIPv6) {
    Write-Log "(IPv6) 更新不要: $($Counts.v6.NoUpdate) | 更新: $($Counts.v6.Update) | 作成: $($Counts.v6.Create) | 失敗: $($Counts.v6.Error) |" 
    if ($ResultHost.v6.Success) { Write-Log "(IPv6) ホスト名: $($ResultHost.v6.Success)" }
    if ($Counts.v6.Error) { Write-Log "(IPv6) 失敗したホスト名: $($ResultHost.v6.Error)" }
}
Write-Log "スクリプトを終了しています..."
Write-Log "------------------------------"

if (($Counts.v4.Error) -or ($Counts.v6.Error)) { Exit 1 } else { Exit }
