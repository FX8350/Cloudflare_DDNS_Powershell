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

    # IPv4 address (Optional)
    [Parameter()]
    [string]
    $IpAddress = "",

    # IPv6 address (Optional)
    [Parameter()]
    [string]
    $Ipv6Address = "",

    # Cloudflare API Token
    [Parameter()]
    [string]
    $Token = "api_token",

    # Create New Record
    [Parameter()]
    [Switch]
    $Y,

    # Disable IPv4
    [Parameter()]
    [Switch]
    $NoIpv4,

    # Enable IPv6
    [Parameter()]
    [Switch]
    $UseIpv6,

    # IPv6 address Source
    [Parameter()]
    [string]
    [ValidateSet("Powershell", "Web")]
    $Ipv6Source = "Powershell",
    
    # Index of IPv6 address source interface
    [Parameter()]
    [int32]
    $Ipv6Index,

    # Use Temporary (Privacy) IPv6 address
    [Parameter()]
    [switch]
    $UseTemp,

    # Disable logging
    [Parameter()]
    [Switch]
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
    $CheckIp = "https://checkip.amazonaws.com",

    # External IPv6 addres API URI
    [Parameter()]
    [String]
    $CheckIpv6 = "https://domains.google.com/checkip"
)

if ($Delay) {
    Write-Host "-Delay $($Delay) が指定されているため、$($Delay)秒間スクリプトの進行を停止しています。"
    Write-Host "不要な場合は -Delay <秒数> を削除してください。このコンソール出力はログファイルには記載されません。"
    Start-Sleep -s $Delay
}

function Write-Log {
    [CmdletBinding()]
    Param (
        [Parameter()]
        [string]
        $Message,

        [Parameter()]
        [Switch]
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
    Param ()
    $ErrorMessage = "Cloudflare APIからの応答が正しくありません。"
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
    if ($NoIpv4) {
        Write-Log "IPv4が無効化されていますが、IPv6が有効化されていません。 最低でもどちらかを有効にしてください。"
        Exit-Script
    }
    if (($Ipv6Address) -or ($UseTemp) -or ($Ipv6Index) -or ($Ipv6Source -eq "Web")) {
        Write-Log "IPv6用のパラメーターが指定されていますが、IPv6が有効化されていません。 -UseIpv6 を指定してください。"
        Exit-Script
    }
}
elseif (($Ipv6Source -eq "PowerShell") -and (-not($Ipv6Index)) -and (-not($Ipv6Address))) {
    Write-Log "IPv6アドレス取得に必要な情報が指定されていません。"
    Write-Log "Windowsから取得する場合は -Ipv6Index <数字> でインターフェース番号を指定してください。"
    Write-Log "Webから取得する場合は -Ipv6Source Web を指定してください。"
    Exit-Script
}

function Invoke-IpAddress {
    [CmdletBinding()]
    Param(
        [Parameter()]
        [string]
        $Address,

        [Parameter()]
        [string]
        $Ip
    )
    $IpRegex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    $Ipv6Regex = "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"
    if ($Ip -eq "IPv4") {
        $IpUri = $CheckIp; $IpMatch = $IpRegex 
    }
    elseif ($Ip -eq "IPv6") {
        $IpUri = $CheckIpv6; $IpMatch = $Ipv6Regex; 
        if (-not($UseTemp)) { $Origin = "Link" } else { $Origin = "Random" }
    }
    if ($Address) {
        if ($Address -match $IpMatch) {
            Write-Log "パラメーターに指定された$($Ip)アドレス($($Address))を使用します。" -Info
            Return $Address
        }
        else {
            Write-Log "パラメーターに指定された$($Ip)アドレス($($Address))が無効な値です。"
            Exit-Script
        }
    }
    else {
        Write-Log "$($Ip)アドレスを取得します。" -info
        if (($Ip -eq "IPv4") -or ($Ipv6Source -eq "Web")) {
            Try {
                $Address = Invoke-RestMethod -Uri $IpUri
            }
            catch {
                Write-Log "$($Ip)アドレスの取得に失敗しました。 $($IpUri) にアクセスできません。"
                Write-Log "エラーメッセージ: ($_)"
                Exit-Script
            }
        }
        elseif ($Ipv6Source -eq "PowerShell") {
            try { 
                $Address = (Get-NetIPAddress -InterfaceIndex $Ipv6Index -AddressFamily IPv6 -PrefixOrigin RouterAdvertisement -ErrorAction Stop | Where-Object { $_.SuffixOrigin -eq $Origin }).IPAddress
            }
            catch {
                Write-Log "IPv6アドレスの取得に失敗しました。"
                Write-Log "エラーメッセージ: $($_)" 
                Exit-Script
            }
        }
        $Address = $Address.ReplaceLineEndings("")
        $Address = $Address.Trim()  
        if (($Address -match $IpMatch) -and ($Address.Count -eq 1)) {
            Write-Log "$($Ip)アドレスの取得に成功しました。" -info
            Return $Address
        }
        else {
            Write-Log "$($Ip)アドレスの取得に失敗しました。 有効な$($Ip)アドレスを確認できませんでした。"
            Write-Log "$($Address)"
            Exit-Script
        }
    }
}

# Get IP address
if (-not($NoIpv4)) {
    $IpAddress = Invoke-IpAddress $IpAddress IPv4
}
if ($UseIpv6) {
    $Ipv6Address = Invoke-IpAddress $Ipv6Address IPv6
}


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
$ResponseBody = $Response.Content | ConvertFrom-Json
if (-not($ResponseBody.success)) {
    Show-ApiError
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
    $ZoneRegex = "^.*$($ZoneName.Replace(".","\."))$"
    Write-Log "Zone IDの取得に成功しました。" -info
}

function Invoke-DDNS {
    [CmdletBinding()]
    Param(
        [Parameter()]
        [string]
        $Hosts,

        [Parameter()]
        [string]
        $Ip
    )
    Write-Log "($($Ip)) $($Hosts) の処理を開始します。" -info
    if ($Hosts -notmatch $ZoneRegex) {
        Write-Log "($($Ip)) $($Hosts) がゾーン名($($ZoneName))と一致しません。"
        Return @{ "Success" = $false }
    }
    if ($Ip -eq "IPv6") { $Type = "AAAA"; $IpAddr = $Ipv6Address } elseif ($Ip -eq "IPv4") { $Type = "A"; $IpAddr = $IpAddress }
    $RecordUri = "$($Api)/$($ZoneId)/dns_records?name=$($Hosts)&type=$($Type)"
    Try {
        $Response = Invoke-WebRequest -Method Get -Uri $RecordUri -Headers $Headers -ContentType 'application/json' -SkipHttpErrorCheck
    }
    Catch {
        Write-Log "($($Ip)) $($Hosts) のDNSレコードの取得に失敗しました。 Cloudflare APIにアクセスできません。"
        Write-Log "エラーメッセージ：$($_)"
        Return @{ "Success" = $false }
    }
    $ResponseBody = $Response.Content | ConvertFrom-Json
    if (-not($ResponseBody.success)) {
        Show-ApiError
        Write-Log "($($Ip)) $($Hosts) のDNSレコードの取得に失敗しました。"
        Return @{ "Success" = $false }
    }
    elseif (-not($ResponseBody.result.id)) {
        if (-not($Y)) {
            Write-Log "($($Ip)) $($Hosts) のDNSレコードが存在しません。 新たに作成するには -y を指定して再度実行してください。"
            Return @{ "Success" = $false }
        }
        else {
            Write-Log "($($Ip)) $($Hosts) のDNSレコードが存在しません。 $($Ip)アドレス($($IpAddr),TTL=$($Ttl))のDNSレコードを新たに作成します。"
            if ($Ttl -eq 0) { $CreateTtl = 1 } else { $CreateTtl = $Ttl }
            $CreateUri = "$($Api)/$($ZoneId)/dns_records"
            $Body = @{
                "type"    = "$($Type)"
                "name"    = "$($Hosts)"
                "content" = "$($IpAddr)"
                "ttl"     = "$($CreateTtl)"
            } | ConvertTo-Json
            Try {
                $Response = Invoke-WebRequest -Uri $CreateUri -Method Post -Body $Body -Headers $Headers -ContentType 'application/json' -SkipHttpErrorCheck
            }
            Catch {
                Write-Log "($($Ip)) $($Hosts) のDNSレコードの作成に失敗しました。 Cloudflare APIにアクセスできません。"
                Write-Log "エラーメッセージ: $($_)"
                Return @{ "Success" = $false }
            }
            $ResponseBody = $Response.Content | ConvertFrom-Json
            if (-not($ResponseBody.success)) {
                Show-ApiError
                Write-Log "($($Ip)) $($Hosts) のDNSレコードの作成に失敗しました。"
                Return @{ "Success" = $false }
            }
            else {
                Write-Log "($($Ip)) $($Hosts) のDNSレコードの作成に成功しました。" -info
                Return @{ "Success" = $true; "CreateRecord" = $true }
            }
        }
    }
    else {
        $RecordId = $ResponseBody.result.id
        $DnsRecord = $ResponseBody.result.content
        $RecordTtl = $ResponseBody.result.ttl
        Write-Log "($($Ip)) $($Hosts) のDNSコードIDの取得に成功しました。" -info
        if ($Ttl -eq 0) { $UpdateTtl = $ResponseBody.result.ttl } else { $UpdateTtl = $Ttl }
        if (($IpAddr -eq $DnsRecord) -and ($RecordTtl -eq $UpdateTtl)) {
            Write-Log "($($Ip)) $($Hosts) のDNSレコード($($DnsRecord),TTL=$($RecordTtl))と指定された$($Ip)アドレス($($IpAddr),TTL=$($Ttl))が一致しました。 DNSレコードの更新は必要ありません。" -info
            Return @{ "Success" = $true; "NoUpdate" = $true }
        }
        else {
            Write-Log "($($Ip)) $($Hosts) のDNSレコード($($DnsRecord),TTL=$($RecordTtl))と$($Ip)アドレス($($IpAddr),TTL=$($Ttl))が一致しません。 DNSレコードの更新を行います。"
            $UpdateUri = "$($Api)/$($ZoneId)/dns_records/$($RecordId)"
            $Body = @{
                "type"    = "$($Type)"
                "name"    = "$($Hosts)"
                "content" = "$($IpAddr)"
                "ttl"     = "$($UpdateTtl)"
            } | ConvertTo-Json
            Try {
                $Response = Invoke-WebRequest -Uri $UpdateUri -Method Put -Body $Body -Headers $Headers -ContentType 'application/json' -SkipHttpErrorCheck
            }
            Catch {
                Write-Log "($($Ip)) $($Hosts) のDNSレコードの更新に失敗しました。 Cloudflare APIにアクセスできません。"
                Write-Log "エラーメッセージ: $($_)"
                Return @{ "Success" = $false }
            }
            $ResponseBody = $Response.Content | ConvertFrom-Json
            if (-not($ResponseBody.success)) {
                Show-ApiError
                Write-Log "($($Ip)) $($Hosts) のDNSレコードの更新に失敗しました。"
                Return @{ "Success" = $false }
            }
            else {
                Write-Log "($($Ip)) $($Hosts) のDNSレコードの更新に成功しました。" -info
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
    if (-not($NoIpv4)) { 
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
if (-not($NoIpv4)) { Write-Log "(IPv4) 更新不要: $($Counts.v4.NoUpdate) | 更新: $($Counts.v4.Update) | 作成: $($Counts.v4.Create) | 失敗: $($Counts.v4.Error) |"; Write-Host "(IPv4) ホスト名: $($ResultHost.v4.Success)" }
if ($Counts.v4.Error) { Write-Log "(IPv4) 失敗したホスト名: $($ResultHost.v4.Error)" }
if ($UseIpv6) { Write-Log "(IPv6) 更新不要: $($Counts.v6.NoUpdate) | 更新: $($Counts.v6.Update) | 作成: $($Counts.v6.Create) | 失敗: $($Counts.v6.Error) |"; Write-Host "(IPv6) ホスト名: $($ResultHost.v6.Success)" }
if ($Counts.v6.Error) { Write-Log "(IPv6) 失敗したホスト名: $($ResultHost.v6.Error)" }
Write-Log "スクリプトを終了しています..."
Write-Log "------------------------------"

if (($Counts.v4.Error) -or ($Counts.v6.Error)) { Exit 1 } else { Exit }

