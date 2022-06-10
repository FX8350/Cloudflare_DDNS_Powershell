# Cloudflare_DDNS_Powershell
プログラムの素人がググりながら作ったスクリプトです<br>
Powershell 7でしか動かないみたいです

## 必要なもの
1. Powershell 7
2. Windows 10 (たぶん11でも動きます)
3. Cloudflareのアカウント(無料)
4. 自分のドメイン(年1,000～1,500円ぐらい)<br>どうやら`.tk`なんかの無料ドメインではAPIが使えないらしいです ([参考](https://community.cloudflare.com/t/unable-to-update-ddns-using-api-for-some-tlds/167228))

## 使い方
1. ドメインを取得する
2. Cloudflareのアカウントを作成しネームサーバーなどの設定を済ませる
3. APIトークンを取得する
4. スクリプトを直接編集するか、パラメータを指定してコンソールからスクリプトを起動し動作を確認する
6. タスクスケジューラに5分ごとぐらいで起動するようにしておく

* 例: `.\cloudflare_dns.ps1 -Hostname "hogehoge.net","test.hogehoge.net" -TTl 120 -Token "hogefuga"`

* `triger.xml`はイベントビューアのカスタムフィルターです。<br>
`TaskName`の部分を自分で作ったタスク名に変更してトリガーとしてタスクスケジューラに登録すれば、エラーが発生した時に指定したプログラムやスクリプトを起動する事ができます。<br>
メール送信スクリプトなんかを組めばいいらしいですが私は諦めました。
* [Powershellの仕様](https://github.com/PowerShell/PowerShell/issues/3028#issuecomment-275212445)により、タスクスケジューラから起動されるとコンソールのウインドウが一瞬表示されます。<br>
これを回避するには以下のいずれかの条件で登録してください。
   1. 「ユーザーがログオンしてるかどうかにかかわらず実行する」を指定する
   2. 権限を`SYSTEM`にする
   3. JavaScriptやVBScriptでヘルパーとなる起動スクリプトを書き、そこから起動する

* 起動時やログイン時をトリガーにすると、まだネットに接続されていない状態で処理を行おうとしてエラーになる場合があります。<br>
その場合は`-Dealy`パラメーターを引数に追加して適当な秒数待つようにしてください。


## パラーメーター
いずれも順番や大文字小文字は区別しません。

### -Hostname <ホスト名, ホスト名,...> (必須)
ホスト名を指定します。<br>
スクリプトを直接編集する場合は改行、パラメーターとして渡す場合は`,`(コロン)で区切ることで複数のホストを選択できます。<br>
なんでコロンで区切れるのかは分かりません。<br>
タスクスケジューラに複数のホスト名を渡す際は、引数に<br>
`-ExecutionPolicy ByPass -Command "& 'C:\path_to_script\cloudflare_ddns.ps1' -hostname 'example.com', 'www.example.com'"`<br>
のように`-File`ではなく`-Command "&`で指定すると上手くいきます。この場合、引数の文字列はシングルクオートで囲うようです。

### -Ttl <数字>
TTLを指定します。<br>
60～86400秒の間か、1=Cloudflareでの自動か、0(後述)のいずれかを入力します。<br>
ddo.jpの有料版が60秒、MyDNS.jpが300秒なのでこの間ぐらいを指定するといいと思います。<br>
0の場合、既存のレコードのTTLをそのまま引き継ぎ、新規作成の場合は1になります。<br>
デフォルトは0です。

### -Proxied <Auto, True, False>
プロキシの有無の指定します。<br>
Auto、True、False、のいずれかの入力します。<br>
Autoの場合は更新時は既存のレコードのProxiedの値をそのまま引き継ぎ、新規作成時は指定しません。<br>
指定なしの場合、2022年6月時点では無効となるようです。<br>
[APIのドキュメント](https://api.cloudflare.com/#dns-records-for-a-zone-update-dns-record)によればTTLと異なり必須パラメーターでは無いのでこのような処理となっています。<br>
デフォルトはAutoです。

### -IPAddr <IPv4アドレス>
DNSレコードに登録する**IPv4アドレス**を固定的に指定します。<br>
通常は外部サイトから取得しますが、何らかの理由で別のIPアドレスを利用したい場合はこちらで指定してください。

### -IPv6Addr <IPv6アドレス>
DNSレコードに登録する**IPv6アドレス**を固定的に指定します。<br>
通常はWindowsから取得しますが、何らかの理由で別のIPアドレスを利用したい場合はこちらで指定してください。<br>
`-UseIPv6`パラメーターの指定が必要です。<br>
ここにIPv6アドレスが指定されていた場合、IPv6アドレス取得関係のパラメーターは無視されます。

### -Token <トークン> (必須)
CloudflareのAPIトークンを指定します。<br>
DNSのEDIT権限があればOKです。

### -Y
`-Hostname`で指定されたホスト名のレコードが登録されていない時、新たにレコードを作成します。<br>
スクリプトを直接編集する場合は`$Y = $True,`、パラメーターとして渡す場合は`-Y`とだけ指定すれば有効になります。(以下同じ)<br>
タイプミスだった時に面倒なのででデフォルトでは無効になっています。

### -NoIPv4
IPv4アドレス(Aレコード)を無効化します。

### -UseIPv6
IPv6アドレス(AAAA)レコードを有効化します。<br>
デフォルトでは指定なし(無効)になっています。IPv6関係の他のパラメーターはこのパラメーターが指定されていないとエラーになります。<br>
このスクリプトではWindowsからIPv6アドレスを取得しています。<br>
一般的なステートレスでIPv6アドレスを自動生成している環境であれば取得できると思いますが、自分の環境でしか試せていません。<br>
不具合が出る場合は`-IPv6Source`パラメーターを変更してください。

### -IPv6Source <Windows, Web>
Webを指定するとIPv6アドレスを外部サイトから取得します。<br>
Windowsで一時アドレスを無効にしていない場合は、一時アドレスが取得されると思います。<br>
デフォルトはWindowsです。

### -IPv6Index <数字>
WindowsからIPv6アドレスを取得する際に利用するインターフェースの番号(INDEX)を指定します。<br>
Powershellかコマンドプロンプトから`netsh interface ip show interface`と打てば`Idx`として出てきます。<br>
`-IPv6Source`が`Web`の時は無視されます。

### -UseTemp
WindowsからIPv6アドレスを取得する際、一時IPv6アドレスを利用します。<br>
デフォルトでは指定なし(無効)になっており、固定的な値が利用されます。<br>
`-IPv6Source`が`Web`の時は無視されます。

### -NoLog
デフォルトではスクリプトの置いてあるフォルダにログファイルを生成しますが、これを行わないようにします。<br>
コンソールへでの表示は変わりません。

### -LogLevel <Error, Info>
Infoを指定するとより詳細なログを表示します。<br>
コンソールでの表示も変わります。<br>
デフォルトはErrorです。

### -LogName <名前>
ログファイルの名前を指定します。<br>
拡張子も含めたものを指定してください。<br>
指定されていない時は`スクリプト名.log`で生成されます。<br>
タスクスケジューラーなどで一つのスクリプトを複数同時に起動するとログがごちゃまぜになるので引数で指定してあげると楽です。

### -Delay <秒>
指定した秒数だけスクリプトの冒頭で処理を停止します。<br>
タスクスケジューラでの起動時にネットワークエラーが出る場合に適当に指定してください。<br>
コンソールには表示されますが、ログには記載されません。

### -ZoneId
~~編集するZone IDを指定します。  
無くてもAPIトークンから自動で取得しますが、指定するとリクエスト一回分通信を節約できます。~~<br>
廃止しました

### -ExternalIp
`-IpAddress`に置き換えました

## メモ
* コメントに英語と日本語が混ざってるのは何となく
* `Invoke-RestMethod`ではなく`Invoke-WebRequest`なのは<br>
・そもそもCloudflareのAPIに接続できなかった時の例外<br>
・接続は出来たがエラーを返された時のHTTPのステータスコードとレスポンスの中身<br>の両方を楽に取得できるのが`Invoke-WebRequest`だったから
