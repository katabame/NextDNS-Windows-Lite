# nextdns-win-lite

NextDNS 用の軽量 Windows クライアントです。ローカルで DNS を受け付けて NextDNS の DoH
(`https://dns.nextdns.io/<プロファイルID>`) に転送し、そのとき **ホスト名と OS 情報** を
`X-Device-Id` / `X-Device-Name` / `X-Device-Model` ヘッダで送ります (LAN側IPアドレスは送りません)
(Linux 版公式 CLI と同じ方式)。NextDNS の Logs 画面にデバイス名・モデルが表示されます。

標準ライブラリのみで書かれており、外部依存はありません。

## 使い方 (管理者権限の PowerShell / コマンドプロンプト)

```
:: 1. 送信される情報を確認
nextdns-win.exe info -profile abc123

:: 2. NextDNS への疎通テスト (Logs 画面にデバイスが出るか確認)
nextdns-win.exe test -profile abc123

:: 3. 常駐登録 + DNS を 127.0.0.1 / ::1 に切り替え
nextdns-win.exe install -profile abc123

:: 元に戻す
nextdns-win.exe uninstall
```

`abc123` は自分のプロファイルID (my.nextdns.io の「設定」画面にある ID) に置き換えてください。

- `install` は、タスクスケジューラに「起動時に SYSTEM で実行」するタスク `NextDNSLite` を登録し、
  アクティブなネットワークアダプタの DNS を `127.0.0.1` / `::1` に設定します。
  DNS 設定を変えたくない場合は `-no-dns` を付けてください (後から `set-dns` / `reset-dns` で切り替え可能)。
- `uninstall` は DNS を自動取得 (DHCP) に戻し、タスクを削除します。
- 動作確認だけなら、管理者として `nextdns-win.exe run -profile abc123 -v` を実行し、
  別のターミナルで `nslookup example.com 127.0.0.1` を試せます。

## オプション

| オプション | 説明 |
|---|---|
| `-profile` | プロファイルID (環境変数 `NEXTDNS_PROFILE` でも可) |
| `-listen` | 待ち受けアドレス。既定 `127.0.0.1:53,[::1]:53` |
| `-bootstrap` | `dns.nextdns.io` の名前解決に使う DNS。既定 `1.1.1.1:53` |
| `-name` | デバイス名を上書き (既定: ホスト名) |
| `-model` | モデルを上書き (既定: 例 `Windows 11 Pro 24H2 (build 26100) x64`) |
| `-log` | ログファイル (サービス実行時のデバッグ用) |
| `-v` | 各クエリをログに出す |

## 仕組みと注意点

- **ブートストラップ**: システム DNS が自分自身 (127.0.0.1) を向いていても動くよう、
  `dns.nextdns.io` だけは `-bootstrap` の DNS で解決します (この問い合わせのみ平文)。
- **デバイス情報**: 名前・モデルに日本語など非 ASCII が含まれる場合は、HTTP ヘッダとして不正にならないよう
  パーセントエンコードして送ります。デバイスIDはマシンGUIDとプロファイルIDのハッシュ先頭5文字です。
- **障害時**: NextDNS に到達できないときは SERVFAIL を返します (平文 DNS へのフォールバックはしません)。
  不調時は `uninstall` か `reset-dns` で DNS を元に戻せます。
- Windows サービスではなくタスクスケジューラで常駐させる方式です (外部ライブラリ不要にするため)。
- VPN やセキュリティソフトが 53 番ポートを使っている場合は起動に失敗します。

## ビルド

Go 1.21 以降があれば、どの OS からでもビルドできます。

```
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o nextdns-win.exe .
GOOS=windows GOARCH=arm64 go build -ldflags "-s -w" -o nextdns-win-arm64.exe .
go test ./...
```
