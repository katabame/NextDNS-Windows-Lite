// nextdns-win-lite: NextDNS 用の軽量 Windows クライアント。
//
// ローカル (127.0.0.1:53 / [::1]:53) で DNS を受け付け、NextDNS の DoH
// (https://dns.nextdns.io/<profile>) へ転送する。その際、公式 CLI と同じく
// X-Device-Id / X-Device-Name / X-Device-Model ヘッダを付け、
// ホスト名と OS 情報が NextDNS のログに表示されるようにする。
// (LAN側IPアドレス (X-Device-Ip) は送信しない。)
//
// 標準ライブラリのみで実装している (外部依存なし)。
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	version  = "0.1.0"
	taskName = "NextDNSLite"
	dohHost  = "dns.nextdns.io"
)

var profileRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

type config struct {
	Profile   string
	Listen    string
	Bootstrap string
	Name      string
	Model     string
	LogFile   string
	Verbose   bool
	NoDNS     bool
}

func main() {
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}

	var c config
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	fs.StringVar(&c.Profile, "profile", os.Getenv("NEXTDNS_PROFILE"), "NextDNS のプロファイルID (例: abc123)")
	fs.StringVar(&c.Listen, "listen", "127.0.0.1:53,[::1]:53", "待ち受けアドレス (カンマ区切り)")
	fs.StringVar(&c.Bootstrap, "bootstrap", "1.1.1.1:53", "dns.nextdns.io の名前解決に使うDNSサーバ")
	fs.StringVar(&c.Name, "name", "", "送信するデバイス名 (既定: ホスト名)")
	fs.StringVar(&c.Model, "model", "", "送信するデバイスモデル (既定: Windowsの製品名/バージョン)")
	fs.StringVar(&c.LogFile, "log", "", "ログファイルのパス (既定: 標準エラー)")
	fs.BoolVar(&c.Verbose, "v", false, "各クエリをログに出す")
	fs.BoolVar(&c.NoDNS, "no-dns", false, "install時にシステムのDNS設定を変更しない")
	fs.Usage = usage
	_ = fs.Parse(args)

	var err error
	switch cmd {
	case "run":
		err = cmdRun(c)
	case "info":
		err = cmdInfo(c)
	case "test":
		err = cmdTest(c)
	case "install":
		err = cmdInstall(c)
	case "uninstall":
		err = cmdUninstall()
	case "set-dns":
		err = setDNS()
	case "reset-dns":
		err = resetDNS()
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "不明なコマンド: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "エラー:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `nextdns-win-lite %s

使い方:
  nextdns-win run       -profile ID [オプション]   DNSプロキシを起動 (既定)
  nextdns-win info      -profile ID                送信するデバイス情報を表示
  nextdns-win test      -profile ID                NextDNSへ疎通テスト
  nextdns-win install   -profile ID                タスクスケジューラに登録して起動し、DNSを127.0.0.1に設定 (管理者)
  nextdns-win uninstall                            登録解除してDNS設定を自動(DHCP)に戻す (管理者)
  nextdns-win set-dns | reset-dns                  DNS設定のみ変更/復元 (管理者)

オプション:
  -profile   プロファイルID (環境変数 NEXTDNS_PROFILE でも可)
  -listen    待ち受けアドレス (既定 127.0.0.1:53,[::1]:53)
  -bootstrap dns.nextdns.io の解決用DNS (既定 1.1.1.1:53)
  -name      デバイス名を上書き (既定 ホスト名)
  -model     デバイスモデルを上書き (既定 OS情報)
  -log       ログファイル
  -v         詳細ログ
  -no-dns    install時にDNS設定を変更しない
`, version)
}

// ---------------------------------------------------------------- デバイス情報

type deviceInfo struct {
	ID    string
	Name  string
	Model string
}

func newDeviceInfo(c config) *deviceInfo {
	name := c.Name
	if name == "" {
		name, _ = os.Hostname()
	}
	model := c.Model
	if model == "" {
		model = osDescription()
	}
	guid := regQuery(`HKLM\SOFTWARE\Microsoft\Cryptography`, "MachineGuid")
	if guid == "" {
		guid, _ = os.Hostname()
	}
	sum := sha256.Sum256([]byte(guid + "|" + c.Profile))
	id := strings.ToUpper(hex.EncodeToString(sum[:]))[:5]
	return &deviceInfo{ID: id, Name: name, Model: model}
}

// headerSafe はHTTPヘッダに載せられる値にする。改行や空白の連続は畳み、
// 非ASCIIを含む場合はパーセントエンコードする (不正なヘッダ値で DoH が
// 失敗する事故を避けるため)。
func headerSafe(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			return url.PathEscape(s)
		}
	}
	return s
}

func osDescription() string {
	arch := map[string]string{"amd64": "x64", "arm64": "ARM64", "386": "x86"}[runtime.GOARCH]
	if arch == "" {
		arch = runtime.GOARCH
	}
	if runtime.GOOS != "windows" {
		if b, err := os.ReadFile("/etc/os-release"); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(l, "PRETTY_NAME=") {
					return strings.Trim(l[len("PRETTY_NAME="):], `"`) + " " + arch
				}
			}
		}
		return runtime.GOOS + " " + arch
	}
	key := `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	product := regQuery(key, "ProductName")
	disp := regQuery(key, "DisplayVersion")
	if disp == "" {
		disp = regQuery(key, "ReleaseId")
	}
	build := regQuery(key, "CurrentBuildNumber")
	if build == "" {
		build = regQuery(key, "CurrentBuild")
	}
	// Windows 11 でも ProductName が "Windows 10 ..." のままになるため補正する。
	var n int
	fmt.Sscanf(build, "%d", &n)
	if n >= 22000 {
		product = strings.Replace(product, "Windows 10", "Windows 11", 1)
	}
	if product == "" {
		product = "Windows"
	}
	parts := []string{product}
	if disp != "" {
		parts = append(parts, disp)
	}
	if build != "" {
		parts = append(parts, "(build "+build+")")
	}
	parts = append(parts, arch)
	return strings.Join(parts, " ")
}

// regQuery は reg.exe で REG_SZ の値を読む。Windows 以外や失敗時は空文字。
func regQuery(key, name string) string {
	if runtime.GOOS != "windows" {
		return ""
	}
	out, err := exec.Command("reg", "query", key, "/v", name).Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if i := strings.Index(line, "REG_SZ"); i >= 0 && strings.Contains(line, name) {
			return strings.TrimSpace(line[i+len("REG_SZ"):])
		}
	}
	return ""
}

// ---------------------------------------------------------------- DoH上流

// bootDialer は dns.nextdns.io だけをブートストラップDNSで名前解決する。
// (システムDNSが 127.0.0.1 = 自分自身を向いていても無限ループにならない)
type bootDialer struct {
	d    net.Dialer
	res  *net.Resolver
	mu   sync.Mutex
	ips  []string
	at   time.Time
	host string
}

func newBootDialer(host, bootstrap string) *bootDialer {
	b := &bootDialer{host: host}
	b.d = net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	b.res = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return b.d.DialContext(ctx, network, bootstrap)
		},
	}
	return b
}

func (b *bootDialer) lookup(ctx context.Context) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.ips) > 0 && time.Since(b.at) < 5*time.Minute {
		return b.ips
	}
	lctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ips, err := b.res.LookupHost(lctx, b.host)
	if err != nil || len(ips) == 0 {
		return b.ips // 失敗時は前回の結果を使い回す
	}
	// IPv4 を先に試す (IPv6 が不通の環境で待たされないように)
	sort.SliceStable(ips, func(i, j int) bool {
		return !strings.Contains(ips[i], ":") && strings.Contains(ips[j], ":")
	})
	b.ips, b.at = ips, time.Now()
	return b.ips
}

func (b *bootDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil || h != b.host {
		return b.d.DialContext(ctx, network, addr)
	}
	var last error
	for _, ip := range b.lookup(ctx) {
		c, err := b.d.DialContext(ctx, network, net.JoinHostPort(ip, p))
		if err == nil {
			return c, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("dns.nextdns.io を名前解決できません (bootstrap を確認してください)")
	}
	return nil, last
}

type upstream struct {
	url    string
	client *http.Client
	dev    *deviceInfo
}

func newUpstream(c config, dev *deviceInfo) *upstream {
	bd := newBootDialer(dohHost, c.Bootstrap)
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         bd.DialContext,
		ForceAttemptHTTP2:   true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	}
	return &upstream{
		url:    "https://" + dohHost + "/" + url.PathEscape(c.Profile),
		client: &http.Client{Transport: tr},
		dev:    dev,
	}
}

func (u *upstream) resolve(ctx context.Context, q []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.url, bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "nextdns-win-lite/"+version)
	req.Header.Set("X-Device-Id", u.dev.ID)
	if v := headerSafe(u.dev.Name); v != "" {
		req.Header.Set("X-Device-Name", v)
	}
	if v := headerSafe(u.dev.Model); v != "" {
		req.Header.Set("X-Device-Model", v)
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
	}
	if len(body) < 12 {
		return nil, errors.New("DoH応答が短すぎます")
	}
	return body, nil
}

// ---------------------------------------------------------------- DNSメッセージ補助

// questionEnd は最初の質問セクションの終端位置を返す。
func questionEnd(q []byte) int {
	i := 12
	for {
		if i >= len(q) {
			return -1
		}
		l := int(q[i])
		if l == 0 {
			i++
			break
		}
		if l&0xC0 != 0 {
			return -1
		}
		i += l + 1
	}
	i += 4
	if i > len(q) {
		return -1
	}
	return i
}

// reply はクエリから、指定のRCODE(とTCフラグ)だけを持つ応答を作る。
func reply(q []byte, rcode byte, tc bool) []byte {
	end := questionEnd(q)
	if end < 0 {
		out := make([]byte, 12)
		copy(out, q[:2])
		out[2], out[3] = 0x81, 0x80|rcode
		return out
	}
	out := append([]byte(nil), q[:end]...)
	out[2] = 0x80 | (q[2] & 0x79) // QR=1, opcode/RD を維持
	if tc {
		out[2] |= 0x02
	}
	out[3] = 0x80 | rcode // RA=1
	binary.BigEndian.PutUint16(out[4:], 1)
	for i := 6; i < 12; i++ {
		out[i] = 0
	}
	return out
}

// ---------------------------------------------------------------- サーバ

type handler struct {
	up      *upstream
	verbose bool
}

func (h *handler) handle(q []byte, udp bool) []byte {
	if len(q) < 12 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	start := time.Now()
	resp, err := h.up.resolve(ctx, q)
	if err != nil {
		log.Printf("上流エラー: %v", err)
		return reply(q, 2, false) // SERVFAIL
	}
	if h.verbose {
		log.Printf("ok %d bytes %s", len(resp), time.Since(start).Round(time.Millisecond))
	}
	if udp && len(resp) > 1232 {
		return reply(q, resp[3]&0x0F, true) // UDPで大きすぎる場合はTCで再問い合わせさせる
	}
	return resp
}

func serveUDP(ctx context.Context, addr string, h *handler) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); pc.Close() }()
	log.Printf("UDP 待ち受け: %s", addr)
	sem := make(chan struct{}, 256)
	buf := make([]byte, 65535)
	for {
		n, ra, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		q := append([]byte(nil), buf[:n]...)
		select {
		case sem <- struct{}{}:
		default:
			continue // 過負荷時は破棄
		}
		go func() {
			defer func() { <-sem }()
			if resp := h.handle(q, true); resp != nil {
				pc.WriteTo(resp, ra)
			}
		}()
	}
}

func serveTCP(ctx context.Context, addr string, h *handler) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); ln.Close() }()
	log.Printf("TCP 待ち受け: %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			defer conn.Close()
			for {
				conn.SetReadDeadline(time.Now().Add(10 * time.Second))
				var lb [2]byte
				if _, err := io.ReadFull(conn, lb[:]); err != nil {
					return
				}
				msg := make([]byte, binary.BigEndian.Uint16(lb[:]))
				if _, err := io.ReadFull(conn, msg); err != nil {
					return
				}
				resp := h.handle(msg, false)
				if resp == nil {
					return
				}
				out := make([]byte, 2, 2+len(resp))
				binary.BigEndian.PutUint16(out, uint16(len(resp)))
				out = append(out, resp...)
				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err := conn.Write(out); err != nil {
					return
				}
			}
		}()
	}
}

// ---------------------------------------------------------------- コマンド

func checkProfile(c config) error {
	if c.Profile == "" {
		return errors.New("-profile (プロファイルID) を指定してください")
	}
	if !profileRe.MatchString(c.Profile) {
		return errors.New("プロファイルIDは英数字・-・_ のみ使えます")
	}
	return nil
}

func setupLog(c config) (func(), error) {
	if c.LogFile == "" {
		return func() {}, nil
	}
	f, err := os.OpenFile(c.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	log.SetOutput(f)
	return func() { f.Close() }, nil
}

func cmdRun(c config) error {
	if err := checkProfile(c); err != nil {
		return err
	}
	closeLog, err := setupLog(c)
	if err != nil {
		return err
	}
	defer closeLog()

	dev := newDeviceInfo(c)
	h := &handler{up: newUpstream(c, dev), verbose: c.Verbose}
	log.Printf("nextdns-win-lite %s 起動: profile=%s name=%q model=%q id=%s",
		version, c.Profile, dev.Name, dev.Model, dev.ID)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	var mu sync.Mutex
	started := 0
	for _, addr := range strings.Split(c.Listen, ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		for _, srv := range []func(context.Context, string, *handler) error{serveUDP, serveTCP} {
			srv := srv
			// 先にbindできるか確認するため、起動エラーは最初の応答で拾う
			errCh := make(chan error, 1)
			go func() { errCh <- srv(ctx, addr, h) }()
			select {
			case err := <-errCh:
				log.Printf("%s の待ち受けに失敗: %v", addr, err)
			case <-time.After(300 * time.Millisecond):
				mu.Lock()
				started++
				mu.Unlock()
				wg.Add(1)
				go func() { defer wg.Done(); <-errCh }()
			}
		}
	}
	if started == 0 {
		return errors.New("どのアドレスでも待ち受けできませんでした (管理者権限で実行しているか、ポート53が使用中でないか確認してください)")
	}
	<-ctx.Done()
	wg.Wait()
	log.Printf("停止します")
	return nil
}

func cmdInfo(c config) error {
	dev := newDeviceInfo(c)
	fmt.Printf("X-Device-Id    : %s\n", dev.ID)
	fmt.Printf("X-Device-Name  : %s\n", headerSafe(dev.Name))
	fmt.Printf("X-Device-Model : %s\n", headerSafe(dev.Model))
	return nil
}

func cmdTest(c config) error {
	if err := checkProfile(c); err != nil {
		return err
	}
	dev := newDeviceInfo(c)
	up := newUpstream(c, dev)
	// example.com の A レコードを問い合わせる
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range []string{"example", "com"} {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	resp, err := up.resolve(ctx, q)
	if err != nil {
		return err
	}
	fmt.Printf("成功: %d bytes, RCODE=%d, answers=%d, %s\n", len(resp), resp[3]&0x0F,
		binary.BigEndian.Uint16(resp[6:]), time.Since(start).Round(time.Millisecond))
	fmt.Printf("送信したデバイス情報: id=%s name=%q model=%q\n", dev.ID, headerSafe(dev.Name), headerSafe(dev.Model))
	fmt.Println("NextDNS の Logs 画面にこのデバイスが表示されるか確認してください。")
	return nil
}

func requireWindows() error {
	if runtime.GOOS != "windows" {
		return errors.New("このコマンドは Windows 専用です")
	}
	return nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func powershell(script string) error {
	return run("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
}

func setDNS() error {
	if err := requireWindows(); err != nil {
		return err
	}
	return powershell(`Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object { ` +
		`Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses '127.0.0.1','::1' }; ` +
		`Clear-DnsClientCache`)
}

func resetDNS() error {
	if err := requireWindows(); err != nil {
		return err
	}
	return powershell(`Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object { ` +
		`Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses }; ` +
		`Clear-DnsClientCache`)
}

func cmdInstall(c config) error {
	if err := requireWindows(); err != nil {
		return err
	}
	if err := checkProfile(c); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	tr := fmt.Sprintf(`"%s" run -profile %s`, exe, c.Profile)
	if c.Name != "" {
		tr += fmt.Sprintf(` -name "%s"`, c.Name)
	}
	if c.Model != "" {
		tr += fmt.Sprintf(` -model "%s"`, c.Model)
	}
	if c.Bootstrap != "1.1.1.1:53" {
		tr += " -bootstrap " + c.Bootstrap
	}
	if c.LogFile != "" {
		tr += fmt.Sprintf(` -log "%s"`, c.LogFile)
	}
	if err := run("schtasks", "/Create", "/TN", taskName, "/TR", tr,
		"/SC", "ONSTART", "/RU", "SYSTEM", "/RL", "HIGHEST", "/F"); err != nil {
		return fmt.Errorf("タスクの登録に失敗 (管理者として実行していますか?): %w", err)
	}
	if err := run("schtasks", "/Run", "/TN", taskName); err != nil {
		return fmt.Errorf("タスクの開始に失敗: %w", err)
	}
	time.Sleep(2 * time.Second) // プロキシが待ち受けを始めてからDNSを切り替える
	if c.NoDNS {
		fmt.Println("インストール完了。DNS設定は変更していません (set-dns で切り替え可能)。")
		return nil
	}
	if err := setDNS(); err != nil {
		return err
	}
	fmt.Println("インストール完了。DNSを 127.0.0.1 / ::1 に設定しました。")
	return nil
}

func cmdUninstall() error {
	if err := requireWindows(); err != nil {
		return err
	}
	if err := resetDNS(); err != nil {
		fmt.Fprintln(os.Stderr, "DNS設定の復元に失敗:", err)
	}
	_ = run("schtasks", "/End", "/TN", taskName)
	if err := run("schtasks", "/Delete", "/TN", taskName, "/F"); err != nil {
		return err
	}
	fmt.Println("アンインストール完了。DNSを自動取得(DHCP)に戻しました。")
	return nil
}
