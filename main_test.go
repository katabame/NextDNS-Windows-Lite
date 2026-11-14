package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func testQuery() []byte {
	q := []byte{0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range []string{"example", "com"} {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

func freePort(t *testing.T, network string) string {
	t.Helper()
	if network == "udp" {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		return pc.LocalAddr().String()
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// 模擬DoHサーバ: 受け取ったヘッダを記録し、クエリにQRを立てて返す。
func mockDoH(t *testing.T) (*httptest.Server, *http.Header, *sync.Mutex) {
	var mu sync.Mutex
	var got http.Header
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Clone()
		mu.Unlock()
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad", 400)
			return
		}
		b, _ := io.ReadAll(r.Body)
		b[2] |= 0x80
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv, &got, &mu
}

func TestProxyUDPAndTCPWithDeviceHeaders(t *testing.T) {
	srv, got, mu := mockDoH(t)
	dev := &deviceInfo{ID: "ABCDE", Name: "My PC", Model: "Windows 11 Pro 24H2 (build 26100) x64"}
	h := &handler{up: &upstream{url: srv.URL + "/abc123", client: srv.Client(), dev: dev}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	uaddr, taddr := freePort(t, "udp"), freePort(t, "tcp")
	go serveUDP(ctx, uaddr, h)
	go serveTCP(ctx, taddr, h)
	time.Sleep(200 * time.Millisecond)

	// UDP
	c, err := net.Dial("udp", uaddr)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write(testQuery())
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("UDP応答なし: %v", err)
	}
	if buf[0] != 0xAB || buf[1] != 0xCD || buf[2]&0x80 == 0 || n != len(testQuery()) {
		t.Fatalf("UDP応答が不正: % x", buf[:n])
	}

	mu.Lock()
	hd := *got
	mu.Unlock()
	for k, want := range map[string]string{
		"X-Device-Id":    "ABCDE",
		"X-Device-Name":  "My PC",
		"X-Device-Model": "Windows 11 Pro 24H2 (build 26100) x64",
	} {
		if hd.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, hd.Get(k), want)
		}
	}

	if _, ok := hd["X-Device-Ip"]; ok {
		t.Errorf("X-Device-Ip は送信しない仕様です: %q", hd.Get("X-Device-Ip"))
	}

	// TCP (2バイト長プレフィックス)
	tc, err := net.Dial("tcp", taddr)
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(3 * time.Second))
	q := testQuery()
	lb := make([]byte, 2)
	binary.BigEndian.PutUint16(lb, uint16(len(q)))
	tc.Write(append(lb, q...))
	if _, err := io.ReadFull(tc, lb); err != nil {
		t.Fatalf("TCP応答なし: %v", err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(lb))
	io.ReadFull(tc, resp)
	if resp[2]&0x80 == 0 {
		t.Fatalf("TCP応答が不正: % x", resp)
	}
}

func TestServfailWhenUpstreamDown(t *testing.T) {
	srv, _, _ := mockDoH(t)
	url := srv.URL + "/abc123"
	client := srv.Client()
	srv.Close() // 上流を落とす
	h := &handler{up: &upstream{url: url, client: client, dev: &deviceInfo{ID: "ABCDE", Name: "x"}}}
	resp := h.handle(testQuery(), true)
	if resp == nil || resp[3]&0x0F != 2 || resp[2]&0x80 == 0 {
		t.Fatalf("SERVFAILになっていない: % x", resp)
	}
	if resp[0] != 0xAB || resp[1] != 0xCD {
		t.Fatalf("IDが保持されていない")
	}
}

func TestTruncatedReplyForLargeUDP(t *testing.T) {
	r := reply(testQuery(), 0, true)
	if r[2]&0x02 == 0 || r[2]&0x80 == 0 || binary.BigEndian.Uint16(r[6:]) != 0 {
		t.Fatalf("TC応答が不正: % x", r)
	}
}

func TestHeaderSafe(t *testing.T) {
	cases := map[string]string{
		"My PC":        "My PC",
		"  a \r\n b ":  "a b",
		"田中のPC":        "%E7%94%B0%E4%B8%AD%E3%81%AEPC",
		"Bob's iPhone": "Bob's iPhone",
	}
	for in, want := range cases {
		if got := headerSafe(in); got != want {
			t.Errorf("headerSafe(%q) = %q, want %q", in, got, want)
		}
	}
	if strings.ContainsAny(headerSafe("a\r\nX-Evil: 1"), "\r\n") {
		t.Error("改行が残っている")
	}
}
