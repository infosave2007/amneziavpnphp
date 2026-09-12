// Run this file from the root of the pinned amneziawg-go checkout.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func parseConfig(text string) map[string]string {
	out := map[string]string{}
	section := ""
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		p := strings.SplitN(line, "=", 2)
		if len(p) == 2 {
			out[section+":"+strings.ToLower(strings.TrimSpace(p[0]))] = strings.TrimSpace(p[1])
		}
	}
	return out
}

func keyHex(v string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("invalid 32-byte key")
	}
	return hex.EncodeToString(b), nil
}

func main() {
	stage := "init"
	defer func() {
		if recover() != nil {
			encoded, _ := json.Marshal(map[string]any{"success": false, "error": "probe_failed", "stage": stage})
			fmt.Println(string(encoded))
			os.Exit(1)
		}
	}()
	configPath := flag.String("config", "", "client .conf path")
	gateway := flag.String("gateway", "10.8.31.1", "tunnel gateway")
	httpsHost := flag.String("https-host", "example.com", "DNS and HTTPS target")
	expectedEgress := flag.String("expected-egress", "", "expected public egress IP")
	timeout := flag.Duration("timeout", 20*time.Second, "probe timeout")
	flag.Parse()
	if *configPath == "" {
		panic("-config is required")
	}
	conf, err := os.ReadFile(*configPath)
	if err != nil {
		panic(err)
	}
	c := parseConfig(string(conf))
	stage = "config"
	priv, err := keyHex(c["[Interface]:privatekey"])
	if err != nil {
		panic(err)
	}
	pub, err := keyHex(c["[Peer]:publickey"])
	if err != nil {
		panic(err)
	}
	psk, err := keyHex(c["[Peer]:presharedkey"])
	if err != nil {
		panic(err)
	}
	hp, err := keyHex(c["[Interface]:headerprotectionkey"])
	if err != nil {
		panic(err)
	}
	addr := strings.Split(c["[Interface]:address"], "/")[0]
	dns := "1.1.1.1"
	if value := c["[Interface]:dns"]; value != "" {
		dns = strings.TrimSpace(strings.Split(value, ",")[0])
	}
	endpoint := c["[Peer]:endpoint"]
	if addr == "" || endpoint == "" {
		panic("config lacks address or endpoint")
	}
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(addr)}, []netip.Addr{netip.MustParseAddr(dns)}, 1280)
	if err != nil {
		panic(err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))
	stage = "device"
	defer dev.Close()
	lines := []string{"private_key=" + priv}
	names := map[string]string{
		"jc": "jc", "jmin": "jmin", "jmax": "jmax", "s1": "s1", "s2": "s2", "s3": "s3", "s4": "s4",
		"h1": "h1", "h2": "h2", "h3": "h3", "h4": "h4", "i1": "i1", "i2": "i2", "i3": "i3", "i4": "i4", "i5": "i5",
		"contentpaddingaddition": "content_padding_addition", "rekeyaftertime": "rekey_after_time", "rekeytimeout": "rekey_timeout",
		"rejectaftertime": "reject_after_time", "keepalivetimeout": "keepalive_timeout", "maxhandshakeattempts": "max_handshake_attempts",
	}
	for source, target := range names {
		if v := c["[Interface]:"+source]; v != "" {
			lines = append(lines, target+"="+v)
		}
	}
	lines = append(lines, "header_protection_key="+hp)
	for _, pair := range [][2]string{{"randomtrailers", "random_trailers"}, {"disablecookies", "disable_cookies"}} {
		v := strings.ToLower(c["[Interface]:"+pair[0]])
		if v != "" {
			lines = append(lines, pair[1]+"="+strconv.FormatBool(v == "on" || v == "true" || v == "1"))
		}
	}
	lines = append(lines, "public_key="+pub, "preshared_key="+psk, "endpoint="+endpoint, "allowed_ip=0.0.0.0/0")
	if v := c["[Peer]:persistentkeepalive"]; v != "" {
		lines = append(lines, "persistent_keepalive_interval="+v)
	}
	if err := dev.IpcSet(strings.Join(lines, "\n") + "\n"); err != nil {
		panic(err)
	}
	if err := dev.Up(); err != nil {
		panic(err)
	}
	stage = "icmp_dial"
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	ping, err := tnet.Dial("ping4", *gateway)
	if err != nil {
		panic(err)
	}
	defer ping.Close()
	_ = ping.SetDeadline(time.Now().Add(*timeout))
	seqBytes := make([]byte, 2)
	_, _ = rand.Read(seqBytes)
	seq := int(seqBytes[0])<<8 | int(seqBytes[1])
	packet, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{Seq: seq, Data: nonce}}).Marshal(nil)
	started := time.Now()
	if _, err := ping.Write(packet); err != nil {
		panic(err)
	}
	stage = "icmp_read"
	n, err := ping.Read(packet)
	if err != nil {
		panic(err)
	}
	reply, err := icmp.ParseMessage(1, packet[:n])
	if err != nil {
		panic(err)
	}
	echo, ok := reply.Body.(*icmp.Echo)
	if !ok || echo.Seq != seq || !bytes.Equal(echo.Data, nonce) {
		panic("nonce echo mismatch")
	}
	pingLatency := time.Since(started)
	stage = "dns"
	addresses, err := tnet.LookupContextHost(ctx, *httpsHost)
	if err != nil || len(addresses) == 0 {
		panic("DNS lookup failed")
	}
	transport := &http.Transport{
		DialContext:     tnet.DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{Transport: transport, Timeout: *timeout}
	stage = "https"
	request, _ := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+*httpsHost+"/", nil)
	httpsStarted := time.Now()
	response, err := client.Do(request)
	if err != nil {
		panic(err)
	}
	response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 500 {
		panic("unexpected HTTPS status")
	}
	stage = "egress"
	egressRequest, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org/", nil)
	egressResponse, err := client.Do(egressRequest)
	if err != nil {
		panic("egress lookup failed")
	}
	egressBody := make([]byte, 64)
	egressN, _ := egressResponse.Body.Read(egressBody)
	egressResponse.Body.Close()
	egress := strings.TrimSpace(string(egressBody[:egressN]))
	if *expectedEgress != "" && egress != *expectedEgress {
		panic("egress mismatch")
	}
	egressHash := sha256.Sum256([]byte(egress))
	configHash := sha256.Sum256(conf)
	nonceHash := sha256.Sum256(nonce)
	result := map[string]any{"success": true, "config_sha256": hex.EncodeToString(configHash[:]), "nonce_sha256": hex.EncodeToString(nonceHash[:]), "icmp_latency_ms": pingLatency.Milliseconds(), "dns_answers": len(addresses), "https_status": response.StatusCode, "https_latency_ms": time.Since(httpsStarted).Milliseconds(), "egress_matches_expected": *expectedEgress == "" || egress == *expectedEgress, "egress_sha256": hex.EncodeToString(egressHash[:])}
	encoded, _ := json.Marshal(result)
	fmt.Println(string(encoded))
}
