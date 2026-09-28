package util

import (
	"encoding/base64"
	"testing"
)

func TestParsePoolLinkHysteria2KeepsFullPassword(t *testing.T) {
	node, ok := ParsePoolLink("hy2://user:secret@1.2.3.4:443?obfs=salamander&obfs-password=ob&sni=x.example#FI%20%7C%20HY2")
	if !ok {
		t.Fatal("hy2 link rejected")
	}
	if node.Tag != "FI | HY2" || node.Type != "hysteria2" {
		t.Fatalf("got tag %q type %q", node.Tag, node.Type)
	}
	if node.Options["password"] != "user:secret" {
		t.Fatalf("password truncated: %v", node.Options["password"])
	}
	obfs := node.Options["obfs"].(map[string]interface{})
	if obfs["password"] != "ob" || obfs["type"] != "salamander" {
		t.Fatalf("obfs: %v", obfs)
	}
}

func TestParsePoolLinkVlessReality(t *testing.T) {
	node, ok := ParsePoolLink("vless://uuid-1@5.6.7.8:443?security=reality&pbk=PK&sid=ab&sni=s.example&fp=firefox&flow=xtls-rprx-vision&type=tcp#NL | VLESS")
	if !ok {
		t.Fatal("vless link rejected")
	}
	tls := node.Options["tls"].(map[string]interface{})
	reality := tls["reality"].(map[string]interface{})
	if node.Options["uuid"] != "uuid-1" || node.Options["flow"] != "xtls-rprx-vision" || reality["public_key"] != "PK" || reality["short_id"] != "ab" {
		t.Fatalf("unexpected options %v", node.Options)
	}
	if tls["utls"].(map[string]interface{})["fingerprint"] != "firefox" {
		t.Fatal("fingerprint lost")
	}
	if node.Options["server_port"] != 443 {
		t.Fatalf("port %v", node.Options["server_port"])
	}
}

func TestParsePoolLinkRejectsXHTTP(t *testing.T) {
	if _, ok := ParsePoolLink("vless://u@1.1.1.1:443?type=xhttp&security=reality#X | XHTTP"); ok {
		t.Fatal("xhttp must be skipped, sing-box cannot dial it")
	}
}

func TestParsePoolLinkShadowsocksBothForms(t *testing.T) {
	user := base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw"))
	for _, link := range []string{
		"ss://" + user + "@9.9.9.9:8443#A | SS",
		"ss://" + base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw@9.9.9.9:8443")) + "#A | SS",
	} {
		node, ok := ParsePoolLink(link)
		if !ok {
			t.Fatalf("rejected %s", link)
		}
		if node.Options["method"] != "chacha20-ietf-poly1305" || node.Options["password"] != "pw" || node.Options["server"] != "9.9.9.9" {
			t.Fatalf("%s -> %v", link, node.Options)
		}
	}
}

func TestDecodeSubscriptionBase64(t *testing.T) {
	raw := base64.StdEncoding.EncodeToString([]byte("trojan://p@h:1#T\nvless://u@h:2#V\n"))
	if got := DecodeSubscription([]byte(raw)); got != "trojan://p@h:1#T\nvless://u@h:2#V\n" {
		t.Fatalf("got %q", got)
	}
}
