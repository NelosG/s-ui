package service

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/alireza0/s-ui/database/model"
)

func TestReadSourceCountsOneLink(t *testing.T) {
	ss := base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw"))
	body := strings.Join([]string{
		"vless://uuid-1@5.6.7.8:443?security=reality&pbk=PK&sid=ab&sni=s.example&fp=chrome&type=tcp#NL | VLESS",
		"ss://" + ss + "@9.9.9.9:8443#A | SS",
		"vless://uuid-2@5.6.7.9:443?security=reality&pbk=PK&sid=ab&sni=s.example&fp=chrome&type=tcp#RU | VLESS",
		"not a link",
	}, "\n")
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.UserAgent()
		w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(body))))
	}))
	defer srv.Close()
	f := poolFilter{ua: "v2rayTun/1.0", allowed: map[string]bool{"vless": true, "shadowsocks": true}, skip: regexp.MustCompile(`^RU `)}
	src, nodes := readSource(srv.URL+"/sub/0123456789abcdef", f, false)
	if src.Error != "" || gotUA != "v2rayTun/1.0" {
		t.Fatalf("error %q, user agent %q", src.Error, gotUA)
	}
	if src.Fetched != 3 || src.Usable != 2 || len(nodes) != 2 || src.Types["vless"] != 1 || src.Types["shadowsocks"] != 1 {
		t.Fatalf("fetched %d usable %d types %v", src.Fetched, src.Usable, src.Types)
	}
	if strings.Contains(src.Link, "0123456789abcdef") {
		t.Fatalf("the token must not reach the report: %s", src.Link)
	}

	bad, _ := readSource("ftp://example.com/sub", f, false)
	if bad.Error == "" {
		t.Fatal("only http(s) links are fetched")
	}
}

func TestMergeManagedKeepsOperatorFields(t *testing.T) {
	current := json.RawMessage(`{"server":"1.1.1.1","server_port":443,"password":"old","tcp_keep_alive":"15s","tls":{"enabled":true,"server_name":"a"}}`)
	fresh := map[string]interface{}{"server": "2.2.2.2", "server_port": 443, "password": "new", "tls": map[string]interface{}{"enabled": true, "server_name": "a"}}
	merged, changed, err := mergeManaged(current, fresh)
	if err != nil || !changed {
		t.Fatalf("expected a change, got changed=%v err=%v", changed, err)
	}
	if merged["tcp_keep_alive"] != "15s" {
		t.Fatal("a hand-set dial option must survive the refresh")
	}
	if merged["server"] != "2.2.2.2" || merged["password"] != "new" {
		t.Fatalf("connection fields must follow the subscription: %v", merged)
	}
}

func TestMergeManagedUnchangedIsNoop(t *testing.T) {
	current := json.RawMessage(`{"server":"1.1.1.1","server_port":443,"uuid":"u","transport":{},"tls":{"enabled":true}}`)
	fresh := map[string]interface{}{"server": "1.1.1.1", "server_port": 443, "uuid": "u", "transport": map[string]interface{}{}, "tls": map[string]interface{}{"enabled": true}}
	if _, changed, _ := mergeManaged(current, fresh); changed {
		t.Fatal("same values with different Go number types must not count as a change")
	}
}

func TestPoolIdentityIgnoresNumberTypes(t *testing.T) {
	parsed := map[string]interface{}{"server": "2.27.203.199", "server_port": 443, "uuid": "u"}
	stored := model.Outbound{Type: "vless", Options: json.RawMessage(`{"server":"2.27.203.199","server_port":443,"uuid":"u","tcp_keep_alive":"15s"}`)}
	if poolIdentity("vless", parsed) != poolIdentity(stored.Type, outboundOptions(stored)) {
		t.Fatal("a freshly parsed link and the stored outbound for it must have the same identity")
	}
	other := map[string]interface{}{"server": "2.27.203.199", "server_port": 443, "uuid": "rotated"}
	if poolIdentity("vless", parsed) == poolIdentity("vless", other) {
		t.Fatal("new credentials make a different node")
	}
}

func TestDeadStreaks(t *testing.T) {
	pool := []model.Outbound{{Tag: "a"}, {Tag: "b"}, {Tag: "c"}, {Tag: "d"}}
	start := time.Unix(1_000_000, 0)
	since := map[string]int64{"b": start.Add(-time.Hour).Unix(), "c": start.Add(-time.Hour).Unix(), "gone": 1}
	alive := deadStreaks(map[string]string{"a": "dead", "b": "alive", "c": "unknown", "d": "suspect"}, pool, since, start)
	if alive != 2 {
		t.Fatalf("alive and suspect nodes count as alive, got %d", alive)
	}
	if since["a"] != start.Unix() {
		t.Fatal("a node found dead starts a streak now")
	}
	if _, ok := since["b"]; ok {
		t.Fatal("a node found alive ends its streak")
	}
	if since["c"] != start.Add(-time.Hour).Unix() {
		t.Fatal("a node not judged yet (right after a start) keeps its streak")
	}
	if _, ok := since["gone"]; ok {
		t.Fatal("streaks of nodes no longer in the pool are dropped")
	}
	deadStreaks(map[string]string{"a": "dead"}, pool, since, start.Add(time.Hour))
	if since["a"] != start.Unix() {
		t.Fatal("a streak keeps its start while the node stays dead")
	}
}

func TestMergeManagedDropsFieldTheProviderRemoved(t *testing.T) {
	current := json.RawMessage(`{"server":"1.1.1.1","server_port":443,"password":"p","obfs":{"type":"salamander","password":"x"}}`)
	fresh := map[string]interface{}{"server": "1.1.1.1", "server_port": 443, "password": "p"}
	merged, changed, _ := mergeManaged(current, fresh)
	if !changed {
		t.Fatal("obfs disappearing from the link is a change")
	}
	if _, has := merged["obfs"]; has {
		t.Fatal("obfs the provider no longer sets must be removed")
	}
}
