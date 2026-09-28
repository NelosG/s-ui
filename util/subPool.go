package util

import (
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"
)

// PoolNode is one proxy parsed from a provider subscription, already in sing-box outbound
// shape. Tag is the link's fragment, which the provider keeps stable across credential
// rotations, so it is what ties a subscription entry to a panel outbound.
type PoolNode struct {
	Tag     string
	Type    string
	Options map[string]interface{}
}

var poolSchemes = map[string]string{
	"vless":     "vless",
	"trojan":    "trojan",
	"hy2":       "hysteria2",
	"hysteria2": "hysteria2",
	"ss":        "shadowsocks",
}

// DecodeSubscription accepts a raw link list or its base64 form.
func DecodeSubscription(raw []byte) string {
	text := strings.TrimSpace(string(raw))
	if strings.Contains(text[:min(len(text), 200)], "://") {
		return text
	}
	compact := strings.Join(strings.Fields(text), "")
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if decoded, err := enc.DecodeString(compact); err == nil {
			return string(decoded)
		}
	}
	return text
}

// ParsePoolLink turns one share link into a node. Unsupported links (other schemes, XHTTP
// and other transports sing-box cannot speak) return ok=false.
//
// The built-in link converter keeps only the user part of a hysteria2 "user:pass@host"
// link, which once killed the whole HY2 pool; here the full userinfo is the password.
func ParsePoolLink(link string) (PoolNode, bool) {
	scheme, rest, found := strings.Cut(strings.TrimSpace(link), "://")
	if !found {
		return PoolNode{}, false
	}
	typ, known := poolSchemes[strings.ToLower(scheme)]
	if !known {
		return PoolNode{}, false
	}
	var fragment string
	if i := strings.Index(rest, "#"); i >= 0 {
		fragment, _ = url.PathUnescape(rest[i+1:])
		rest = rest[:i]
	}
	query := url.Values{}
	if i := strings.Index(rest, "?"); i >= 0 {
		query, _ = url.ParseQuery(rest[i+1:])
		rest = rest[:i]
	}
	if typ == "shadowsocks" && !strings.Contains(rest, "@") {
		decoded, err := decodeB64(rest)
		if err != nil {
			return PoolNode{}, false
		}
		rest = decoded
	}
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return PoolNode{}, false
	}
	userinfo, hostport := rest[:at], rest[at+1:]
	hostport, _, _ = strings.Cut(hostport, "/")
	userinfo, _ = url.PathUnescape(userinfo)
	colon := strings.LastIndex(hostport, ":")
	if colon < 0 {
		return PoolNode{}, false
	}
	host := strings.Trim(hostport[:colon], "[]")
	port, err := strconv.Atoi(hostport[colon+1:])
	if err != nil {
		return PoolNode{}, false
	}
	transport := strings.ToLower(query.Get("type"))
	if transport != "" && transport != "tcp" && transport != "raw" {
		return PoolNode{}, false
	}
	opts := map[string]interface{}{"server": host, "server_port": port}
	switch typ {
	case "vless":
		opts["uuid"] = userinfo
		if flow := query.Get("flow"); flow != "" {
			opts["flow"] = flow
		}
		opts["packet_encoding"] = "xudp"
		opts["transport"] = map[string]interface{}{}
		tls := map[string]interface{}{
			"enabled":     true,
			"server_name": query.Get("sni"),
			"utls":        map[string]interface{}{"enabled": true, "fingerprint": orDefault(query.Get("fp"), "chrome")},
		}
		if query.Get("security") == "reality" || query.Get("pbk") != "" {
			tls["reality"] = map[string]interface{}{"enabled": true, "public_key": query.Get("pbk"), "short_id": query.Get("sid")}
		}
		opts["tls"] = tls
	case "trojan":
		opts["password"] = userinfo
		opts["transport"] = map[string]interface{}{}
		opts["tls"] = map[string]interface{}{"enabled": true, "server_name": query.Get("sni")}
	case "hysteria2":
		opts["password"] = userinfo
		if obfs := query.Get("obfs"); obfs != "" {
			opts["obfs"] = map[string]interface{}{"type": obfs, "password": query.Get("obfs-password")}
		}
		insecure := query.Get("insecure") == "1" || query.Get("insecure") == "true"
		opts["tls"] = map[string]interface{}{"enabled": true, "server_name": query.Get("sni"), "insecure": insecure}
	case "shadowsocks":
		if !strings.Contains(userinfo, ":") {
			decoded, err := decodeB64(userinfo)
			if err != nil {
				return PoolNode{}, false
			}
			userinfo = decoded
		}
		method, password, ok := strings.Cut(userinfo, ":")
		if !ok {
			return PoolNode{}, false
		}
		opts["method"], opts["password"] = method, password
	}
	return PoolNode{Tag: strings.TrimSpace(fragment), Type: typ, Options: opts}, true
}

func decodeB64(s string) (string, error) {
	// Providers mix padded and unpadded, standard and URL-safe alphabets.
	bare := strings.TrimRight(s, "=")
	var lastErr error
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding} {
		decoded, err := enc.DecodeString(bare)
		if err == nil {
			return string(decoded), nil
		}
		lastErr = err
	}
	return "", lastErr
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
