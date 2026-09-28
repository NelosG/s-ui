package service

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
	"github.com/alireza0/s-ui/logger"
	"github.com/alireza0/s-ui/util"
	"github.com/alireza0/s-ui/util/common"
)

// PoolSubService keeps the proxy pool in step with a provider subscription. The provider
// rotates credentials every week or two and keeps the link names, so outbounds are matched
// by tag and only their connection fields are rewritten; anything set by hand on an
// outbound (dial options and the like) survives.
type PoolSubService struct {
	ConfigService
	SettingService
}

type PoolSubReport struct {
	At        int64    `json:"at"`
	Fetched   int      `json:"fetched"`
	Usable    int      `json:"usable"`
	Updated   []string `json:"updated"`
	Added     []string `json:"added"`
	Unchanged int      `json:"unchanged"`
	Missing   []string `json:"missing"`
	Joined    int      `json:"joined"`
	Errors    []string `json:"errors"`
	// removed for being dead too long (added by the pruner between runs), held back because
	// they were removed and the provider still lists them unchanged, and skipped as the same
	// server and credentials as another node
	Removed    []string `json:"removed"`
	Held       []string `json:"held"`
	Duplicates []string `json:"duplicates"`
	// what each link gave, in the order of poolSubUrls
	Sources []PoolSubSource `json:"sources"`
}

// PoolSubSource is one subscription link's share of a run or a check. Link is redacted the
// way the panel shows it, which is also how the panel matches it to its list.
type PoolSubSource struct {
	Link    string         `json:"link"`
	Fetched int            `json:"fetched"`
	Usable  int            `json:"usable"`
	Types   map[string]int `json:"types"`
	Sample  []string       `json:"sample,omitempty"`
	Error   string         `json:"error,omitempty"`
}

type poolFilter struct {
	ua      string
	allowed map[string]bool
	skip    *regexp.Regexp
}

func (s *PoolSubService) loadFilter() (poolFilter, error) {
	f := poolFilter{allowed: map[string]bool{}}
	f.ua, _ = s.SettingService.getString("poolSubUA")
	protocols, _ := s.SettingService.getString("poolSubProtocols")
	skipExpr, _ := s.SettingService.getString("poolSubSkip")
	if strings.TrimSpace(skipExpr) != "" {
		var err error
		if f.skip, err = regexp.Compile(skipExpr); err != nil {
			return f, common.NewError("invalid poolSubSkip: ", err)
		}
	}
	for _, p := range strings.Split(protocols, ",") {
		if p = strings.TrimSpace(p); p != "" {
			f.allowed[p] = true
		}
	}
	return f, nil
}

// readSource fetches one link and returns the nodes the settings accept, in the provider's
// order.
func readSource(link string, f poolFilter, retry bool) (PoolSubSource, []util.PoolNode) {
	src := PoolSubSource{Link: redactSub(link), Types: map[string]int{}}
	if !strings.HasPrefix(link, "http://") && !strings.HasPrefix(link, "https://") {
		src.Error = "not an http(s) link: " + redactSub(link)
		return src, nil
	}
	body, err := fetchSubscription(link, f.ua)
	if err != nil && retry {
		// The provider's API is slow at times; one retry beats a run with half the pool.
		time.Sleep(3 * time.Second)
		body, err = fetchSubscription(link, f.ua)
	}
	if err != nil {
		src.Error = err.Error()
		return src, nil
	}
	var nodes []util.PoolNode
	for _, line := range strings.Split(util.DecodeSubscription(body), "\n") {
		if !strings.Contains(line, "://") {
			continue
		}
		src.Fetched++
		node, ok := util.ParsePoolLink(line)
		if !ok || node.Tag == "" || !f.allowed[node.Type] || (f.skip != nil && f.skip.MatchString(node.Tag)) {
			continue
		}
		nodes = append(nodes, node)
		src.Types[node.Type]++
	}
	src.Usable = len(nodes)
	return src, nodes
}

// Check reads the given links the way a run would and reports what each offers, without
// touching the pool: for a link about to be added.
func (s *PoolSubService) Check(links []string) ([]PoolSubSource, error) {
	if len(links) == 0 {
		return nil, common.NewError("no links")
	}
	if len(links) > 10 {
		return nil, common.NewError("at most 10 links at a time")
	}
	f, err := s.loadFilter()
	if err != nil {
		return nil, err
	}
	result := make([]PoolSubSource, 0, len(links))
	for _, link := range links {
		src, nodes := readSource(link, f, false)
		for _, n := range nodes[:min(5, len(nodes))] {
			src.Sample = append(src.Sample, n.Tag)
		}
		result = append(result, src)
	}
	return result, nil
}

var poolSubRunning sync.Mutex

// managed keys are the connection fields a subscription owns; everything else on an
// outbound belongs to the operator.
var poolManagedKeys = []string{"server", "server_port", "uuid", "flow", "password", "method", "packet_encoding", "obfs", "tls", "transport"}

var poolProxyTypes = []string{"vless", "trojan", "hysteria2", "shadowsocks"}

func (s *PoolSubService) Run() (*PoolSubReport, error) {
	if !poolSubRunning.TryLock() {
		return nil, common.NewError("pool update already running")
	}
	defer poolSubRunning.Unlock()
	// Empty lists, not nil: nil marshals to null and the panel reads .length on them.
	report := &PoolSubReport{At: time.Now().Unix(), Updated: []string{}, Added: []string{}, Missing: []string{}, Errors: []string{},
		Removed: []string{}, Held: []string{}, Duplicates: []string{}, Sources: []PoolSubSource{}}
	defer func() {
		raw, _ := json.Marshal(report)
		if err := s.SettingService.setString("poolSubLast", string(raw)); err != nil {
			logger.Warning("pool update: unable to store report: ", err)
		}
	}()

	urls, _ := s.SettingService.getString("poolSubUrls")
	addNew, _ := s.SettingService.getBool("poolSubAddNew")
	f, err := s.loadFilter()
	if err != nil {
		return report, err
	}

	// First subscription wins on duplicate names; list the complete one first. The same
	// server and credentials under a second name are one node too.
	nodes := map[string]util.PoolNode{}
	identities := map[string]string{}
	var order []string
	for _, link := range strings.Fields(urls) {
		src, parsed := readSource(link, f, true)
		report.Sources = append(report.Sources, src)
		if src.Error != "" {
			report.Errors = append(report.Errors, src.Error)
			continue
		}
		report.Fetched += src.Fetched
		for _, node := range parsed {
			if _, dup := nodes[node.Tag]; dup {
				continue
			}
			id := poolIdentity(node.Type, node.Options)
			if other, dup := identities[id]; dup {
				report.Duplicates = append(report.Duplicates, node.Tag+" = "+other)
				continue
			}
			identities[id] = node.Tag
			nodes[node.Tag] = node
			order = append(order, node.Tag)
		}
	}
	report.Usable = len(nodes)
	if len(nodes) == 0 {
		// An empty or broken answer must never be read as "the provider removed everything".
		return report, common.NewError("subscription gave no usable nodes")
	}

	var current []model.Outbound
	if err := database.GetDB().Model(model.Outbound{}).Find(&current).Error; err != nil {
		return report, err
	}
	byTag := map[string]model.Outbound{}
	endpoints := map[string]string{} // identity -> pool tag
	for _, o := range current {
		byTag[o.Tag] = o
		if slices.Contains(poolProxyTypes, o.Type) {
			endpoints[poolIdentity(o.Type, outboundOptions(o))] = o.Tag
		}
	}
	tombstones := map[string]poolTombstone{}
	s.loadJSON(poolRemovedKey, &tombstones)
	tombstonesChanged := false
	for tag, o := range byTag {
		if slices.Contains(poolProxyTypes, o.Type) {
			if _, inSub := nodes[tag]; !inSub {
				report.Missing = append(report.Missing, tag)
			}
		}
	}
	slices.Sort(report.Missing)

	for _, tag := range order {
		node := nodes[tag]
		existing, known := byTag[tag]
		if known {
			if existing.Type != node.Type {
				report.Errors = append(report.Errors, fmt.Sprintf("%s: type changed %s -> %s, left alone", tag, existing.Type, node.Type))
				continue
			}
			merged, changed, err := mergeManaged(existing.Options, node.Options)
			if err != nil {
				report.Errors = append(report.Errors, tag+": "+err.Error())
				continue
			}
			if !changed {
				report.Unchanged++
				continue
			}
			if err := s.saveOutbound("edit", existing.Id, node.Type, tag, merged); err != nil {
				report.Errors = append(report.Errors, tag+": "+err.Error())
				continue
			}
			report.Updated = append(report.Updated, tag)
			continue
		}
		if !addNew {
			continue
		}
		id := poolIdentity(node.Type, node.Options)
		if t, held := tombstones[tag]; held {
			if t.Identity == id {
				report.Held = append(report.Held, tag)
				continue
			}
			// new address or credentials: the node gets a fresh chance
			delete(tombstones, tag)
			tombstonesChanged = true
		}
		if other, dup := endpoints[id]; dup {
			report.Duplicates = append(report.Duplicates, tag+" = "+other)
			continue
		}
		if err := s.saveOutbound("new", 0, node.Type, tag, node.Options); err != nil {
			report.Errors = append(report.Errors, tag+": "+err.Error())
			continue
		}
		endpoints[id] = tag
		report.Added = append(report.Added, tag)
	}
	if tombstonesChanged {
		s.storeJSON(poolRemovedKey, tombstones)
	}
	s.syncGroups(report, order)
	logger.Info("pool update: ", len(report.Updated), " updated, ", len(report.Added), " added, ", report.Unchanged, " unchanged, ", len(report.Errors), " errors")
	return report, nil
}

// syncGroups makes every urltest group that carries pool nodes carry all of them. Which
// nodes a group may actually use is the engine's job (exclude_egress, expected_status,
// health), so membership is simply everything; new nodes go to the end of the list, which
// is the bottom of the priority order. Groups without pool nodes (zapret only) are left
// alone.
func (s *PoolSubService) syncGroups(report *PoolSubReport, order []string) {
	var current []model.Outbound
	if err := database.GetDB().Model(model.Outbound{}).Order("id").Find(&current).Error; err != nil {
		report.Errors = append(report.Errors, "sync groups: "+err.Error())
		return
	}
	pool := map[string]bool{}
	for _, o := range current {
		if slices.Contains(poolProxyTypes, o.Type) {
			pool[o.Tag] = true
		}
	}
	// subscription order first, then pool outbounds added by hand
	var all []string
	for _, tag := range order {
		if pool[tag] {
			all = append(all, tag)
		}
	}
	for _, o := range current {
		if pool[o.Tag] && !slices.Contains(all, o.Tag) {
			all = append(all, o.Tag)
		}
	}
	for _, g := range current {
		if g.Type != "urltest" {
			continue
		}
		var opts map[string]interface{}
		if err := json.Unmarshal(g.Options, &opts); err != nil {
			continue
		}
		members := toStrings(opts["outbounds"])
		if !slices.ContainsFunc(members, func(m string) bool { return pool[m] }) {
			continue
		}
		added := 0
		for _, tag := range all {
			if !slices.Contains(members, tag) {
				members = append(members, tag)
				added++
			}
		}
		if added == 0 {
			continue
		}
		opts["outbounds"] = members
		if err := s.saveOutbound("edit", g.Id, g.Type, g.Tag, opts); err != nil {
			report.Errors = append(report.Errors, g.Tag+": "+err.Error())
			continue
		}
		report.Joined += added
	}
}
func (s *PoolSubService) saveOutbound(act string, id uint, typ, tag string, opts map[string]interface{}) error {
	obj := map[string]interface{}{}
	for k, v := range opts {
		obj[k] = v
	}
	obj["type"], obj["tag"] = typ, tag
	if act == "edit" {
		obj["id"] = id
	}
	data, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	_, err = s.ConfigService.Save("outbounds", act, data, "", "pool-sub", "")
	return err
}

// mergeManaged overwrites the subscription-owned keys of an outbound and reports whether
// anything actually changed.
func mergeManaged(raw json.RawMessage, fresh map[string]interface{}) (map[string]interface{}, bool, error) {
	current := map[string]interface{}{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &current); err != nil {
			return nil, false, err
		}
	}
	// Round-trip the fresh values so numbers compare as the same JSON types.
	freshRaw, _ := json.Marshal(fresh)
	var freshNorm map[string]interface{}
	_ = json.Unmarshal(freshRaw, &freshNorm)
	changed := false
	for _, key := range poolManagedKeys {
		v, has := freshNorm[key]
		old, had := current[key]
		switch {
		case has && (!had || !reflect.DeepEqual(old, v)):
			current[key] = v
			changed = true
		case !has && had && key != "transport":
			delete(current, key)
			changed = true
		}
	}
	return current, changed, nil
}

func fetchSubscription(link, ua string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, link, nil)
	if err != nil {
		return nil, err
	}
	if ua != "" {
		// The provider serves a different, trimmed link set to unknown clients.
		req.Header.Set("User-Agent", ua)
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, common.NewError("fetch ", redactSub(link), ": ", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, common.NewErrorf("fetch %s: http %d", redactSub(link), resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

// redactSub keeps the subscription token out of logs and reports.
func redactSub(link string) string {
	if i := strings.LastIndex(link, "/"); i > 0 && len(link)-i > 12 {
		return link[:i+9] + "..."
	}
	return link
}

func toStrings(v interface{}) []string {
	list, _ := v.([]interface{})
	result := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// PoolSubDue reports whether the scheduled update should run now.
func (s *PoolSubService) PoolSubDue() bool {
	interval, err := s.SettingService.getInt("poolSubInterval")
	if err != nil || interval <= 0 {
		return false
	}
	if urls, _ := s.SettingService.getString("poolSubUrls"); strings.TrimSpace(urls) == "" {
		return false
	}
	last, _ := s.SettingService.getString("poolSubLast")
	var report PoolSubReport
	_ = json.Unmarshal([]byte(last), &report)
	return time.Since(time.Unix(report.At, 0)) >= time.Duration(interval)*time.Minute
}

// LastReport returns the stored result of the previous run, nil before the first one.
func (s *PoolSubService) LastReport() *PoolSubReport {
	last, _ := s.SettingService.getString("poolSubLast")
	if last == "" {
		return nil
	}
	var report PoolSubReport
	if json.Unmarshal([]byte(last), &report) != nil {
		return nil
	}
	return &report
}
