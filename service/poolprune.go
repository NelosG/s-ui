package service

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
	"github.com/alireza0/s-ui/logger"
)

// Pool pruning. A pool node that stays dead for poolSubRemoveAfter days leaves the pool and
// every group: the provider keeps listing nodes long after they stop working, and each dead
// member costs probes and clutters every group. A node that works but left the
// subscription stays. A removed node is remembered with the connection it had, so the next
// refresh does not add it back while the provider still lists it unchanged; new credentials
// or a new address bring it back as a fresh node.

const (
	poolDeadSinceKey = "poolSubDeadSince"
	poolRemovedKey   = "poolSubRemoved"
	tombstoneKeep    = 30 * 24 * time.Hour
	// with fewer live pool nodes than this the NAS itself is more likely offline than the
	// whole pool dead, and nothing is removed
	pruneMinAlive = 3
)

type poolTombstone struct {
	Identity string `json:"identity"`
	At       int64  `json:"at"`
}

// poolIdentity names the endpoint a pool outbound connects to: the same type, address, port
// and credentials are the same node whatever the provider calls it.
func poolIdentity(typ string, opts map[string]interface{}) string {
	field := func(key string) string {
		if v, ok := opts[key]; ok && v != nil {
			return fmt.Sprint(v)
		}
		return ""
	}
	return strings.Join([]string{typ, field("server"), field("server_port"), field("uuid"), field("password")}, "|")
}

func outboundOptions(o model.Outbound) map[string]interface{} {
	opts := map[string]interface{}{}
	_ = json.Unmarshal(o.Options, &opts)
	// round-trip so numbers compare the same way as in freshly parsed links
	raw, _ := json.Marshal(opts)
	_ = json.Unmarshal(raw, &opts)
	return opts
}

func (s *PoolSubService) loadJSON(key string, into interface{}) {
	raw, _ := s.SettingService.getString(key)
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), into)
	}
}

func (s *PoolSubService) storeJSON(key string, value interface{}) {
	raw, _ := json.Marshal(value)
	if err := s.SettingService.setString(key, string(raw)); err != nil {
		logger.Warning("pool prune: unable to store ", key, ": ", err)
	}
}

// deadStreaks updates, from the engine's current view, since when each pool node has been
// dead without a break, and returns the pool nodes and how many of them are alive now.
// Nodes the engine has not judged yet (unknown, right after a start) keep their streak.
func deadStreaks(states map[string]string, pool []model.Outbound, deadSince map[string]int64, now time.Time) int {
	alive := 0
	present := map[string]bool{}
	for _, o := range pool {
		present[o.Tag] = true
		switch states[o.Tag] {
		case "dead":
			if _, known := deadSince[o.Tag]; !known {
				deadSince[o.Tag] = now.Unix()
			}
		case "alive", "suspect":
			delete(deadSince, o.Tag)
			alive++
		}
	}
	for tag := range deadSince {
		if !present[tag] {
			delete(deadSince, tag)
		}
	}
	return alive
}

// Prune records dead streaks and removes pool nodes dead for poolSubRemoveAfter days. It
// runs from the pool job every few minutes; a sample that finds a node alive resets it.
func (s *PoolSubService) Prune() []string {
	if !poolSubRunning.TryLock() {
		return nil
	}
	defer poolSubRunning.Unlock()
	days, err := s.SettingService.getInt("poolSubRemoveAfter")
	if err != nil || days <= 0 {
		return nil
	}
	snap, err := s.ConfigService.Health()
	if err != nil || len(snap.Nodes) == 0 {
		return nil
	}
	states := map[string]string{}
	for _, n := range snap.Nodes {
		states[n.Tag] = n.State
	}
	var all []model.Outbound
	if err := database.GetDB().Model(model.Outbound{}).Order("id").Find(&all).Error; err != nil {
		return nil
	}
	var pool []model.Outbound
	for _, o := range all {
		if slices.Contains(poolProxyTypes, o.Type) {
			pool = append(pool, o)
		}
	}
	deadSince := map[string]int64{}
	s.loadJSON(poolDeadSinceKey, &deadSince)
	now := time.Now()
	alive := deadStreaks(states, pool, deadSince, now)
	s.storeJSON(poolDeadSinceKey, deadSince)
	if alive < pruneMinAlive {
		return nil
	}
	var expired []string
	for _, o := range pool {
		if since, ok := deadSince[o.Tag]; ok && now.Sub(time.Unix(since, 0)) >= time.Duration(days)*24*time.Hour {
			expired = append(expired, o.Tag)
		}
	}
	if len(expired) == 0 {
		return nil
	}
	removed := s.removePoolNodes(expired, all, now)
	for _, tag := range removed {
		delete(deadSince, tag)
	}
	s.storeJSON(poolDeadSinceKey, deadSince)
	if len(removed) > 0 {
		logger.Info("pool prune: removed ", len(removed), " nodes dead for ", days, " days: ", strings.Join(removed, ", "))
		if report := s.LastReport(); report != nil {
			report.Removed = append(report.Removed, removed...)
			s.storeJSON("poolSubLast", report)
		}
	}
	return removed
}

// removePoolNodes takes tags out of every group, then deletes them and remembers what they
// were. A tag that some other outbound uses as a detour, or whose removal would leave a group
// empty, stays.
func (s *PoolSubService) removePoolNodes(tags []string, all []model.Outbound, now time.Time) []string {
	keep := map[string]bool{}
	type groupEdit struct {
		o       model.Outbound
		opts    map[string]interface{}
		members []string
	}
	var edits []groupEdit
	for _, o := range all {
		opts := outboundOptions(o)
		if detour, ok := opts["detour"].(string); ok && slices.Contains(tags, detour) {
			keep[detour] = true
		}
		if o.Type != "urltest" && o.Type != "selector" {
			continue
		}
		members := toStrings(opts["outbounds"])
		left := slices.DeleteFunc(slices.Clone(members), func(m string) bool { return slices.Contains(tags, m) })
		if len(left) == len(members) {
			continue
		}
		if len(left) == 0 {
			for _, m := range members {
				keep[m] = true
			}
			continue
		}
		edits = append(edits, groupEdit{o: o, opts: opts, members: members})
	}
	var gone []string
	for _, tag := range tags {
		if !keep[tag] {
			gone = append(gone, tag)
		}
	}
	if len(gone) == 0 {
		return nil
	}
	for _, e := range edits {
		e.opts["outbounds"] = slices.DeleteFunc(e.members, func(m string) bool { return slices.Contains(gone, m) })
		if err := s.saveOutbound("edit", e.o.Id, e.o.Type, e.o.Tag, e.opts); err != nil {
			logger.Warning("pool prune: group ", e.o.Tag, ": ", err)
			return nil
		}
	}
	tombstones := map[string]poolTombstone{}
	s.loadJSON(poolRemovedKey, &tombstones)
	var removed []string
	for _, o := range all {
		if !slices.Contains(gone, o.Tag) {
			continue
		}
		data, _ := json.Marshal(o.Tag)
		if _, err := s.ConfigService.Save("outbounds", "del", data, "", "pool-prune", ""); err != nil {
			logger.Warning("pool prune: ", o.Tag, ": ", err)
			continue
		}
		tombstones[o.Tag] = poolTombstone{Identity: poolIdentity(o.Type, outboundOptions(o)), At: now.Unix()}
		removed = append(removed, o.Tag)
	}
	for tag, t := range tombstones {
		if now.Sub(time.Unix(t.At, 0)) > tombstoneKeep {
			delete(tombstones, tag)
		}
	}
	s.storeJSON(poolRemovedKey, tombstones)
	return removed
}
