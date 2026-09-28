package core

import (
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing/service"
)

// Health returns the per-node state and group choices kept by the forked urltest engine.
func (c *Core) Health() (group.HealthSnapshot, error) {
	box, err := c.running()
	if err != nil {
		return group.HealthSnapshot{}, err
	}
	return group.Snapshot(service.PtrFromContext[urltest.HistoryStorage](box.ctx)), nil
}

// Flows returns the engine's flow records after seq and its newest sequence number.
func (c *Core) Flows(seq int64) ([]group.FlowRecord, int64, error) {
	box, err := c.running()
	if err != nil {
		return nil, 0, err
	}
	records, latest := group.Flows(service.PtrFromContext[urltest.HistoryStorage](box.ctx), seq)
	return records, latest, nil
}
