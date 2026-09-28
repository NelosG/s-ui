package cronjob

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/alireza0/s-ui/config"
	"github.com/alireza0/s-ui/logger"
	"github.com/alireza0/s-ui/service"
)

// TelemetryJob keeps a history of the engine's view on disk. The engine's own event log holds
// the last 500 events, an hour and a half on a busy evening, and a complaint about a stall
// from last night needs more. New events go to health-events.jsonl as they appear; once a
// minute a line with every group's choice and the numbers of each live node goes to
// health-metrics.jsonl. Each file moves to .1 past its size limit, so about a week is kept.
type TelemetryJob struct {
	service.ConfigService
	dir         string
	lastEvent   int64
	lastFlow    int64
	lastMetrics time.Time
	prev        map[string]nodeCounters
}

// Flow records (one line per connection that stalled, froze, opened slowly, was closed by the
// engine or moved a lot of data) go to flows.jsonl: the node events say that a node stalled,
// these say which stream, how long it waited on the node and on the client, and who ended it.
const (
	eventsFile      = "health-events.jsonl"
	metricsFile     = "health-metrics.jsonl"
	flowsFile       = "flows.jsonl"
	eventsMaxBytes  = 20 << 20
	metricsMaxBytes = 40 << 20
	flowsMaxBytes   = 40 << 20
	metricsEvery    = time.Minute
)

type nodeCounters struct {
	Down, Up, Stalls, UDPStalls, StallMs, ProbeFail, Deaths, RaceLosses, DialFails int64
}

// metricsNode is one node in a metrics line; deltas are since the previous line.
type metricsNode struct {
	State     string `json:"state"`
	Conns     int    `json:"conns,omitempty"`
	UDP       int    `json:"udp,omitempty"`
	Down      int64  `json:"down,omitempty"`
	Up        int64  `json:"up,omitempty"`
	Score     int    `json:"score,omitempty"`
	Stalls    int64  `json:"stalls,omitempty"`
	UDPStalls int64  `json:"udp_stalls,omitempty"`
	StallMs   int64  `json:"stall_ms,omitempty"`
	ProbeFail int64  `json:"probe_fail,omitempty"`
	Deaths    int64  `json:"deaths,omitempty"`
	Lost      int64  `json:"race_losses,omitempty"`
	DialFails int64  `json:"dial_fails,omitempty"`
}

type metricsLine struct {
	At     int64                  `json:"at"`
	Groups map[string]string      `json:"groups"`
	Nodes  map[string]metricsNode `json:"nodes"`
}

func NewTelemetryJob() *TelemetryJob {
	return &TelemetryJob{dir: filepath.Join(filepath.Dir(config.GetDBFolderPath()), "logs"), prev: map[string]nodeCounters{}}
}

func (j *TelemetryJob) Run() {
	snap, err := j.ConfigService.Health()
	if err != nil {
		return
	}
	// events arrive newest first
	var fresh [][]byte
	for _, e := range snap.Events {
		if e.At <= j.lastEvent {
			break
		}
		line, _ := json.Marshal(e)
		fresh = append(fresh, line)
	}
	if len(snap.Events) > 0 {
		j.lastEvent = max(j.lastEvent, snap.Events[0].At)
	}
	slices.Reverse(fresh)
	for _, line := range fresh {
		j.write(eventsFile, line, eventsMaxBytes)
	}

	records, latest, err := j.ConfigService.Flows(j.lastFlow)
	if err == nil {
		if latest < j.lastFlow {
			// the core restarted and numbers its records from 1 again
			records, latest, _ = j.ConfigService.Flows(0)
		}
		for _, rec := range records {
			line, _ := json.Marshal(rec)
			j.write(flowsFile, line, flowsMaxBytes)
		}
		j.lastFlow = latest
	}

	now := time.Now()
	if now.Sub(j.lastMetrics) < metricsEvery {
		return
	}
	j.lastMetrics = now
	m := metricsLine{At: now.Unix(), Groups: map[string]string{}, Nodes: map[string]metricsNode{}}
	for _, g := range snap.Groups {
		m.Groups[g.Tag] = g.Primary
	}
	for _, n := range snap.Nodes {
		cur := nodeCounters{Down: n.BytesDown, Up: n.BytesUp, Stalls: n.Stalls, UDPStalls: n.UDPStalls, StallMs: n.StallMs,
			ProbeFail: n.ProbeFail, Deaths: n.Deaths, RaceLosses: n.RaceLosses, DialFails: n.DialFails}
		prev, seen := j.prev[n.Tag]
		j.prev[n.Tag] = cur
		if !seen {
			// first sight after a start: no delta to tell yet
			prev = cur
		}
		entry := metricsNode{
			State: n.State, Conns: n.Connections, UDP: n.UDPFlows,
			Down: cur.Down - prev.Down, Up: cur.Up - prev.Up, Stalls: cur.Stalls - prev.Stalls,
			UDPStalls: cur.UDPStalls - prev.UDPStalls, StallMs: cur.StallMs - prev.StallMs,
			ProbeFail: cur.ProbeFail - prev.ProbeFail, Deaths: cur.Deaths - prev.Deaths,
			Lost: cur.RaceLosses - prev.RaceLosses, DialFails: cur.DialFails - prev.DialFails,
		}
		for _, p := range n.Probes {
			if p.Score > 0 && (entry.Score == 0 || p.Score < entry.Score) {
				entry.Score = p.Score
			}
		}
		// dead nodes nobody uses would fill the file with nothing
		if n.State == "dead" && entry.Conns == 0 && entry.Down == 0 && entry.Deaths == 0 {
			continue
		}
		m.Nodes[n.Tag] = entry
	}
	line, _ := json.Marshal(m)
	j.write(metricsFile, line, metricsMaxBytes)
}

func (j *TelemetryJob) write(name string, line []byte, limit int64) {
	if err := appendLine(filepath.Join(j.dir, name), line, limit); err != nil {
		logger.Debug("telemetry: ", err)
	}
}

// appendLine adds line to path, first moving path to path.1 if it would grow past limit.
func appendLine(path string, line []byte, limit int64) error {
	if info, err := os.Stat(path); err == nil && info.Size()+int64(len(line))+1 > limit {
		if err := os.Rename(path, path+".1"); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}
