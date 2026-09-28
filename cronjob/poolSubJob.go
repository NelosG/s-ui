package cronjob

import (
	"github.com/alireza0/s-ui/logger"
	"github.com/alireza0/s-ui/service"
)

// PoolSubJob refreshes the proxy pool from the provider subscription when it is due, and on
// every tick samples which pool nodes are dead, removing those dead for too long.
type PoolSubJob struct {
	service.PoolSubService
}

func NewPoolSubJob() *PoolSubJob {
	return &PoolSubJob{}
}

func (j *PoolSubJob) Run() {
	if j.PoolSubDue() {
		if _, err := j.PoolSubService.Run(); err != nil {
			logger.Warning("pool update: ", err)
		}
	}
	j.Prune()
}
