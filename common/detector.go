package common

import (
	"strings"
	"sync"
	"time"

	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"github.com/go-co-op/gocron"
)

type Detector interface {
	Name() string
	Schedule() string
	Detect() error
}

type Detectors struct {
	scheduler *gocron.Scheduler
	logger    sreCommon.Logger
	items     []Detector
}

func (ds *Detectors) Add(d Detector) {

	if utils.IsEmpty(d) {
		return
	}
	ds.items = append(ds.items, d)
}

func (ds *Detectors) Scheduled() bool {
	return ds.scheduler.Len() > 0
}

func (ds *Detectors) schedule(schedule string, wait bool, fun interface{}) {

	var ss *gocron.Scheduler
	if len(strings.Split(schedule, " ")) == 1 {
		ss = ds.scheduler.Every(schedule)
	} else {
		ss = ds.scheduler.Cron(schedule)
	}
	if wait {
		ss = ss.WaitForSchedule()
	}
	ss.Do(fun)
}

func (ds *Detectors) run(wg *sync.WaitGroup, once, wait bool, d Detector) {

	if utils.IsEmpty(d) {
		return
	}
	// run once and return if there is flag
	if once {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.Detect()
		}()
		return
	}
	// run on schedule if there is one defined
	schedule := d.Schedule()
	if !utils.IsEmpty(schedule) {
		ds.schedule(schedule, wait, d.Detect)
		ds.logger.Debug("Detector %s enabled on schedule: %s", d.Name(), schedule)
	}
}

func (ds *Detectors) Start(once, wait bool) {

	wg := &sync.WaitGroup{}

	for _, d := range ds.items {
		ds.run(wg, once, wait, d)
	}
	ds.scheduler.StartAsync()
	wg.Wait()
}

func NewDetectors(observability *Observability) *Detectors {

	return &Detectors{
		scheduler: gocron.NewScheduler(time.UTC),
		logger:    observability.Logs(),
	}
}
