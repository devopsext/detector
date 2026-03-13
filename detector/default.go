package detector

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"golang.org/x/sync/errgroup"
)

// DefaultDetectorType is the type identifier used in the V3 YAML config for Default pipeline detectors.
const DefaultDetectorType = "Default"

// DefaultOptions holds the configuration for a single Default pipeline detector instance.
type DefaultOptions struct {
	Config                 *common.DetectorDefaultConfig
	Triggers               *common.Triggers
	Memory                 *common.Memory
	ObserverDefaultConfigs []*common.ObserverConfig
	ObserverDefaults       []common.ObserverDefault
	VerifierDefaults       []common.VerifierDefaultInterface
	NotifierDefaultConfigs []*common.NotifierDefaultConfiguration
}

// NotifierDefaultConfiguration wraps a NotifierDefault with its trigger probability threshold.
type NotifierDefaultConfiguration = common.NotifierDefaultConfiguration

type Default struct {
	options *DefaultOptions
	logger  sreCommon.Logger
	lock    *sync.Mutex
}

const DefaultDetectorName = "Default"

func (d *Default) Name() string {
	name := d.options.Config.Name
	if utils.IsEmpty(name) {
		return DefaultDetectorName
	}
	return name
}

func (d *Default) Schedule() string {
	return d.options.Config.Schedule
}

func (d *Default) Start(ctx context.Context) {
	// Default pipeline detectors do not have long-running start logic.
}

// triggerKey builds a stable deduplication key from a label map.
// For Default pipeline, labels (e.g. application=billing_front, component=api) serve as the identifier.
func (d *Default) triggerKey(notifier common.NotifierDefault, labels map[string]string) string {

	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(labels))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, labels[k]))
	}

	return fmt.Sprintf("%s: %s", notifier.Name(), strings.Join(parts, ","))
}

func (d *Default) observe() ([]*common.ObserveDefaultOutput, error) {

	if len(d.options.ObserverDefaultConfigs) == 0 {
		return nil, fmt.Errorf("Default %s detector has no observer configs", d.Name())
	}

	g := &errgroup.Group{}
	mu := &sync.Mutex{}
	var results []*common.ObserveDefaultOutput

	for i, cfg := range d.options.ObserverDefaultConfigs {

		obs := d.findObserver(cfg.Name)
		if obs == nil {
			d.logger.Debug("Default %s detector: observer %s not found, skipping", d.Name(), cfg.Name)
			continue
		}

		g.Go(func() error {

			out, err := obs.ObserveDefault(d.options.ObserverDefaultConfigs[i])
			if err != nil {
				d.logger.Error("Default %s detector: observer %s error: %s", d.Name(), cfg.Name, err)
				return err
			}
			if out == nil || out.IsEmpty() {
				return nil
			}

			mu.Lock()
			results = append(results, out)
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return results, nil
}

func (d *Default) findObserver(name string) common.ObserverDefault {
	for _, o := range d.options.ObserverDefaults {
		if strings.EqualFold(o.Name(), name) {
			return o
		}
	}
	return nil
}

func (d *Default) mergeObserveOutputs(outs []*common.ObserveDefaultOutput) *common.ObserveDefaultOutput {

	merged := &common.ObserveDefaultOutput{}
	for _, o := range outs {
		if o == nil {
			continue
		}
		merged.Items = append(merged.Items, o.Items...)
	}
	if len(merged.Items) == 0 {
		return nil
	}
	return merged
}

func (d *Default) verify(out *common.ObserveDefaultOutput) (*common.VerifyDefaultResult, error) {

	if len(d.options.VerifierDefaults) == 0 {
		return nil, fmt.Errorf("Default %s detector has no verifier configurations", d.Name())
	}

	g := &errgroup.Group{}
	mu := &sync.Mutex{}
	var allItems []*common.VerifyDefaultItem

	for _, v := range d.options.VerifierDefaults {

		g.Go(func() error {

			vr, err := v.VerifyDefault(out)
			if err != nil {
				d.logger.Error("Default %s detector: verifier %s error: %s", d.Name(), v.Name(), err)
				return err
			}
			if vr == nil || vr.IsEmpty() {
				return nil
			}

			mu.Lock()
			allItems = append(allItems, vr.Items...)
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	if len(allItems) == 0 {
		return nil, nil
	}

	return &common.VerifyDefaultResult{Items: allItems}, nil
}

// recover clears memory entries for metrics that have recovered (item.Passed == true).
// Approved entries are kept in memory with NoTTL until the metric goes above threshold again.
func (d *Default) recover(vr *common.VerifyDefaultResult) {

	mem := d.options.Memory
	if mem == nil {
		return
	}

	for _, nc := range d.options.NotifierDefaultConfigs {
		for _, item := range vr.Items {
			if item == nil || !item.Passed {
				continue
			}
			key := d.triggerKey(nc.Notifier, item.Labels)
			entry := mem.Get(key)
			if entry != nil && entry.State == common.MemoryStateApproved {
				mem.Delete(key)
				d.logger.Info("Default %s: metric recovered, clearing memory for %s", d.Name(), key)
			}
		}
	}
}

func (d *Default) notify(vr *common.VerifyDefaultResult) error {

	if len(d.options.NotifierDefaultConfigs) == 0 {
		return fmt.Errorf("Default %s detector has no notifier configurations", d.Name())
	}

	mem := d.options.Memory
	var errs []error

	for _, nc := range d.options.NotifierDefaultConfigs {

		trackable, isTrackable := nc.Notifier.(common.NotifierDefaultTrackable)

		filtered := &common.VerifyDefaultResult{}
		for _, item := range vr.Items {
			if item == nil || item.Passed {
				continue
			}

			key := d.triggerKey(nc.Notifier, item.Labels)

			if mem != nil {
				entry := mem.Get(key)
				if entry != nil {
					if isTrackable && entry.MessageID != "" {
						status, err := trackable.CheckMessageStatus(entry.MessageID)
						if err != nil {
							d.logger.Debug("Default %s: status check error for %s: %s", d.Name(), key, err)
							continue
						}
						switch status {
						case "approved", "delivered":
							mem.Approve(key)
							d.logger.Debug("Default %s: message approved for %s, skipping", d.Name(), key)
							continue
						case "rejected", "not_found", "failed":
							mem.Delete(key)
							d.logger.Info("Default %s: message %s for %s, will resend", d.Name(), status, key)
						default:
							d.logger.Debug("Default %s: message status %s for %s, waiting", d.Name(), status, key)
							continue
						}
					} else {
						continue
					}
				}
			}

			cloned := *item
			switch {
			case nc.ThresholdAlert > 0 && cloned.Value < nc.ThresholdAlert:
				cloned.Severity = "alert"
			case nc.ThresholdWarning > 0 && cloned.Value < nc.ThresholdWarning:
				cloned.Severity = "warning"
			case nc.ThresholdWarning == 0 && nc.ThresholdAlert == 0:
				cloned.Severity = "warning"
			default:
				continue
			}
			filtered.Items = append(filtered.Items, &cloned)
		}

		if filtered.IsEmpty() {
			continue
		}

		if isTrackable {
			tracking, err := trackable.NotifyDefaultWithTracking(filtered)
			if err != nil {
				d.logger.Error("Default %s: tracked notify error: %s", d.Name(), err)
				errs = append(errs, err)
			}
			for _, t := range tracking {
				item := filtered.Items[t.ItemIndex]
				key := d.triggerKey(nc.Notifier, item.Labels)
				if mem != nil {
					mem.Record(key, t.MessageID, nc.Notifier.Name())
				}
			}
		} else {
			err := nc.Notifier.NotifyDefault(filtered)
			if err != nil {
				d.logger.Error("Default %s: notify error: %s", d.Name(), err)
				errs = append(errs, err)
			} else if mem != nil {
				for _, item := range filtered.Items {
					key := d.triggerKey(nc.Notifier, item.Labels)
					mem.Record(key, "", nc.Notifier.Name())
				}
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("Default %s: %d notification error(s)", d.Name(), len(errs))
	}
	return nil
}

func (d *Default) Detect() error {

	if !d.lock.TryLock() {
		return fmt.Errorf("Default %s detector already in a loop", d.Name())
	}
	defer d.lock.Unlock()

	d.logger.Debug("Default %s detector is observing...", d.Name())
	t1 := time.Now()
	outs, err := d.observe()
	if err != nil {
		d.logger.Error("Default %s detector cannot observe, error: %s", d.Name(), err)
		return nil
	}
	d.logger.Debug("Default %s detector observed in %s", d.Name(), time.Since(t1))

	out := d.mergeObserveOutputs(outs)
	if out == nil {
		d.logger.Debug("Default %s detector has no observe results", d.Name())
		return nil
	}

	d.logger.Debug("Default %s detector is verifying...", d.Name())
	t2 := time.Now()
	vr, err := d.verify(out)
	if err != nil {
		d.logger.Error("Default %s detector cannot verify, error: %s", d.Name(), err)
		return nil
	}
	d.logger.Debug("Default %s detector verified in %s", d.Name(), time.Since(t2))

	if vr == nil {
		d.logger.Debug("Default %s detector has no verify results", d.Name())
		return nil
	}

	d.logger.Debug("Default %s detector is recovering...", d.Name())
	d.recover(vr)

	d.logger.Debug("Default %s detector is notifying...", d.Name())
	t3 := time.Now()
	if err := d.notify(vr); err != nil {
		d.logger.Error("Default %s detector cannot notify, error: %s", d.Name(), err)
	}
	d.logger.Debug("Default %s detector notified in %s", d.Name(), time.Since(t3))

	return nil
}

func NewDefault(options *DefaultOptions, observability *common.Observability) *Default {

	logger := observability.Logs()

	if options.Config == nil {
		logger.Debug("Default detector has no config. Skipped.")
		return nil
	}

	if len(options.ObserverDefaults) == 0 {
		logger.Debug("Default detector %s has no observers. Skipped.", options.Config.Name)
		return nil
	}

	return &Default{
		options: options,
		logger:  logger,
		lock:    &sync.Mutex{},
	}
}
