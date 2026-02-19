package notifier

import (
	"errors"

	"github.com/devopsext/detector/common"
	sreCommon "github.com/devopsext/sre/common"
)

type LoggerOptions struct {
}

type Logger struct {
	options LoggerOptions
	logger  sreCommon.Logger
}

const NotifierLoggerName = "Logger"

func (s *Logger) Name() string {
	return NotifierLoggerName
}

func (s *Logger) Notify(vr *common.VerifyResult) error {

	if vr.Items.IsEmpty() {
		return errors.New("Logger notifier cannot process empty items")
	}

	for _, entry := range vr.Items.Items() {

		if entry == nil {
			continue
		}

		key := entry.EntryKey()

		sum := float64(0.0)
		countries := []string{}

		for k, v := range entry.EntryVerifyCountries() {

			if v == nil {
				continue
			}
			p := v.Probability
			if p == nil {
				continue
			}

			sum = sum + *p
			country := common.NormalizeCountry(k)
			countries = append(countries, country)
		}

		l := len(countries)
		if l == 0 {
			continue
		}

		avg := sum / float64(l)

		s.logger.Info("Logger notifier item %s in countries %s %0.2f%%", key, countries, avg)
	}
	return nil
}

func NewLogger(options LoggerOptions, observability *common.Observability) *Logger {

	return &Logger{
		options: options,
		logger:  observability.Logs(),
	}
}
