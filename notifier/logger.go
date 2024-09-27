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

	if vr.Endpoints.IsEmpty() {
		return errors.New("Logger notifier cannot process empty endpoints")
	}

	for _, e := range vr.Endpoints.Items() {

		if e == nil {
			continue
		}

		uri := common.NormalizeURI(e.URI)

		sum := float64(0.0)
		countries := []string{}

		for k, v := range e.Countries {

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

		s.logger.Info("Logger notifier endpoint %s in countries %s %0.2f%%", uri, countries, avg)
	}
	return nil
}

func NewLogger(options LoggerOptions, observability *common.Observability) *Logger {

	return &Logger{
		options: options,
		logger:  observability.Logs(),
	}
}
