package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"sync"
	"syscall"

	"github.com/devopsext/detector/common"
	"github.com/devopsext/detector/notifier"
	"github.com/devopsext/detector/observer"
	"github.com/devopsext/detector/source"
	"github.com/devopsext/detector/verifier"
	sreCommon "github.com/devopsext/sre/common"
	sreProvider "github.com/devopsext/sre/provider"
	"github.com/devopsext/utils"
	"github.com/go-co-op/gocron"
	"github.com/spf13/cobra"
)

var version = "unknown"
var APPNAME = "DETECTOR"

var logs = sreCommon.NewLogs()
var metrics = sreCommon.NewMetrics()
var stdout *sreProvider.Stdout
var mainWG sync.WaitGroup

type RootOptions struct {
	Logs          []string
	Metrics       []string
	RunOnce       bool
	SchedulerWait bool
}

var rootOptions = RootOptions{
	Logs:          strings.Split(envGet("LOGS", "stdout").(string), ","),
	Metrics:       strings.Split(envGet("METRICS", "prometheus").(string), ","),
	RunOnce:       envGet("RUN_ONCE", false).(bool),
	SchedulerWait: envGet("SCHEDULER_WAIT", true).(bool),
}

var stdoutOptions = sreProvider.StdoutOptions{
	Format:          envGet("STDOUT_FORMAT", "text").(string),
	Level:           envGet("STDOUT_LEVEL", "info").(string),
	Template:        envGet("STDOUT_TEMPLATE", "{{.file}} {{.msg}}").(string),
	TimestampFormat: envGet("STDOUT_TIMESTAMP_FORMAT", time.RFC3339Nano).(string),
	TextColors:      envGet("STDOUT_TEXT_COLORS", true).(bool),
}

var prometheusMetricsOptions = sreProvider.PrometheusOptions{
	URL:    envGet("PROMETHEUS_METRICS_URL", "/metrics").(string),
	Listen: envGet("PROMETHEUS_METRICS_LISTEN", ":8080").(string),
	Prefix: envGet("PROMETHEUS_METRICS_PREFIX", "").(string),
}

var sourceConfig = source.ConfigOptions{
	Path: envGet("SOURCE_CONFIG_PATH", "").(string),
}

var observerDatadog = observer.DatadogOptions{
	URL: envGet("OBSERVER_DATADOG_URL", "").(string),
}

var verifierHttp = verifier.HttpOptions{
	URL: envGet("VERIFIER_HTTP_URL", "").(string),
}

var notifierSlack = notifier.SlackOptions{
	Token: envGet("NOTIFIER_SLACK_URL", "").(string),
}

/*var dSignalOptions = discovery.SignalOptions{
	Disabled:     strings.Split(envStringExpand("SIGNAL_DISABLED", ""), ","),
	Schedule:     envGet("SIGNAL_SCHEDULE", "").(string),
	Query:        envFileContentExpand("SIGNAL_QUERY", ""),
	QueryPeriod:  envGet("SIGNAL_QUERY_PERIOD", "").(string),
	QueryStep:    envGet("SIGNAL_QUERY_STEP", "").(string),
	Metric:       envGet("SIGNAL_METRIC", "").(string),
	Ident:        envFileContentExpand("SIGNAL_IDENT", ""),
	Field:        envGet("SIGNAL_FIELD", "").(string),
	Files:        envFileContentExpand("SIGNAL_FILES", ""),
	Vars:         envFileContentExpand("SIGNAL_VARS", ""),
	BaseTemplate: envStringExpand("SIGNAL_BASE_TEMPLATE", ""),
	CacheSize:    envGet("SIGNAL_CACHE_SIZE", 0).(int),
}*/

func getOnlyEnv(key string) string {
	value, ok := os.LookupEnv(key)
	if ok {
		return value
	}
	return fmt.Sprintf("$%s", key)
}

func envGet(s string, def interface{}) interface{} {
	return utils.EnvGet(fmt.Sprintf("%s_%s", APPNAME, s), def)
}

func envStringExpand(s string, def string) string {
	snew := envGet(s, def).(string)
	return os.Expand(snew, getOnlyEnv)
}

func envFileContentExpand(s string, def string) string {
	snew := envGet(s, def).(string)
	bytes, err := utils.Content(snew)
	if err != nil {
		return def
	}
	return os.Expand(string(bytes), getOnlyEnv)
}

func interceptSyscall() {

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-c
		logs.Info("Exiting...")
		os.Exit(1)
	}()
}

func runSchedule(s *gocron.Scheduler, schedule string, wait bool, jobFun interface{}) {

	var ss *gocron.Scheduler
	if len(strings.Split(schedule, " ")) == 1 {
		ss = s.Every(schedule)
	} else {
		ss = s.Cron(schedule)
	}
	if wait {
		ss = ss.WaitForSchedule()
	}
	ss.Do(jobFun)
}

/*
func runStandAloneDiscovery(wg *sync.WaitGroup, discovery common.Discovery, logger *sreCommon.Logs) {

		if utils.IsEmpty(discovery) {
			return
		}
		wg.Add(1)
		go func(d common.Discovery) {
			defer wg.Done()
			d.Discover()
		}(discovery)
		logger.Debug("%s: discovery enabled on event", discovery.Name())
	}

func runSimpleDiscovery(wg *sync.WaitGroup, scheduler *gocron.Scheduler, schedule string, discovery common.Discovery, logger *sreCommon.Logs) {

		if utils.IsEmpty(discovery) {
			return
		}
		// run once and return if there is flag
		if rootOptions.RunOnce {
			wg.Add(1)
			go func(d common.Discovery) {
				defer wg.Done()
				d.Discover()
			}(discovery)
			return
		}
		// run on schedule if there is one defined
		if !utils.IsEmpty(schedule) {
			runSchedule(scheduler, schedule, rootOptions.SchedulerWait, discovery.Discover)
			logger.Debug("%s: discovery enabled on schedule: %s", discovery.Name(), schedule)
		}
	}
*/
func Execute() {

	rootCmd := &cobra.Command{
		Use:   "discovery",
		Short: "Discovery",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {

			stdoutOptions.Version = version
			stdout = sreProvider.NewStdout(stdoutOptions)
			if utils.Contains(rootOptions.Logs, "stdout") && stdout != nil {
				stdout.SetCallerOffset(2)
				logs.Register(stdout)
			}

			logs.Info("Booting...")

			// Metrics
			prometheusMetricsOptions.Version = version
			prometheus := sreProvider.NewPrometheusMeter(prometheusMetricsOptions, logs, stdout)
			if utils.Contains(rootOptions.Metrics, "prometheus") && prometheus != nil {
				prometheus.StartInWaitGroup(&mainWG)
				metrics.Register(prometheus)
			}
		},
		Run: func(cmd *cobra.Command, args []string) {

			obs := common.NewObservability(logs, metrics)

			notifiers := common.NewNotifiers(obs)
			notifiers.Add(notifier.NewSlack(notifierSlack, obs))

			verifiers := common.NewVerifiers(obs, notifiers)
			verifiers.Add(verifier.NewHttp(verifierHttp, obs))

			observers := common.NewObservers(obs, verifiers)
			observers.Add(observer.NewDatadog(observerDatadog, obs))

			sources := common.NewSources(obs, observers)
			sources.Add(source.NewConfig(sourceConfig, obs))

			// define scheduler
			scheduler := gocron.NewScheduler(time.UTC)
			wg := &sync.WaitGroup{}

			// run simple discoveries
			/*
				runSimpleDiscovery(wg, scheduler, dObserviumOptions.Schedule, discovery.NewObservium(dObserviumOptions, obs, processors), logger)
				runSimpleDiscovery(wg, scheduler, dZabbixOptions.Schedule, discovery.NewZabbix(dZabbixOptions, obs, processors), logger)
				runSimpleDiscovery(wg, scheduler, dK8sOptions.Schedule, discovery.NewK8s(dK8sOptions, obs, processors), logger)
				runSimpleDiscovery(wg, scheduler, dVCenterOptions.Schedule, discovery.NewVCenter(dVCenterOptions, obs, processors), logger)
				runSimpleDiscovery(wg, scheduler, dAWSEC2Options.Schedule, discovery.NewAWSEC2(dAWSEC2Options, obs, processors), logger)
				runSimpleDiscovery(wg, scheduler, dDumbOptions.Schedule, discovery.NewDumb(dDumbOptions, obs, processors), logger)
			*/

			scheduler.StartAsync()

			// run supportive discoveries without scheduler
			if !rootOptions.RunOnce {
				/*
					runStandAloneDiscovery(wg, discovery.NewPubSub(dPubSubOptions, obs, processors), logger)
					runStandAloneDiscovery(wg, discovery.NewFiles(dFilesOptions, obs, processors), logger)
				*/
			}
			wg.Wait()

			// start wait if there are some jobs
			if scheduler.Len() > 0 {
				mainWG.Wait()
			}
		},
	}

	flags := rootCmd.PersistentFlags()

	flags.StringSliceVar(&rootOptions.Logs, "logs", rootOptions.Logs, "Log providers: stdout")
	flags.StringSliceVar(&rootOptions.Metrics, "metrics", rootOptions.Metrics, "Metric providers: prometheus")
	flags.BoolVar(&rootOptions.RunOnce, "run-once", rootOptions.RunOnce, "Run once")
	flags.BoolVar(&rootOptions.SchedulerWait, "scheduler-wait", rootOptions.SchedulerWait, "Scheduler wait until first try")

	flags.StringVar(&stdoutOptions.Format, "stdout-format", stdoutOptions.Format, "Stdout format: json, text, template")
	flags.StringVar(&stdoutOptions.Level, "stdout-level", stdoutOptions.Level, "Stdout level: info, warn, error, debug, panic")
	flags.StringVar(&stdoutOptions.Template, "stdout-template", stdoutOptions.Template, "Stdout template")
	flags.StringVar(&stdoutOptions.TimestampFormat, "stdout-timestamp-format", stdoutOptions.TimestampFormat, "Stdout timestamp format")
	flags.BoolVar(&stdoutOptions.TextColors, "stdout-text-colors", stdoutOptions.TextColors, "Stdout text colors")
	flags.BoolVar(&stdoutOptions.Debug, "stdout-debug", stdoutOptions.Debug, "Stdout debug")

	flags.StringVar(&prometheusMetricsOptions.URL, "prometheus-metrics-url", prometheusMetricsOptions.URL, "Prometheus metrics endpoint url")
	flags.StringVar(&prometheusMetricsOptions.Listen, "prometheus-metrics-listen", prometheusMetricsOptions.Listen, "Prometheus metrics listen")
	flags.StringVar(&prometheusMetricsOptions.Prefix, "prometheus-metrics-prefix", prometheusMetricsOptions.Prefix, "Prometheus metrics prefix")

	flags.StringVar(&observerDatadog.URL, "observer-datadog", observerDatadog.URL, "Observer datadog url")

	flags.StringVar(&sourceConfig.Path, "config-path", sourceConfig.Path, "Source config path")

	// Signal
	/*
		flags.StringVar(&dSignalOptions.Schedule, "signal-schedule", dSignalOptions.Schedule, "Signal discovery schedule")
		flags.StringVar(&dSignalOptions.Query, "signal-query", dSignalOptions.Query, "Signal discovery query")
		flags.StringVar(&dSignalOptions.QueryPeriod, "signal-query-period", dSignalOptions.QueryPeriod, "Signal discovery query period")
		flags.StringVar(&dSignalOptions.QueryStep, "signal-query-step", dSignalOptions.QueryStep, "Signal discovery query step")
		flags.StringVar(&dSignalOptions.Ident, "signal-object", dSignalOptions.Ident, "Signal discovery ident label")
		flags.StringVar(&dSignalOptions.Field, "signal-field", dSignalOptions.Field, "Signal discovery field label")
		flags.StringVar(&dSignalOptions.Metric, "signal-metric", dSignalOptions.Metric, "Signal discovery metric label")
		flags.StringVar(&dSignalOptions.Files, "signal-files", dSignalOptions.Files, "Signal discovery files")
		flags.StringSliceVar(&dSignalOptions.Disabled, "signal-disabled", dSignalOptions.Disabled, "Signal discovery disabled services")
		flags.StringVar(&dSignalOptions.BaseTemplate, "signal-base-template", dSignalOptions.BaseTemplate, "Signal discovery base template")
		flags.StringVar(&dSignalOptions.Vars, "signal-vars", dSignalOptions.Vars, "Signal discovery vars")
	*/

	interceptSyscall()

	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version number",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version)
		},
	})

	if err := rootCmd.Execute(); err != nil {
		logs.Error(err)
		os.Exit(1)
	}
}
