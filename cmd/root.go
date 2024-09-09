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
	"github.com/devopsext/detector/detector"
	"github.com/devopsext/detector/notifier"
	"github.com/devopsext/detector/observer"
	"github.com/devopsext/detector/source"
	"github.com/devopsext/detector/verifier"
	sreCommon "github.com/devopsext/sre/common"
	sreProvider "github.com/devopsext/sre/provider"
	"github.com/devopsext/tools/vendors"
	"github.com/devopsext/utils"
	"github.com/spf13/cobra"
)

var version = "unknown"
var APPNAME = "DETECTOR"

var logs = sreCommon.NewLogs()
var metrics = sreCommon.NewMetrics()
var stdout *sreProvider.Stdout
var main sync.WaitGroup

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
	Site:       envGet("OBSERVER_DATADOG_SITE", "").(string),
	ApiKey:     envGet("OBSERVER_DATADOG_API_KEY", "").(string),
	AppKey:     envGet("OBSERVER_DATADOG_APP_KEY", "").(string),
	TagUri:     envGet("OBSERVER_DATADOG_TAG_URI", "").(string),
	TagCountry: envGet("OBSERVER_DATADOG_TAG_COUNTRY", "").(string),
	Query:      envFileContentExpand("OBSERVER_DATADOG_QUERY", ""),
	File:       envGet("OBSERVER_DATADOG_FILE", "").(string),
	Min:        envGet("OBSERVER_DATADOG_MIN", 0.0).(float64),
	Max:        envGet("OBSERVER_DATADOG_MAX", 100.0).(float64),
	Duration:   envGet("OBSERVER_DATADOG_DURATION", "").(string),
	Timeout:    envGet("OBSERVER_DATADOG_TIMEOUT", "").(string),
}

var verifierSite24x7 = verifier.Site24x7Options{
	Site24x7Options: vendors.Site24x7Options{
		Timeout:      envGet("VERIFIER_SITE24X7_TIMEOUT", 30).(int),
		Insecure:     envGet("VERIFIER_SITE24X7_INSECURE", false).(bool),
		ClientID:     envGet("VERIFIER_SITE24X7_CLIENT_ID", "").(string),
		ClientSecret: envGet("VERIFIER_SITE24X7_CLIENT_SECRET", "").(string),
		RefreshToken: envGet("VERIFIER_SITE24X7_REFRESH_TOKEN", "").(string),
	},
	MonitorName:           envGet("VERIFIER_SITE24X7_MONITOR_NAME", "detector").(string),
	MonitorFrequency:      envGet("VERIFIER_SITE24X7_MONITOR_FREQUENCY", "1440").(string),
	MonitorTimeout:        envGet("VERIFIER_SITE24X7_MONITOR_TIMEOUT", 30).(int),
	HttpMethod:            envGet("VERIFIER_SITE24X7_HTTP_METHOD", "GET").(string),
	HttpUserAgent:         envGet("VERIFIER_SITE24X7_HTTP_USER_AGENT", "detector").(string),
	NotificationProfileID: envGet("VERIFIER_SITE24X7_NOTIFICATION_PROFILE_ID", "").(string),
	ThresholdProfileID:    envGet("VERIFIER_SITE24X7_THRESHOLD_PROFILE_ID", "").(string),
	UserGroupIDs:          strings.Split(envGet("VERIFIER_SITE24X7_USER_GROUP_IDS", "").(string), ","),
	PollTimeout:           envGet("VERIFIER_SITE24X7_POLL_TIMEOUT", 160).(int),
	PollDelay:             envGet("VERIFIER_SITE24X7_POLL_DELAY", 500).(int),
	LogReportFile:         envGet("VERIFIER_SITE24X7_LOG_REPORT_FILE", "").(string),
}

var verifierHttp = verifier.HttpOptions{
	URL: envGet("VERIFIER_HTTP_URL", "").(string),
}

var notifierSlack = notifier.SlackOptions{
	SlackOptions: vendors.SlackOptions{
		Timeout:  envGet("NOTIFIER_SLACK_TIMEOUT", 30).(int),
		Insecure: envGet("NOTIFIER_SLACK_INSECURE", false).(bool),
		Token:    envGet("NOTIFIER_SLACK_TOKEN", "").(string),
	},
	Channel:  envGet("NOTIFIER_SLACK_CHANNEL", "").(string),
	Message:  envFileContentExpand("NOTIFIER_SLACK_MESSAGE", ""),
	Runbooks: envFileContentExpand("NOTIFIER_SLACK_RUNBOOKS", ""),
}

var detectorAvailability = detector.AvailabilityOptions{
	Schedule:  envGet("AVAILABILITY_SCHEDULE", "").(string),
	Sources:   envGet("AVAILABILITY_SOURCES", "").(string),
	Observers: envGet("AVAILABILITY_OBSERVERS", "").(string),
	Verifiers: envGet("AVAILABILITY_VERIFIERS", "").(string),
	Notifiers: envGet("AVAILABILITY_NOTIFIERS", "").(string),
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
				prometheus.StartInWaitGroup(&main)
				metrics.Register(prometheus)
			}
		},
		Run: func(cmd *cobra.Command, args []string) {

			obs := common.NewObservability(logs, metrics)

			sources := common.NewSources(obs)
			sources.Add(source.NewConfig(&sourceConfig, obs))

			observers := common.NewObservers(obs)
			observers.Add(observer.NewDatadog(&observerDatadog, obs))

			verifiers := common.NewVerifiers(obs)
			verifiers.Add(verifier.NewSite24x7(&verifierSite24x7, obs))
			verifiers.Add(verifier.NewHttp(&verifierHttp, obs))

			notifiers := common.NewNotifiers(obs)
			notifiers.Add(notifier.NewSlack(notifierSlack, obs))

			detectors := common.NewDetectors(obs)
			detectors.Add(detector.NewAvailability(&detectorAvailability, obs, sources, observers, verifiers, notifiers))

			detectors.Start(rootOptions.RunOnce, rootOptions.SchedulerWait)

			// start wait if there are some jobs
			if detectors.Scheduled() {
				main.Wait()
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

	flags.StringVar(&sourceConfig.Path, "source-config-path", sourceConfig.Path, "Source config path")

	flags.StringVar(&observerDatadog.Site, "observer-datadog-site", observerDatadog.Site, "Observer datadog site")
	flags.StringVar(&observerDatadog.AppKey, "observer-datadog-app-key", observerDatadog.AppKey, "Observer datadog app key")
	flags.StringVar(&observerDatadog.ApiKey, "observer-datadog-api-key", observerDatadog.ApiKey, "Observer datadog api key")
	flags.StringVar(&observerDatadog.TagUri, "observer-datadog-tag-uri", observerDatadog.TagUri, "Observer datadog tag uri")
	flags.StringVar(&observerDatadog.TagCountry, "observer-datadog-tag-country", observerDatadog.TagCountry, "Observer datadog tag country")
	flags.StringVar(&observerDatadog.Query, "observer-datadog-query", observerDatadog.Query, "Observer datadog query")
	flags.StringVar(&observerDatadog.File, "observer-datadog-file", observerDatadog.File, "Observer datadog file")
	flags.Float64Var(&observerDatadog.Min, "observer-datadog-min", observerDatadog.Min, "Observer datadog min value")
	flags.Float64Var(&observerDatadog.Max, "observer-datadog-max", observerDatadog.Max, "Observer datadog max value")
	flags.StringVar(&observerDatadog.Duration, "observer-datadog-duration", observerDatadog.Duration, "Observer datadog duration")
	flags.StringVar(&observerDatadog.Timeout, "observer-datadog-timeout", observerDatadog.Timeout, "Observer datadog timeout")

	flags.IntVar(&verifierSite24x7.Site24x7Options.Timeout, "verifier-site24x7-timeout", verifierSite24x7.Site24x7Options.Timeout, "Verifier site24x7 timeout in seconds")
	flags.BoolVar(&verifierSite24x7.Site24x7Options.Insecure, "verifier-site24x7-insecure", verifierSite24x7.Site24x7Options.Insecure, "Verifier site24x7 insecure")
	flags.StringVar(&verifierSite24x7.Site24x7Options.ClientID, "verifier-site24x7-client-id", verifierSite24x7.Site24x7Options.ClientID, "Verifier site24x7 client ID")
	flags.StringVar(&verifierSite24x7.Site24x7Options.ClientSecret, "verifier-site24x7-client-secret", verifierSite24x7.Site24x7Options.ClientSecret, "Verifier site24x7 client secret")
	flags.StringVar(&verifierSite24x7.Site24x7Options.RefreshToken, "verifier-site24x7-refresh-token", verifierSite24x7.Site24x7Options.RefreshToken, "Verifier site24x7 refresh token")
	flags.StringVar(&verifierSite24x7.MonitorName, "verifier-site24x7-monitor-name", verifierSite24x7.MonitorName, "Verifier site24x7 monitor name")
	flags.StringVar(&verifierSite24x7.MonitorFrequency, "verifier-site24x7-monitor-frequency", verifierSite24x7.MonitorFrequency, "Verifier site24x7 monitor frequency")
	flags.IntVar(&verifierSite24x7.MonitorTimeout, "verifier-site24x7-monitor-timeout", verifierSite24x7.MonitorTimeout, "Verifier site24x7 monitor timeout")
	flags.StringVar(&verifierSite24x7.HttpMethod, "verifier-site24x7-http-method", verifierSite24x7.HttpMethod, "Verifier site24x7 http method")
	flags.StringVar(&verifierSite24x7.HttpUserAgent, "verifier-site24x7-http-user-agent", verifierSite24x7.HttpUserAgent, "Verifier site24x7 http user agent")
	flags.StringVar(&verifierSite24x7.NotificationProfileID, "verifier-site24x7-notification-profile-id", verifierSite24x7.NotificationProfileID, "Verifier site24x7 notification profile id")
	flags.StringVar(&verifierSite24x7.ThresholdProfileID, "verifier-site24x7-threshold-profile-id", verifierSite24x7.ThresholdProfileID, "Verifier site24x7 threshold profile id")
	flags.StringSliceVar(&verifierSite24x7.UserGroupIDs, "verifier-site24x7-user-group-ids", verifierSite24x7.UserGroupIDs, "Verifier site24x7 user group ids")
	flags.IntVar(&verifierSite24x7.PollTimeout, "verifier-site24x7-poll-timeout", verifierSite24x7.PollTimeout, "Verifier site24x7 poll timeout in seconds")
	flags.IntVar(&verifierSite24x7.PollDelay, "verifier-site24x7-poll-delay", verifierSite24x7.PollDelay, "Verifier site24x7 poll delay in milliseconds")
	flags.StringVar(&verifierSite24x7.LogReportFile, "verifier-site24x7-log-report-id", verifierSite24x7.LogReportFile, "Verifier site24x7log report file")

	flags.StringVar(&verifierHttp.URL, "verifier-http-url", verifierHttp.URL, "Verfifier http url")

	flags.IntVar(&notifierSlack.SlackOptions.Timeout, "notifier-slack-timeout", notifierSlack.SlackOptions.Timeout, "Notifier slack timeout")
	flags.BoolVar(&notifierSlack.SlackOptions.Insecure, "notifier-slack-insecure", notifierSlack.SlackOptions.Insecure, "Notifier slack insecure")
	flags.StringVar(&notifierSlack.SlackOptions.Token, "notifier-slack-token", notifierSlack.SlackOptions.Token, "Notifier slack token")
	flags.StringVar(&notifierSlack.Channel, "notifier-slack-channel", notifierSlack.Channel, "Notifier slack channel")
	flags.StringVar(&notifierSlack.Message, "notifier-slack-message", notifierSlack.Message, "Notifier slack message")
	flags.StringVar(&notifierSlack.Runbooks, "notifier-slack-runbooks", notifierSlack.Runbooks, "Notifier slack runbooks")

	flags.StringVar(&detectorAvailability.Schedule, "detector-availability-schedule", detectorAvailability.Schedule, "Detector availability schedule")
	flags.StringVar(&detectorAvailability.Sources, "detector-availability-sources", detectorAvailability.Sources, "Detector availability sources")
	flags.StringVar(&detectorAvailability.Observers, "detector-availability-observers", detectorAvailability.Observers, "Detector availability observers")
	flags.StringVar(&detectorAvailability.Verifiers, "detector-availability-verifiers", detectorAvailability.Verifiers, "Detector availability verifiers")
	flags.StringVar(&detectorAvailability.Notifiers, "detector-availability-notifiers", detectorAvailability.Notifiers, "Detector availability notifiers")

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
