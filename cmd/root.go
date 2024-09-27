package cmd

import (
	"context"
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

var sourcePubSub = source.PubSubOptions{
	Credentials:  envGet("SOURCE_PUBSUB_CREDENTIALS", "").(string),
	Topic:        envGet("SOURCE_PUBSUB_TOPIC", "").(string),
	Subscription: envGet("SOURCE_PUBSUB_SUBSCRIPTION", "").(string),
	Project:      envGet("SOURCE_PUBSUB_PROJECT", "").(string),
	AckDeadline:  envGet("SOURCE_PUBSUB_ACK_DEADLINE", 20).(int),
	Retention:    envGet("SOURCE_PUBSUB_RETENTION", 86400).(int),
	ConfigFiles:  envStringExpand("SOURCE_PUBSUB_CONFIG_FILES", ""),
	Replacements: envGet("SOURCE_PUBSUB_REPLACEMENTS", "").(string),
}

var observerRandom = observer.RandomOptions{
	Min:   envGet("OBSERVER_RANDOM_MIN", 0.0).(float64),
	Max:   envGet("OBSERVER_RANDOM_MAX", 100.0).(float64),
	Delay: envGet("OBSERVER_RANDOM_DELAY", 0).(int),
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

var verifierRandom = verifier.RandomOptions{
	Min:   envGet("VERIFIER_RANDOM_MIN", 0.0).(float64),
	Max:   envGet("VERIFIER_RANDOM_MAX", 100.0).(float64),
	Delay: envGet("VERIFIER_RANDOM_DELAY", 0).(int),
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

var notifierLogger = notifier.LoggerOptions{}

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

var detectorOptions = common.DetectorOptions{
	StartTimeout: envGet("START_TIMEOUT", 5).(int),
}

type DetectorSimpleOptions struct {
	Schedules string
	Sources   string
	Observers string
	Verifiers string
	Notifiers string
}

var detectorSimple = DetectorSimpleOptions{
	Schedules: envGet("SIMPLE_SCHEDULES", "").(string),
	Sources:   envGet("SIMPLE_SOURCES", "").(string),
	Observers: envGet("SIMPLE_OBSERVERS", "").(string),
	Verifiers: envGet("SIMPLE_VERIFIERS", "").(string),
	Notifiers: envGet("SIMPLE_NOTIFIERS", "").(string),
}

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

func getSimpleDetectors(obs *common.Observability, allSources *common.Sources, allObservers *common.Observers,
	allVerifiers *common.Verifiers, allNotifiers *common.Notifiers) []common.Detector {

	r := []common.Detector{}

	logger := obs.Logs()
	sourceKVs := utils.MapGetKeyValues(detectorSimple.Sources)

	for k, v := range sourceKVs {

		if utils.IsEmpty(k) || utils.IsEmpty(v) {
			continue
		}

		// set schedule
		schedule := "30s"
		scheduleKVs := utils.MapGetKeyValues(detectorSimple.Schedules)
		if !utils.IsEmpty(scheduleKVs[k]) {
			schedule = scheduleKVs[k]
		}

		// find sources
		// "Detector=Config;PubSub,="
		sm := []common.Source{}
		vKeys := strings.Split(v, ";")

		for _, vk := range vKeys {
			vk = strings.TrimSpace(vk)
			if utils.IsEmpty(vk) {
				continue
			}
			s := allSources.FindByName(vk)
			if !utils.IsEmpty(s) {
				sm = append(sm, s)
			}
		}
		if len(sm) == 0 {
			sm = allSources.Items()
		}

		// set observer configurations
		observerCfg := ""
		observerKVs := utils.MapGetKeyValues(detectorSimple.Observers)
		if !utils.IsEmpty(observerKVs[k]) {
			observerCfg = observerKVs[k]
		}

		// Detector1=Datadog:0.0;Observer:1.0
		oc := allObservers.FindConfigurationByPattern(observerCfg)
		if len(oc) == 0 {
			logger.Debug("Boot couldn't find observers for %s", observerCfg)
			continue
		}

		// set verifier configurations
		verifierCfg := ""
		verifierKVs := utils.MapGetKeyValues(detectorSimple.Verifiers)
		if !utils.IsEmpty(verifierKVs[k]) {
			verifierCfg = verifierKVs[k]
		}

		// Detector=Site24x7:0.0
		vc := allVerifiers.FindConfigurationByPattern(verifierCfg)
		if len(vc) == 0 {
			logger.Debug("Boot couldn't find verifiers for %s", verifierCfg)
			continue
		}

		// set notifier configurations
		notifierCfg := ""
		notifierKVs := utils.MapGetKeyValues(detectorSimple.Notifiers)
		if !utils.IsEmpty(notifierKVs[k]) {
			notifierCfg = notifierKVs[k]
		}

		// Detector=Slack:0.0
		nc := allNotifiers.FindConfigurationByPattern(notifierCfg)
		if len(nc) == 0 {
			logger.Debug("Boot couldn't find notifiers for %s", notifierCfg)
			continue
		}

		opts := detector.SimpleOptions{
			Name:                   k,
			Schedule:               schedule,
			Sources:                sm,
			ObserverConfigurations: oc,
			VerifierConfigurations: vc,
			NotifierConfigurations: nc,
		}

		d := detector.NewSimple(&opts, obs)
		if utils.IsEmpty(d) {
			continue
		}
		r = append(r, d)
	}

	return r
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
			ctx := context.Background()

			sources := common.NewSources(obs)
			sources.Add(source.NewConfig(&sourceConfig, obs))
			sources.Add(source.NewPubSub(&sourcePubSub, obs, ctx))

			observers := common.NewObservers(obs)
			observers.Add(observer.NewRandom(&observerRandom, obs))
			observers.Add(observer.NewDatadog(&observerDatadog, obs))

			verifiers := common.NewVerifiers(obs)
			verifiers.Add(verifier.NewRandom(&verifierRandom, obs))
			verifiers.Add(verifier.NewSite24x7(&verifierSite24x7, obs))
			verifiers.Add(verifier.NewHttp(&verifierHttp, obs))

			notifiers := common.NewNotifiers(obs)
			notifiers.Add(notifier.NewLogger(notifierLogger, obs))
			notifiers.Add(notifier.NewSlack(notifierSlack, obs))

			detectors := common.NewDetectors(&detectorOptions, obs)
			detectors.Add(getSimpleDetectors(obs, sources, observers, verifiers, notifiers)...)

			detectors.Start(rootOptions.RunOnce, rootOptions.SchedulerWait, ctx)

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

	flags.StringVar(&sourcePubSub.Credentials, "source-pubsub-credentials", sourcePubSub.Credentials, "Source pubsub credentials")
	flags.StringVar(&sourcePubSub.Topic, "source-pubsub-topic", sourcePubSub.Topic, "Source pubsub topic")
	flags.StringVar(&sourcePubSub.Subscription, "source-pubsub-subscription", sourcePubSub.Subscription, "Source pubsub subscription")
	flags.StringVar(&sourcePubSub.Project, "source-pubsub-project", sourcePubSub.Project, "Source pubsub project")
	flags.IntVar(&sourcePubSub.AckDeadline, "source-pubsub-ack-deadline", sourcePubSub.AckDeadline, "Source pubsub subscription ack deadline duration seconds")
	flags.IntVar(&sourcePubSub.Retention, "source-pubsub-retention", sourcePubSub.Retention, "Source pubsub subscription retention duration seconds")
	flags.StringVar(&sourcePubSub.ConfigFiles, "source-pubsub-config-files", sourcePubSub.ConfigFiles, "Source pubsub config files")
	flags.StringVar(&sourcePubSub.Replacements, "source-pubsub-replacements", sourcePubSub.Replacements, "Source pubsub replacements")

	flags.Float64Var(&observerRandom.Min, "observer-random-min", observerRandom.Min, "Observer random min value")
	flags.Float64Var(&observerRandom.Max, "observer-random-max", observerRandom.Max, "Observer random max value")
	flags.IntVar(&observerRandom.Delay, "observer-random-delay", observerRandom.Delay, "Observer random delay")

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

	flags.Float64Var(&verifierRandom.Min, "verifier-random-min", verifierRandom.Min, "Verifier random min value")
	flags.Float64Var(&verifierRandom.Max, "verifier-random-max", verifierRandom.Max, "Verifier random max value")
	flags.IntVar(&verifierRandom.Delay, "verifier-random-delay", verifierRandom.Delay, "Verifier random delay")

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

	flags.StringVar(&detectorSimple.Schedules, "detector-simple-schedules", detectorSimple.Schedules, "Detector simple schedules")
	flags.StringVar(&detectorSimple.Sources, "detector-simple-sources", detectorSimple.Sources, "Detector simple sources")
	flags.StringVar(&detectorSimple.Observers, "detector-simple-observers", detectorSimple.Observers, "Detector simple observers")
	flags.StringVar(&detectorSimple.Verifiers, "detector-simple-verifiers", detectorSimple.Verifiers, "Detector simple verifiers")
	flags.StringVar(&detectorSimple.Notifiers, "detector-simple-notifiers", detectorSimple.Notifiers, "Detector simple notifiers")

	flags.IntVar(&detectorOptions.StartTimeout, "start-timeout", detectorOptions.StartTimeout, "Detector start timeout")

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
