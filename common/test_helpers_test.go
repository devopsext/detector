package common

import (
	sreCommon "github.com/devopsext/sre/common"
)

// nopLogger is a no-op implementation of sreCommon.Logger for tests.
type nopLogger struct{}

func (n *nopLogger) Info(_ interface{}, _ ...interface{}) sreCommon.Logger  { return n }
func (n *nopLogger) Warn(_ interface{}, _ ...interface{}) sreCommon.Logger  { return n }
func (n *nopLogger) Error(_ interface{}, _ ...interface{}) sreCommon.Logger { return n }
func (n *nopLogger) Debug(_ interface{}, _ ...interface{}) sreCommon.Logger { return n }
func (n *nopLogger) Panic(_ interface{}, _ ...interface{})                  {}
func (n *nopLogger) Stack(_ int) sreCommon.Logger                           { return n }
func (n *nopLogger) Stop()                                                  {}

func (n *nopLogger) SpanInfo(_ sreCommon.TracerSpan, _ interface{}, _ ...interface{}) sreCommon.Logger {
	return n
}
func (n *nopLogger) SpanWarn(_ sreCommon.TracerSpan, _ interface{}, _ ...interface{}) sreCommon.Logger {
	return n
}
func (n *nopLogger) SpanError(_ sreCommon.TracerSpan, _ interface{}, _ ...interface{}) sreCommon.Logger {
	return n
}
func (n *nopLogger) SpanDebug(_ sreCommon.TracerSpan, _ interface{}, _ ...interface{}) sreCommon.Logger {
	return n
}
func (n *nopLogger) SpanPanic(_ sreCommon.TracerSpan, _ interface{}, _ ...interface{}) {}

// testLogger returns a no-op Logger safe for use in tests.
func testLogger() sreCommon.Logger {
	return &nopLogger{}
}
