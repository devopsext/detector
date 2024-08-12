package common

type Endpoint interface {
	Urn() string
	Type() int
	Disabled() bool
	Countries() []string
}

const (
	EndpointTypeUnknown = 0
	EndpointTypeHttp    = 1
	EndpointTypeTcp     = 2
)
