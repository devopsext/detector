package common

type Endpoint struct {
	URL       string
	Disabled  bool
	Countries []string
}

type Endpoints = []*Endpoint

const (
	EndpointTypeUnknown = 0
	EndpointTypeHttp    = 1
	EndpointTypeTcp     = 2
)

const (
	EndpointSchemaUnknown = ""
	EndpointSchemaHttp    = "http"
	EndpointSchemaHttps   = "https"
	EndpointSchemaTcp     = "tcp"
)

func (e *Endpoint) Type() int {
	return EndpointTypeUnknown
}

func (e *Endpoint) Schema() string {
	return EndpointSchemaUnknown
}
