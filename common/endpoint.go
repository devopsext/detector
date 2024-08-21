package common

type Endpoint struct {
	URI       string
	Disabled  bool
	Countries []string
}

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

func (se *Endpoint) Type() int {
	return EndpointTypeUnknown
}

func (se *Endpoint) Schema() string {
	return EndpointSchemaUnknown
}
