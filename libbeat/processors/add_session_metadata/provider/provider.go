package provider

type Provider interface {
	Start() error
	Stop() error
}
