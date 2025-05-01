package libcore

type LocalResolver interface {
	LookupIP(network string, domain string) (string, error)
	Exchange(b []byte) ([]byte, error)
	SupportExchange() bool
}
