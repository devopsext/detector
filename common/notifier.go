package common

type Notifier interface {
	Notify() error
}
