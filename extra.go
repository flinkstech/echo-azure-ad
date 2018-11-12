package authenticate

import (
	"github.com/boj/redistore"
	"github.com/gorilla/sessions"
	session "github.com/ipfans/echo-session"
)

type RS struct {
	*redistore.RediStore
}

func (c *RS) Options(options session.Options) {
	c.RediStore.Options = &sessions.Options{
		Path:     options.Path,
		Domain:   options.Domain,
		MaxAge:   options.MaxAge,
		Secure:   options.Secure,
		HttpOnly: options.HttpOnly,
	}
}

func (c *RS) MaxAge(age int) {
	c.RediStore.SetMaxAge(age)
}

func NewRediStore(size int, network, address, password string, keyPairs ...[]byte) (*RS, error) {
	s, err := redistore.NewRediStore(size, network, address, password, keyPairs...)
	s.SetMaxLength(4096 * 2 * 2 * 2 * 2 * 2 * 2 * 2 * 2 * 2)
	if err != nil {
		return &RS{}, err
	}
	store := &RS{s}
	return store, nil
}
