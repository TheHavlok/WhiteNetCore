package yandex

import (
	"github.com/thehavlok/whitenet/internal/flux/transport"
)

var _ transport.CookieExchanger = (*YandexDocsTransport)(nil)
