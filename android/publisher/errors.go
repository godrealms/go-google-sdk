package publisher

import "errors"

var (
	ErrNotFound     = errors.New("publisher: not found")
	ErrRouteUnknown = errors.New("publisher: cannot determine verification type")
)
