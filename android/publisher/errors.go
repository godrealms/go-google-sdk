package publisher

import "errors"

var (
	ErrRouteUnknown       = errors.New("publisher: cannot determine verification type")
	ErrMissingPackageName = errors.New("publisher: package name is required")
)
