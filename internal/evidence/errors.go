package evidence

import "errors"

// ErrUnsupportedType signals that a registered collector cannot handle the
// requested evidence type. The Registry treats this as a soft failure and
// falls back to a fixture if one is declared, so collectors can be
// incrementally extended without breaking control evaluation.
var ErrUnsupportedType = errors.New("evidence type not supported by collector")
