package security

// ------------------------------------------------------------
// OPTS

type Opts struct {
	Padding Padding
}

// ------------------------------------------------------------
// PADDING

type Padding int

const (
	PaddingNone Padding = iota
	PaddingPkcs7
)
