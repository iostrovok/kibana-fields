package fields

// Field is used for supporting namespace
type Field string

func (f Field) String() string {
	return string(f)
}

type Boolean string
type ConstantKeyWord string
type Date string
type Flattened string
type Float string
type GeoPoint string
type IP string
type KeyWord string
type Long string
type MatchOnlyText string
type Nested string
type Object string
type ScaledFloat string
type TextOnly string
type Wildcard string
