package fields

import (
	"strings"
)

// Field is used for supporting namespace
type Field string

func (f Field) String() string {
	return string(f)
}

// Label presents the name as labels key (no main) in Kibana
//
//	"http.request.body.content" => "http_request_body_content"
func (f Field) Label() string {
	return strings.Replace(string(f), ".", "_", -1)
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
