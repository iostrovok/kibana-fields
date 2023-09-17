package hash

/*
The hash fields represent different bitwise hash algorithms and their values.

Field names for common hashes (e.g. MD5, SHA1) are predefined. Add fields for other hashes by lowercasing the hash algorithm name and using underscore separators as appropriate (snake case, e.g. sha3_512).

Note that this fieldset is used for common hashes that may be computed over a range of generic bytes. Entity-specific hashes such as ja3 or imphash are placed in the fieldsets to which they relate (tls and pe, respectively).
*/

import (
	"github.com/iostrovok/kibana-fields/face"
)

// All available fields as constants
const (
	Md5    face.Field = "hash.md5"
	Sha1   face.Field = "hash.sha1"
	Sha256 face.Field = "hash.sha256"
	Sha384 face.Field = "hash.sha384"
	Sha512 face.Field = "hash.sha512"
	Ssdeep face.Field = "hash.ssdeep"
	Tlsh   face.Field = "hash.tlsh"
)

// All package constants as list
var Fields = []face.Field{
	Md5,
	Sha1,
	Sha256,
	Sha384,
	Sha512,
	Ssdeep,
	Tlsh,
}

// Types describes kibana types of fields
var Types = map[face.Field]face.Type{
	Md5:    face.KeyWord,
	Sha1:   face.KeyWord,
	Sha256: face.KeyWord,
	Sha384: face.KeyWord,
	Sha512: face.KeyWord,
	Ssdeep: face.KeyWord,
	Tlsh:   face.KeyWord,
}
