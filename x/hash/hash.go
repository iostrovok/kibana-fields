package hash

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Cdhash fields.Field = "hash.cdhash" // The Code Directory (CD) hash of an executable.
	Md5    fields.Field = "hash.md5"    // MD5 hash.
	Sha1   fields.Field = "hash.sha1"   // SHA1 hash.
	Sha256 fields.Field = "hash.sha256" // SHA256 hash.
	Sha384 fields.Field = "hash.sha384" // SHA384 hash.
	Sha512 fields.Field = "hash.sha512" // SHA512 hash.
	Ssdeep fields.Field = "hash.ssdeep" // SSDEEP hash.
	Tlsh   fields.Field = "hash.tlsh"   // TLSH hash.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Cdhash,
	Md5,
	Sha1,
	Sha256,
	Sha384,
	Sha512,
	Ssdeep,
	Tlsh,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Cdhash fields.Keyword
	Md5    fields.Keyword
	Sha1   fields.Keyword
	Sha256 fields.Keyword
	Sha384 fields.Keyword
	Sha512 fields.Keyword
	Ssdeep fields.Keyword
	Tlsh   fields.Keyword
}

var Types TypesType = TypesType{}
