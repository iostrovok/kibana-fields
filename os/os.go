package os

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Family   fields.Field = "os.family"   // OS family (such as redhat, debian, freebsd, windows).
	Full     fields.Field = "os.full"     // Operating system name, including the version or code name.
	Kernel   fields.Field = "os.kernel"   // Operating system kernel version as a raw string.
	Name     fields.Field = "os.name"     // Operating system name, without the version.
	Platform fields.Field = "os.platform" // Operating system platform (such centos, ubuntu, windows).
	Type     fields.Field = "os.type"     // Which commercial OS family (one of: linux, macos, unix, windows, ios or android).
	Version  fields.Field = "os.version"  // Operating system version as a raw string.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Family,
	Full,
	Kernel,
	Name,
	Platform,
	Type,
	Version,
}

type TypeExpectedType struct {
	Android string
	Ios     string
	Linux   string
	Macos   string
	Unix    string
	Windows string
}

var TypeExpectedValues TypeExpectedType = TypeExpectedType{
	Android: `android`,
	Ios:     `ios`,
	Linux:   `linux`,
	Macos:   `macos`,
	Unix:    `unix`,
	Windows: `windows`,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Family   fields.KeyWord
	Full     fields.KeyWord
	Kernel   fields.KeyWord
	Name     fields.KeyWord
	Platform fields.KeyWord
	Type     fields.KeyWord
	Version  fields.KeyWord
}

var Types TypesType = TypesType{}
