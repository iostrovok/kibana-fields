package user_agent

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	UserAgentDeviceName fields.Field = "user_agent.device.name" // Name of the device.
	UserAgentName       fields.Field = "user_agent.name"        // Name of the user agent.
	UserAgentOriginal   fields.Field = "user_agent.original"    // Unparsed user_agent string.
	UserAgentOsFamily   fields.Field = "user_agent.os.family"   // OS family (such as redhat, debian, freebsd, windows).
	UserAgentOsFull     fields.Field = "user_agent.os.full"     // Operating system name, including the version or code name.
	UserAgentOsKernel   fields.Field = "user_agent.os.kernel"   // Operating system kernel version as a raw string.
	UserAgentOsName     fields.Field = "user_agent.os.name"     // Operating system name, without the version.
	UserAgentOsPlatform fields.Field = "user_agent.os.platform" // Operating system platform (such centos, ubuntu, windows).
	UserAgentOsType     fields.Field = "user_agent.os.type"     // Which commercial OS family (one of: linux, macos, unix, windows, ios or android).
	UserAgentOsVersion  fields.Field = "user_agent.os.version"  // Operating system version as a raw string.
	UserAgentVersion    fields.Field = "user_agent.version"     // Version of the user agent.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	UserAgentDeviceName,
	UserAgentName,
	UserAgentOriginal,
	UserAgentOsFamily,
	UserAgentOsFull,
	UserAgentOsKernel,
	UserAgentOsName,
	UserAgentOsPlatform,
	UserAgentOsType,
	UserAgentOsVersion,
	UserAgentVersion,
}

type UserAgentOsTypeExpectedType struct {
	Android string
	Ios     string
	Linux   string
	Macos   string
	Unix    string
	Windows string
}

var UserAgentOsTypeExpectedValues UserAgentOsTypeExpectedType = UserAgentOsTypeExpectedType{
	Android: `android`,
	Ios:     `ios`,
	Linux:   `linux`,
	Macos:   `macos`,
	Unix:    `unix`,
	Windows: `windows`,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	UserAgentDeviceName fields.KeyWord
	UserAgentName       fields.KeyWord
	UserAgentOriginal   fields.KeyWord
	UserAgentOsFamily   fields.KeyWord
	UserAgentOsFull     fields.KeyWord
	UserAgentOsKernel   fields.KeyWord
	UserAgentOsName     fields.KeyWord
	UserAgentOsPlatform fields.KeyWord
	UserAgentOsType     fields.KeyWord
	UserAgentOsVersion  fields.KeyWord
	UserAgentVersion    fields.KeyWord
}

var Types TypesType = TypesType{}
