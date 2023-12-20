package pkg

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Architecture fields.Field = "package.architecture"  // Package architecture.
	BuildVersion fields.Field = "package.build_version" // Build version information
	Checksum     fields.Field = "package.checksum"      // Checksum of the installed package for verification.
	Description  fields.Field = "package.description"   // Description of the package.
	InstallScope fields.Field = "package.install_scope" // Indicating how the package was installed, e.g. user-local, global.
	Installed    fields.Field = "package.installed"     // Time when package was installed.
	License      fields.Field = "package.license"       // Package license
	Name         fields.Field = "package.name"          // Package name
	Path         fields.Field = "package.path"          // Path where the package is installed.
	Reference    fields.Field = "package.reference"     // Package home page or reference URL
	Size         fields.Field = "package.size"          // Package size in bytes.
	Type         fields.Field = "package.type"          // Package type
	Version      fields.Field = "package.version"       // Package version

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Architecture,
	BuildVersion,
	Checksum,
	Description,
	InstallScope,
	Installed,
	License,
	Name,
	Path,
	Reference,
	Size,
	Type,
	Version,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Architecture fields.KeyWord
	BuildVersion fields.KeyWord
	Checksum     fields.KeyWord
	Description  fields.KeyWord
	InstallScope fields.KeyWord
	Installed    fields.Date
	License      fields.KeyWord
	Name         fields.KeyWord
	Path         fields.KeyWord
	Reference    fields.KeyWord
	Size         fields.Long
	Type         fields.KeyWord
	Version      fields.KeyWord
}

var Types TypesType = TypesType{}
