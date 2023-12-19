package registry

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	DataBytes   fields.Field = "registry.data.bytes"   // Original bytes written with base64 encoding.
	DataStrings fields.Field = "registry.data.strings" // List of strings representing what was written to the registry.
	DataType    fields.Field = "registry.data.type"    // Standard registry type for encoding contents
	Hive        fields.Field = "registry.hive"         // Abbreviated name for the hive.
	Key         fields.Field = "registry.key"          // Hive-relative path of keys.
	Path        fields.Field = "registry.path"         // Full path, including hive, key and value
	Value       fields.Field = "registry.value"        // Name of the value written.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	DataBytes,
	DataStrings,
	DataType,
	Hive,
	Key,
	Path,
	Value,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	DataBytes   fields.KeyWord
	DataStrings fields.Wildcard
	DataType    fields.KeyWord
	Hive        fields.KeyWord
	Key         fields.KeyWord
	Path        fields.KeyWord
	Value       fields.KeyWord
}

var Types TypesType = TypesType{}
