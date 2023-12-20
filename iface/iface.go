package iface

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Alias fields.Field = "interface.alias" // Interface alias
	ID    fields.Field = "interface.id"    // Interface ID
	Name  fields.Field = "interface.name"  // Interface name

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Alias,
	ID,
	Name,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Alias fields.KeyWord
	ID    fields.KeyWord
	Name  fields.KeyWord
}

var Types TypesType = TypesType{}
