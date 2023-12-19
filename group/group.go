package group

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Domain fields.Field = "group.domain" // Name of the directory the group is a member of.
	ID     fields.Field = "group.id"     // Unique identifier for the group on the system/platform.
	Name   fields.Field = "group.name"   // Name of the group.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Domain,
	ID,
	Name,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Domain fields.KeyWord
	ID     fields.KeyWord
	Name   fields.KeyWord
}

var Types TypesType = TypesType{}
