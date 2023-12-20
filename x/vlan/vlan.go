package vlan

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	ID   fields.Field = "vlan.id"   // VLAN ID as reported by the observer.
	Name fields.Field = "vlan.name" // Optional VLAN name as reported by the observer.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	ID,
	Name,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	ID   fields.KeyWord
	Name fields.KeyWord
}

var Types TypesType = TypesType{}
