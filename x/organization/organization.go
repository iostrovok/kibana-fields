package organization

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	ID   fields.Field = "organization.id"   // Unique identifier for the organization.
	Name fields.Field = "organization.name" // Organization name.

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
