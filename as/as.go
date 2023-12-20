package as

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Number           fields.Field = "as.number"            // Unique number allocated to the autonomous system.
	OrganizationName fields.Field = "as.organization.name" // Organization name.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Number,
	OrganizationName,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Number           fields.Long
	OrganizationName fields.KeyWord
}

var Types TypesType = TypesType{}
