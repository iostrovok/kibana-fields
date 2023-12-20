package device

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	ID              fields.Field = "device.id"               // The unique identifier of a device.
	Manufacturer    fields.Field = "device.manufacturer"     // The vendor name of the device manufacturer.
	ModelIdentifier fields.Field = "device.model.identifier" // The machine readable identifier of the device model.
	ModelName       fields.Field = "device.model.name"       // The human readable marketing name of the device model.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	ID,
	Manufacturer,
	ModelIdentifier,
	ModelName,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	ID              fields.KeyWord
	Manufacturer    fields.KeyWord
	ModelIdentifier fields.KeyWord
	ModelName       fields.KeyWord
}

var Types TypesType = TypesType{}
