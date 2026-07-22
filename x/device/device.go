package device

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	ID              fields.Field = "device.id"               // The unique identifier of a device.
	Manufacturer    fields.Field = "device.manufacturer"     // The vendor name of the device manufacturer.
	ModelIdentifier fields.Field = "device.model.identifier" // The machine readable identifier of the device model.
	ModelName       fields.Field = "device.model.name"       // The human readable marketing name of the device model.
	ProductID       fields.Field = "device.product.id"       // ProductID of the device
	ProductName     fields.Field = "device.product.name"     // Product name of the device
	SerialNumber    fields.Field = "device.serial_number"    // Serial Number of the device
	Type            fields.Field = "device.type"             // Device type classification
	VendorID        fields.Field = "device.vendor.id"        // VendorID of the device
	VendorName      fields.Field = "device.vendor.name"      // Vendor name of the device

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	ID,
	Manufacturer,
	ModelIdentifier,
	ModelName,
	ProductID,
	ProductName,
	SerialNumber,
	Type,
	VendorID,
	VendorName,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	ID              fields.Keyword
	Manufacturer    fields.Keyword
	ModelIdentifier fields.Keyword
	ModelName       fields.Keyword
	ProductID       fields.Keyword
	ProductName     fields.Keyword
	SerialNumber    fields.Keyword
	Type            fields.Keyword
	VendorID        fields.Keyword
	VendorName      fields.Keyword
}

var Types TypesType = TypesType{}
