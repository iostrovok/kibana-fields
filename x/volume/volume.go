package volume

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	BusType        fields.Field = "volume.bus_type"         // Bus type of the device.
	DefaultAccess  fields.Field = "volume.default_access"   // Bus type of the device.
	DeviceName     fields.Field = "volume.device_name"      // Device name of the volume.
	DeviceType     fields.Field = "volume.device_type"      // Volume device type.
	DosName        fields.Field = "volume.dos_name"         // DOS name of the device.
	FileSystemType fields.Field = "volume.file_system_type" // Volume device file system type.
	MountName      fields.Field = "volume.mount_name"       // Mount name of the volume.
	NtName         fields.Field = "volume.nt_name"          // NT name of the device.
	ProductID      fields.Field = "volume.product_id"       // ProductID of the device.
	ProductName    fields.Field = "volume.product_name"     // Produce name of the volume.
	Removable      fields.Field = "volume.removable"        // Indicates if the volume is removable.
	SerialNumber   fields.Field = "volume.serial_number"    // Serial number of the device.
	Size           fields.Field = "volume.size"             // Size of the volume device in bytes.
	VendorID       fields.Field = "volume.vendor_id"        // VendorID of the device.
	VendorName     fields.Field = "volume.vendor_name"      // Vendor name of the device.
	Writable       fields.Field = "volume.writable"         // Indicates if the volume is writable.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	BusType,
	DefaultAccess,
	DeviceName,
	DeviceType,
	DosName,
	FileSystemType,
	MountName,
	NtName,
	ProductID,
	ProductName,
	Removable,
	SerialNumber,
	Size,
	VendorID,
	VendorName,
	Writable,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	BusType        fields.KeyWord
	DefaultAccess  fields.KeyWord
	DeviceName     fields.KeyWord
	DeviceType     fields.KeyWord
	DosName        fields.KeyWord
	FileSystemType fields.KeyWord
	MountName      fields.KeyWord
	NtName         fields.KeyWord
	ProductID      fields.KeyWord
	ProductName    fields.KeyWord
	Removable      fields.Boolean
	SerialNumber   fields.KeyWord
	Size           fields.Long
	VendorID       fields.KeyWord
	VendorName     fields.KeyWord
	Writable       fields.Boolean
}

var Types TypesType = TypesType{}
