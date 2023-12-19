package observer

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	EgressInterfaceAlias  fields.Field = "observer.egress.interface.alias"  // Interface alias
	EgressInterfaceID     fields.Field = "observer.egress.interface.id"     // Interface ID
	EgressInterfaceName   fields.Field = "observer.egress.interface.name"   // Interface name
	EgressVlanID          fields.Field = "observer.egress.vlan.id"          // VLAN ID as reported by the observer.
	EgressVlanName        fields.Field = "observer.egress.vlan.name"        // Optional VLAN name as reported by the observer.
	EgressZone            fields.Field = "observer.egress.zone"             // Observer Egress zone
	GeoCityName           fields.Field = "observer.geo.city_name"           // City name.
	GeoContinentCode      fields.Field = "observer.geo.continent_code"      // Continent code.
	GeoContinentName      fields.Field = "observer.geo.continent_name"      // Name of the continent.
	GeoCountryIsoCode     fields.Field = "observer.geo.country_iso_code"    // Country ISO code.
	GeoCountryName        fields.Field = "observer.geo.country_name"        // Country name.
	GeoLocation           fields.Field = "observer.geo.location"            // Longitude and latitude.
	GeoName               fields.Field = "observer.geo.name"                // User-defined description of a location.
	GeoPostalCode         fields.Field = "observer.geo.postal_code"         // Postal code.
	GeoRegionIsoCode      fields.Field = "observer.geo.region_iso_code"     // Region ISO code.
	GeoRegionName         fields.Field = "observer.geo.region_name"         // Region name.
	GeoTimezone           fields.Field = "observer.geo.timezone"            // The time zone of the location, such as IANA time zone name.
	Hostname              fields.Field = "observer.hostname"                // Hostname of the observer.
	IngressInterfaceAlias fields.Field = "observer.ingress.interface.alias" // Interface alias
	IngressInterfaceID    fields.Field = "observer.ingress.interface.id"    // Interface ID
	IngressInterfaceName  fields.Field = "observer.ingress.interface.name"  // Interface name
	IngressVlanID         fields.Field = "observer.ingress.vlan.id"         // VLAN ID as reported by the observer.
	IngressVlanName       fields.Field = "observer.ingress.vlan.name"       // Optional VLAN name as reported by the observer.
	IngressZone           fields.Field = "observer.ingress.zone"            // Observer ingress zone
	Ip                    fields.Field = "observer.ip"                      // IP addresses of the observer.
	Mac                   fields.Field = "observer.mac"                     // MAC addresses of the observer.
	Name                  fields.Field = "observer.name"                    // Custom name of the observer.
	OsFamily              fields.Field = "observer.os.family"               // OS family (such as redhat, debian, freebsd, windows).
	OsFull                fields.Field = "observer.os.full"                 // Operating system name, including the version or code name.
	OsKernel              fields.Field = "observer.os.kernel"               // Operating system kernel version as a raw string.
	OsName                fields.Field = "observer.os.name"                 // Operating system name, without the version.
	OsPlatform            fields.Field = "observer.os.platform"             // Operating system platform (such centos, ubuntu, windows).
	OsType                fields.Field = "observer.os.type"                 // Which commercial OS family (one of: linux, macos, unix, windows, ios or android).
	OsVersion             fields.Field = "observer.os.version"              // Operating system version as a raw string.
	Product               fields.Field = "observer.product"                 // The product name of the observer.
	SerialNumber          fields.Field = "observer.serial_number"           // Observer serial number.
	Type                  fields.Field = "observer.type"                    // The type of the observer the data is coming from.
	Vendor                fields.Field = "observer.vendor"                  // Vendor name of the observer.
	Version               fields.Field = "observer.version"                 // Observer version.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	EgressInterfaceAlias,
	EgressInterfaceID,
	EgressInterfaceName,
	EgressVlanID,
	EgressVlanName,
	EgressZone,
	GeoCityName,
	GeoContinentCode,
	GeoContinentName,
	GeoCountryIsoCode,
	GeoCountryName,
	GeoLocation,
	GeoName,
	GeoPostalCode,
	GeoRegionIsoCode,
	GeoRegionName,
	GeoTimezone,
	Hostname,
	IngressInterfaceAlias,
	IngressInterfaceID,
	IngressInterfaceName,
	IngressVlanID,
	IngressVlanName,
	IngressZone,
	Ip,
	Mac,
	Name,
	OsFamily,
	OsFull,
	OsKernel,
	OsName,
	OsPlatform,
	OsType,
	OsVersion,
	Product,
	SerialNumber,
	Type,
	Vendor,
	Version,
}

type OsTypeExpectedType struct {
	Android string
	Ios     string
	Linux   string
	Macos   string
	Unix    string
	Windows string
}

var OsTypeExpectedValues OsTypeExpectedType = OsTypeExpectedType{
	Android: `android`,
	Ios:     `ios`,
	Linux:   `linux`,
	Macos:   `macos`,
	Unix:    `unix`,
	Windows: `windows`,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	EgressInterfaceAlias  fields.KeyWord
	EgressInterfaceID     fields.KeyWord
	EgressInterfaceName   fields.KeyWord
	EgressVlanID          fields.KeyWord
	EgressVlanName        fields.KeyWord
	EgressZone            fields.KeyWord
	GeoCityName           fields.KeyWord
	GeoContinentCode      fields.KeyWord
	GeoContinentName      fields.KeyWord
	GeoCountryIsoCode     fields.KeyWord
	GeoCountryName        fields.KeyWord
	GeoLocation           fields.GeoPoint
	GeoName               fields.KeyWord
	GeoPostalCode         fields.KeyWord
	GeoRegionIsoCode      fields.KeyWord
	GeoRegionName         fields.KeyWord
	GeoTimezone           fields.KeyWord
	Hostname              fields.KeyWord
	IngressInterfaceAlias fields.KeyWord
	IngressInterfaceID    fields.KeyWord
	IngressInterfaceName  fields.KeyWord
	IngressVlanID         fields.KeyWord
	IngressVlanName       fields.KeyWord
	IngressZone           fields.KeyWord
	Ip                    fields.IP
	Mac                   fields.KeyWord
	Name                  fields.KeyWord
	OsFamily              fields.KeyWord
	OsFull                fields.KeyWord
	OsKernel              fields.KeyWord
	OsName                fields.KeyWord
	OsPlatform            fields.KeyWord
	OsType                fields.KeyWord
	OsVersion             fields.KeyWord
	Product               fields.KeyWord
	SerialNumber          fields.KeyWord
	Type                  fields.KeyWord
	Vendor                fields.KeyWord
	Version               fields.KeyWord
}

var Types TypesType = TypesType{}
