package observer

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Egress                fields.Field = "observer.egress"                  // Object field for egress information
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
	Ingress               fields.Field = "observer.ingress"                 // Object field for ingress information
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
	Egress,
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
	Ingress,
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
	Egress                fields.Object
	EgressInterfaceAlias  fields.Keyword
	EgressInterfaceID     fields.Keyword
	EgressInterfaceName   fields.Keyword
	EgressVlanID          fields.Keyword
	EgressVlanName        fields.Keyword
	EgressZone            fields.Keyword
	GeoCityName           fields.Keyword
	GeoContinentCode      fields.Keyword
	GeoContinentName      fields.Keyword
	GeoCountryIsoCode     fields.Keyword
	GeoCountryName        fields.Keyword
	GeoLocation           fields.GeoPoint
	GeoName               fields.Keyword
	GeoPostalCode         fields.Keyword
	GeoRegionIsoCode      fields.Keyword
	GeoRegionName         fields.Keyword
	GeoTimezone           fields.Keyword
	Hostname              fields.Keyword
	Ingress               fields.Object
	IngressInterfaceAlias fields.Keyword
	IngressInterfaceID    fields.Keyword
	IngressInterfaceName  fields.Keyword
	IngressVlanID         fields.Keyword
	IngressVlanName       fields.Keyword
	IngressZone           fields.Keyword
	Ip                    fields.IP
	Mac                   fields.Keyword
	Name                  fields.Keyword
	OsFamily              fields.Keyword
	OsFull                fields.Keyword
	OsKernel              fields.Keyword
	OsName                fields.Keyword
	OsPlatform            fields.Keyword
	OsType                fields.Keyword
	OsVersion             fields.Keyword
	Product               fields.Keyword
	SerialNumber          fields.Keyword
	Type                  fields.Keyword
	Vendor                fields.Keyword
	Version               fields.Keyword
}

var Types TypesType = TypesType{}
