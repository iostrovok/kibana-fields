package source

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Address            fields.Field = "source.address"              // Source network address.
	AsNumber           fields.Field = "source.as.number"            // Unique number allocated to the autonomous system.
	AsOrganizationName fields.Field = "source.as.organization.name" // Organization name.
	Bytes              fields.Field = "source.bytes"                // Bytes sent from the source to the destination.
	Domain             fields.Field = "source.domain"               // The domain name of the source.
	GeoCityName        fields.Field = "source.geo.city_name"        // City name.
	GeoContinentCode   fields.Field = "source.geo.continent_code"   // Continent code.
	GeoContinentName   fields.Field = "source.geo.continent_name"   // Name of the continent.
	GeoCountryIsoCode  fields.Field = "source.geo.country_iso_code" // Country ISO code.
	GeoCountryName     fields.Field = "source.geo.country_name"     // Country name.
	GeoLocation        fields.Field = "source.geo.location"         // Longitude and latitude.
	GeoName            fields.Field = "source.geo.name"             // User-defined description of a location.
	GeoPostalCode      fields.Field = "source.geo.postal_code"      // Postal code.
	GeoRegionIsoCode   fields.Field = "source.geo.region_iso_code"  // Region ISO code.
	GeoRegionName      fields.Field = "source.geo.region_name"      // Region name.
	GeoTimezone        fields.Field = "source.geo.timezone"         // The time zone of the location, such as IANA time zone name.
	Ip                 fields.Field = "source.ip"                   // IP address of the source.
	Mac                fields.Field = "source.mac"                  // MAC address of the source.
	NatIp              fields.Field = "source.nat.ip"               // Source NAT ip
	NatPort            fields.Field = "source.nat.port"             // Source NAT port
	Packets            fields.Field = "source.packets"              // Packets sent from the source to the destination.
	Port               fields.Field = "source.port"                 // Port of the source.
	RegisteredDomain   fields.Field = "source.registered_domain"    // The highest registered source domain, stripped of the subdomain.
	Subdomain          fields.Field = "source.subdomain"            // The subdomain of the domain.
	TopLevelDomain     fields.Field = "source.top_level_domain"     // The effective top level domain (com, org, net, co.uk).
	UserDomain         fields.Field = "source.user.domain"          // Name of the directory the user is a member of.
	UserEmail          fields.Field = "source.user.email"           // User email address.
	UserFullName       fields.Field = "source.user.full_name"       // User's full name, if available.
	UserGroupDomain    fields.Field = "source.user.group.domain"    // Name of the directory the group is a member of.
	UserGroupID        fields.Field = "source.user.group.id"        // Unique identifier for the group on the system/platform.
	UserGroupName      fields.Field = "source.user.group.name"      // Name of the group.
	UserHash           fields.Field = "source.user.hash"            // Unique user hash to correlate information for a user in anonymized form.
	UserID             fields.Field = "source.user.id"              // Unique identifier of the user.
	UserName           fields.Field = "source.user.name"            // Short name or login of the user.
	UserRoles          fields.Field = "source.user.roles"           // Array of user roles at the time of the event.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Address,
	AsNumber,
	AsOrganizationName,
	Bytes,
	Domain,
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
	Ip,
	Mac,
	NatIp,
	NatPort,
	Packets,
	Port,
	RegisteredDomain,
	Subdomain,
	TopLevelDomain,
	UserDomain,
	UserEmail,
	UserFullName,
	UserGroupDomain,
	UserGroupID,
	UserGroupName,
	UserHash,
	UserID,
	UserName,
	UserRoles,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Address            fields.KeyWord
	AsNumber           fields.Long
	AsOrganizationName fields.KeyWord
	Bytes              fields.Long
	Domain             fields.KeyWord
	GeoCityName        fields.KeyWord
	GeoContinentCode   fields.KeyWord
	GeoContinentName   fields.KeyWord
	GeoCountryIsoCode  fields.KeyWord
	GeoCountryName     fields.KeyWord
	GeoLocation        fields.GeoPoint
	GeoName            fields.KeyWord
	GeoPostalCode      fields.KeyWord
	GeoRegionIsoCode   fields.KeyWord
	GeoRegionName      fields.KeyWord
	GeoTimezone        fields.KeyWord
	Ip                 fields.IP
	Mac                fields.KeyWord
	NatIp              fields.IP
	NatPort            fields.Long
	Packets            fields.Long
	Port               fields.Long
	RegisteredDomain   fields.KeyWord
	Subdomain          fields.KeyWord
	TopLevelDomain     fields.KeyWord
	UserDomain         fields.KeyWord
	UserEmail          fields.KeyWord
	UserFullName       fields.KeyWord
	UserGroupDomain    fields.KeyWord
	UserGroupID        fields.KeyWord
	UserGroupName      fields.KeyWord
	UserHash           fields.KeyWord
	UserID             fields.KeyWord
	UserName           fields.KeyWord
	UserRoles          fields.KeyWord
}

var Types TypesType = TypesType{}
