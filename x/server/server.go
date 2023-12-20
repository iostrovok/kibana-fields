package server

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Address            fields.Field = "server.address"              // Server network address.
	AsNumber           fields.Field = "server.as.number"            // Unique number allocated to the autonomous system.
	AsOrganizationName fields.Field = "server.as.organization.name" // Organization name.
	Bytes              fields.Field = "server.bytes"                // Bytes sent from the server to the client.
	Domain             fields.Field = "server.domain"               // The domain name of the server.
	GeoCityName        fields.Field = "server.geo.city_name"        // City name.
	GeoContinentCode   fields.Field = "server.geo.continent_code"   // Continent code.
	GeoContinentName   fields.Field = "server.geo.continent_name"   // Name of the continent.
	GeoCountryIsoCode  fields.Field = "server.geo.country_iso_code" // Country ISO code.
	GeoCountryName     fields.Field = "server.geo.country_name"     // Country name.
	GeoLocation        fields.Field = "server.geo.location"         // Longitude and latitude.
	GeoName            fields.Field = "server.geo.name"             // User-defined description of a location.
	GeoPostalCode      fields.Field = "server.geo.postal_code"      // Postal code.
	GeoRegionIsoCode   fields.Field = "server.geo.region_iso_code"  // Region ISO code.
	GeoRegionName      fields.Field = "server.geo.region_name"      // Region name.
	GeoTimezone        fields.Field = "server.geo.timezone"         // The time zone of the location, such as IANA time zone name.
	Ip                 fields.Field = "server.ip"                   // IP address of the server.
	Mac                fields.Field = "server.mac"                  // MAC address of the server.
	NatIp              fields.Field = "server.nat.ip"               // Server NAT ip
	NatPort            fields.Field = "server.nat.port"             // Server NAT port
	Packets            fields.Field = "server.packets"              // Packets sent from the server to the client.
	Port               fields.Field = "server.port"                 // Port of the server.
	RegisteredDomain   fields.Field = "server.registered_domain"    // The highest registered server domain, stripped of the subdomain.
	Subdomain          fields.Field = "server.subdomain"            // The subdomain of the domain.
	TopLevelDomain     fields.Field = "server.top_level_domain"     // The effective top level domain (com, org, net, co.uk).
	UserDomain         fields.Field = "server.user.domain"          // Name of the directory the user is a member of.
	UserEmail          fields.Field = "server.user.email"           // User email address.
	UserFullName       fields.Field = "server.user.full_name"       // User's full name, if available.
	UserGroupDomain    fields.Field = "server.user.group.domain"    // Name of the directory the group is a member of.
	UserGroupID        fields.Field = "server.user.group.id"        // Unique identifier for the group on the system/platform.
	UserGroupName      fields.Field = "server.user.group.name"      // Name of the group.
	UserHash           fields.Field = "server.user.hash"            // Unique user hash to correlate information for a user in anonymized form.
	UserID             fields.Field = "server.user.id"              // Unique identifier of the user.
	UserName           fields.Field = "server.user.name"            // Short name or login of the user.
	UserRoles          fields.Field = "server.user.roles"           // Array of user roles at the time of the event.

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
