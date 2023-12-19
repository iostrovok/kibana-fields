package client

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Address            fields.Field = "client.address"              // Client network address.
	AsNumber           fields.Field = "client.as.number"            // Unique number allocated to the autonomous system.
	AsOrganizationName fields.Field = "client.as.organization.name" // Organization name.
	Bytes              fields.Field = "client.bytes"                // Bytes sent from the client to the server.
	Domain             fields.Field = "client.domain"               // The domain name of the client.
	GeoCityName        fields.Field = "client.geo.city_name"        // City name.
	GeoContinentCode   fields.Field = "client.geo.continent_code"   // Continent code.
	GeoContinentName   fields.Field = "client.geo.continent_name"   // Name of the continent.
	GeoCountryIsoCode  fields.Field = "client.geo.country_iso_code" // Country ISO code.
	GeoCountryName     fields.Field = "client.geo.country_name"     // Country name.
	GeoLocation        fields.Field = "client.geo.location"         // Longitude and latitude.
	GeoName            fields.Field = "client.geo.name"             // User-defined description of a location.
	GeoPostalCode      fields.Field = "client.geo.postal_code"      // Postal code.
	GeoRegionIsoCode   fields.Field = "client.geo.region_iso_code"  // Region ISO code.
	GeoRegionName      fields.Field = "client.geo.region_name"      // Region name.
	GeoTimezone        fields.Field = "client.geo.timezone"         // The time zone of the location, such as IANA time zone name.
	Ip                 fields.Field = "client.ip"                   // IP address of the client.
	Mac                fields.Field = "client.mac"                  // MAC address of the client.
	NatIp              fields.Field = "client.nat.ip"               // Client NAT ip address
	NatPort            fields.Field = "client.nat.port"             // Client NAT port
	Packets            fields.Field = "client.packets"              // Packets sent from the client to the server.
	Port               fields.Field = "client.port"                 // Port of the client.
	RegisteredDomain   fields.Field = "client.registered_domain"    // The highest registered client domain, stripped of the subdomain.
	Subdomain          fields.Field = "client.subdomain"            // The subdomain of the domain.
	TopLevelDomain     fields.Field = "client.top_level_domain"     // The effective top level domain (com, org, net, co.uk).
	UserDomain         fields.Field = "client.user.domain"          // Name of the directory the user is a member of.
	UserEmail          fields.Field = "client.user.email"           // User email address.
	UserFullName       fields.Field = "client.user.full_name"       // User's full name, if available.
	UserGroupDomain    fields.Field = "client.user.group.domain"    // Name of the directory the group is a member of.
	UserGroupID        fields.Field = "client.user.group.id"        // Unique identifier for the group on the system/platform.
	UserGroupName      fields.Field = "client.user.group.name"      // Name of the group.
	UserHash           fields.Field = "client.user.hash"            // Unique user hash to correlate information for a user in anonymized form.
	UserID             fields.Field = "client.user.id"              // Unique identifier of the user.
	UserName           fields.Field = "client.user.name"            // Short name or login of the user.
	UserRoles          fields.Field = "client.user.roles"           // Array of user roles at the time of the event.

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
