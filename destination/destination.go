package destination

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Address            fields.Field = "destination.address"              // Destination network address.
	AsNumber           fields.Field = "destination.as.number"            // Unique number allocated to the autonomous system.
	AsOrganizationName fields.Field = "destination.as.organization.name" // Organization name.
	Bytes              fields.Field = "destination.bytes"                // Bytes sent from the destination to the source.
	Domain             fields.Field = "destination.domain"               // The domain name of the destination.
	GeoCityName        fields.Field = "destination.geo.city_name"        // City name.
	GeoContinentCode   fields.Field = "destination.geo.continent_code"   // Continent code.
	GeoContinentName   fields.Field = "destination.geo.continent_name"   // Name of the continent.
	GeoCountryIsoCode  fields.Field = "destination.geo.country_iso_code" // Country ISO code.
	GeoCountryName     fields.Field = "destination.geo.country_name"     // Country name.
	GeoLocation        fields.Field = "destination.geo.location"         // Longitude and latitude.
	GeoName            fields.Field = "destination.geo.name"             // User-defined description of a location.
	GeoPostalCode      fields.Field = "destination.geo.postal_code"      // Postal code.
	GeoRegionIsoCode   fields.Field = "destination.geo.region_iso_code"  // Region ISO code.
	GeoRegionName      fields.Field = "destination.geo.region_name"      // Region name.
	GeoTimezone        fields.Field = "destination.geo.timezone"         // The time zone of the location, such as IANA time zone name.
	Ip                 fields.Field = "destination.ip"                   // IP address of the destination.
	Mac                fields.Field = "destination.mac"                  // MAC address of the destination.
	NatIp              fields.Field = "destination.nat.ip"               // Destination NAT ip
	NatPort            fields.Field = "destination.nat.port"             // Destination NAT Port
	Packets            fields.Field = "destination.packets"              // Packets sent from the destination to the source.
	Port               fields.Field = "destination.port"                 // Port of the destination.
	RegisteredDomain   fields.Field = "destination.registered_domain"    // The highest registered destination domain, stripped of the subdomain.
	Subdomain          fields.Field = "destination.subdomain"            // The subdomain of the domain.
	TopLevelDomain     fields.Field = "destination.top_level_domain"     // The effective top level domain (com, org, net, co.uk).
	UserDomain         fields.Field = "destination.user.domain"          // Name of the directory the user is a member of.
	UserEmail          fields.Field = "destination.user.email"           // User email address.
	UserFullName       fields.Field = "destination.user.full_name"       // User's full name, if available.
	UserGroupDomain    fields.Field = "destination.user.group.domain"    // Name of the directory the group is a member of.
	UserGroupID        fields.Field = "destination.user.group.id"        // Unique identifier for the group on the system/platform.
	UserGroupName      fields.Field = "destination.user.group.name"      // Name of the group.
	UserHash           fields.Field = "destination.user.hash"            // Unique user hash to correlate information for a user in anonymized form.
	UserID             fields.Field = "destination.user.id"              // Unique identifier of the user.
	UserName           fields.Field = "destination.user.name"            // Short name or login of the user.
	UserRoles          fields.Field = "destination.user.roles"           // Array of user roles at the time of the event.

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
