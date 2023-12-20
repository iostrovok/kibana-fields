package geo

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	CityName       fields.Field = "geo.city_name"        // City name.
	ContinentCode  fields.Field = "geo.continent_code"   // Continent code.
	ContinentName  fields.Field = "geo.continent_name"   // Name of the continent.
	CountryIsoCode fields.Field = "geo.country_iso_code" // Country ISO code.
	CountryName    fields.Field = "geo.country_name"     // Country name.
	Location       fields.Field = "geo.location"         // Longitude and latitude.
	Name           fields.Field = "geo.name"             // User-defined description of a location.
	PostalCode     fields.Field = "geo.postal_code"      // Postal code.
	RegionIsoCode  fields.Field = "geo.region_iso_code"  // Region ISO code.
	RegionName     fields.Field = "geo.region_name"      // Region name.
	Timezone       fields.Field = "geo.timezone"         // The time zone of the location, such as IANA time zone name.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	CityName,
	ContinentCode,
	ContinentName,
	CountryIsoCode,
	CountryName,
	Location,
	Name,
	PostalCode,
	RegionIsoCode,
	RegionName,
	Timezone,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	CityName       fields.KeyWord
	ContinentCode  fields.KeyWord
	ContinentName  fields.KeyWord
	CountryIsoCode fields.KeyWord
	CountryName    fields.KeyWord
	Location       fields.GeoPoint
	Name           fields.KeyWord
	PostalCode     fields.KeyWord
	RegionIsoCode  fields.KeyWord
	RegionName     fields.KeyWord
	Timezone       fields.KeyWord
}

var Types TypesType = TypesType{}
