package url

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Domain           fields.Field = "url.domain"            // Domain of the url.
	Extension        fields.Field = "url.extension"         // File extension from the request url, excluding the leading dot.
	Fragment         fields.Field = "url.fragment"          // Portion of the url after the `#`.
	Full             fields.Field = "url.full"              // Full unparsed URL.
	Original         fields.Field = "url.original"          // Unmodified original url as seen in the event source.
	Password         fields.Field = "url.password"          // Password of the request.
	Path             fields.Field = "url.path"              // Path of the request, such as "/search".
	Port             fields.Field = "url.port"              // Port of the request, such as 443.
	Query            fields.Field = "url.query"             // Query string of the request.
	RegisteredDomain fields.Field = "url.registered_domain" // The highest registered url domain, stripped of the subdomain.
	Scheme           fields.Field = "url.scheme"            // Scheme of the url.
	Subdomain        fields.Field = "url.subdomain"         // The subdomain of the domain.
	TopLevelDomain   fields.Field = "url.top_level_domain"  // The effective top level domain (com, org, net, co.uk).
	Username         fields.Field = "url.username"          // Username of the request.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Domain,
	Extension,
	Fragment,
	Full,
	Original,
	Password,
	Path,
	Port,
	Query,
	RegisteredDomain,
	Scheme,
	Subdomain,
	TopLevelDomain,
	Username,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Domain           fields.KeyWord
	Extension        fields.KeyWord
	Fragment         fields.KeyWord
	Full             fields.Wildcard
	Original         fields.Wildcard
	Password         fields.KeyWord
	Path             fields.Wildcard
	Port             fields.Long
	Query            fields.KeyWord
	RegisteredDomain fields.KeyWord
	Scheme           fields.KeyWord
	Subdomain        fields.KeyWord
	TopLevelDomain   fields.KeyWord
	Username         fields.KeyWord
}

var Types TypesType = TypesType{}
