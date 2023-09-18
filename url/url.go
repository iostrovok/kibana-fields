package url

/*
	URL fields provide support for complete or partial URLs,
	and supports the breaking down into scheme, domain, path, and so on.
*/

import "github.com/iostrovok/kibana-fields/face"

// All available fields as constants
const (
	Domain           face.Field = "url.domain"            // Domain of the url, such as "www.elastic.co". type: keyword
	Extension        face.Field = "url.extension"         // The field contains the file extension from the original request url. the value must be "png", not ".png". type: keyword
	Fragment         face.Field = "url.fragment"          // Portion of the url after the #, such as "top". The # is not part of the fragment. type: keyword
	Full             face.Field = "url.full"              // If full URLs are important to your use case, they should be stored in full Field = "url.full" //, whether this field is reconstructed or present in the event source. type: keyword
	Original         face.Field = "url.original"          // Unmodified original url as seen in the event source. type: keyword
	Password         face.Field = "url.password"          // Password of the request. type: keyword
	Path             face.Field = "url.path"              // Path of the request, such as "/search". type: keyword
	Port             face.Field = "url.port"              // Port of the request, such as 443. type: long
	Query            face.Field = "url.query"             // The query field describes the query string of the request, such as "q=elasticsearch". type: keyword
	RegisteredDomain face.Field = "url.registered_domain" // The highest registered url domain, stripped of the subdomain. type: keyword
	Scheme           face.Field = "url.scheme"            //  Scheme of the request, such as "https". type: keyword
	Subdomain        face.Field = "url.subdomain"         //  The subdomain portion of a fully qualified domain name includes all the names except the host name under the registered_domain. In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain.
	TopLevelDomain   face.Field = "url.top_level_domain"  // example: co.uk  type: keyword
	UserName         face.Field = "url.username"          // Username of the request. type: keyword
)

// All package constants as list
var Fields = []face.Field{
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
	UserName,
}

// Types describes kibana types of fields
var Types = map[face.Field]face.Type{
	Domain:           face.KeyWord,
	Extension:        face.KeyWord,
	Fragment:         face.KeyWord,
	Full:             face.Wildcard,
	Original:         face.Wildcard,
	Password:         face.KeyWord,
	Path:             face.Wildcard,
	Port:             face.Long,
	Query:            face.KeyWord,
	RegisteredDomain: face.KeyWord,
	Scheme:           face.KeyWord,
	Subdomain:        face.KeyWord,
	TopLevelDomain:   face.KeyWord,
	UserName:         face.KeyWord,
}
