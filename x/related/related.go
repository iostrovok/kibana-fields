package related

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Hash  fields.Field = "related.hash"  // All the hashes seen on your event.
	Hosts fields.Field = "related.hosts" // All the host identifiers seen on your event.
	Ip    fields.Field = "related.ip"    // All of the IPs seen on your event.
	User  fields.Field = "related.user"  // All the user names or other user identifiers seen on the event.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Hash,
	Hosts,
	Ip,
	User,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Hash  fields.KeyWord
	Hosts fields.KeyWord
	Ip    fields.IP
	User  fields.KeyWord
}

var Types TypesType = TypesType{}
