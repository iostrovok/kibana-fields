package entity_reference

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	EntityReferenceEntityID    fields.Field = "entity_reference.entity.id"    // Identifiers of referenced entities.
	EntityReferenceHostID      fields.Field = "entity_reference.host.id"      // Referenced host ids.
	EntityReferenceHostName    fields.Field = "entity_reference.host.name"    // Referenced host names.
	EntityReferenceServiceID   fields.Field = "entity_reference.service.id"   // Referenced service ids.
	EntityReferenceServiceName fields.Field = "entity_reference.service.name" // Referenced service names.
	EntityReferenceUserDomain  fields.Field = "entity_reference.user.domain"  // Referenced user directory or AD/LDAP domain names.
	EntityReferenceUserEmail   fields.Field = "entity_reference.user.email"   // Referenced user email addresses.
	EntityReferenceUserID      fields.Field = "entity_reference.user.id"      // Referenced user ids.
	EntityReferenceUserName    fields.Field = "entity_reference.user.name"    // Referenced user short names or logins.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	EntityReferenceEntityID,
	EntityReferenceHostID,
	EntityReferenceHostName,
	EntityReferenceServiceID,
	EntityReferenceServiceName,
	EntityReferenceUserDomain,
	EntityReferenceUserEmail,
	EntityReferenceUserID,
	EntityReferenceUserName,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	EntityReferenceEntityID    fields.Keyword
	EntityReferenceHostID      fields.Keyword
	EntityReferenceHostName    fields.Keyword
	EntityReferenceServiceID   fields.Keyword
	EntityReferenceServiceName fields.Keyword
	EntityReferenceUserDomain  fields.Keyword
	EntityReferenceUserEmail   fields.Keyword
	EntityReferenceUserID      fields.Keyword
	EntityReferenceUserName    fields.Keyword
}

var Types TypesType = TypesType{}
