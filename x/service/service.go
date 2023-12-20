package service

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Address           fields.Field = "service.address"             // Address of this service.
	Environment       fields.Field = "service.environment"         // Environment of the service.
	EphemeralID       fields.Field = "service.ephemeral_id"        // Ephemeral identifier of this service.
	ID                fields.Field = "service.id"                  // Unique identifier of the running service.
	Name              fields.Field = "service.name"                // Name of the service.
	NodeName          fields.Field = "service.node.name"           // Name of the service node.
	NodeRole          fields.Field = "service.node.role"           // Deprecated role (singular) of the service node.
	NodeRoles         fields.Field = "service.node.roles"          // Roles of the service node.
	OriginAddress     fields.Field = "service.origin.address"      // Address of this service.
	OriginEnvironment fields.Field = "service.origin.environment"  // Environment of the service.
	OriginEphemeralID fields.Field = "service.origin.ephemeral_id" // Ephemeral identifier of this service.
	OriginID          fields.Field = "service.origin.id"           // Unique identifier of the running service.
	OriginName        fields.Field = "service.origin.name"         // Name of the service.
	OriginNodeName    fields.Field = "service.origin.node.name"    // Name of the service node.
	OriginNodeRole    fields.Field = "service.origin.node.role"    // Deprecated role (singular) of the service node.
	OriginNodeRoles   fields.Field = "service.origin.node.roles"   // Roles of the service node.
	OriginState       fields.Field = "service.origin.state"        // Current state of the service.
	OriginType        fields.Field = "service.origin.type"         // The type of the service.
	OriginVersion     fields.Field = "service.origin.version"      // Version of the service.
	State             fields.Field = "service.state"               // Current state of the service.
	TargetAddress     fields.Field = "service.target.address"      // Address of this service.
	TargetEnvironment fields.Field = "service.target.environment"  // Environment of the service.
	TargetEphemeralID fields.Field = "service.target.ephemeral_id" // Ephemeral identifier of this service.
	TargetID          fields.Field = "service.target.id"           // Unique identifier of the running service.
	TargetName        fields.Field = "service.target.name"         // Name of the service.
	TargetNodeName    fields.Field = "service.target.node.name"    // Name of the service node.
	TargetNodeRole    fields.Field = "service.target.node.role"    // Deprecated role (singular) of the service node.
	TargetNodeRoles   fields.Field = "service.target.node.roles"   // Roles of the service node.
	TargetState       fields.Field = "service.target.state"        // Current state of the service.
	TargetType        fields.Field = "service.target.type"         // The type of the service.
	TargetVersion     fields.Field = "service.target.version"      // Version of the service.
	Type              fields.Field = "service.type"                // The type of the service.
	Version           fields.Field = "service.version"             // Version of the service.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Address,
	Environment,
	EphemeralID,
	ID,
	Name,
	NodeName,
	NodeRole,
	NodeRoles,
	OriginAddress,
	OriginEnvironment,
	OriginEphemeralID,
	OriginID,
	OriginName,
	OriginNodeName,
	OriginNodeRole,
	OriginNodeRoles,
	OriginState,
	OriginType,
	OriginVersion,
	State,
	TargetAddress,
	TargetEnvironment,
	TargetEphemeralID,
	TargetID,
	TargetName,
	TargetNodeName,
	TargetNodeRole,
	TargetNodeRoles,
	TargetState,
	TargetType,
	TargetVersion,
	Type,
	Version,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Address           fields.KeyWord
	Environment       fields.KeyWord
	EphemeralID       fields.KeyWord
	ID                fields.KeyWord
	Name              fields.KeyWord
	NodeName          fields.KeyWord
	NodeRole          fields.KeyWord
	NodeRoles         fields.KeyWord
	OriginAddress     fields.KeyWord
	OriginEnvironment fields.KeyWord
	OriginEphemeralID fields.KeyWord
	OriginID          fields.KeyWord
	OriginName        fields.KeyWord
	OriginNodeName    fields.KeyWord
	OriginNodeRole    fields.KeyWord
	OriginNodeRoles   fields.KeyWord
	OriginState       fields.KeyWord
	OriginType        fields.KeyWord
	OriginVersion     fields.KeyWord
	State             fields.KeyWord
	TargetAddress     fields.KeyWord
	TargetEnvironment fields.KeyWord
	TargetEphemeralID fields.KeyWord
	TargetID          fields.KeyWord
	TargetName        fields.KeyWord
	TargetNodeName    fields.KeyWord
	TargetNodeRole    fields.KeyWord
	TargetNodeRoles   fields.KeyWord
	TargetState       fields.KeyWord
	TargetType        fields.KeyWord
	TargetVersion     fields.KeyWord
	Type              fields.KeyWord
	Version           fields.KeyWord
}

var Types TypesType = TypesType{}
