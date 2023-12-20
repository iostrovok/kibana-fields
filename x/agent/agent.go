package agent

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	BuildOriginal fields.Field = "agent.build.original" // Extended build information for the agent.
	EphemeralID   fields.Field = "agent.ephemeral_id"   // Ephemeral identifier of this agent.
	ID            fields.Field = "agent.id"             // Unique identifier of this agent.
	Name          fields.Field = "agent.name"           // Custom name of the agent.
	Type          fields.Field = "agent.type"           // Type of the agent.
	Version       fields.Field = "agent.version"        // Version of the agent.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	BuildOriginal,
	EphemeralID,
	ID,
	Name,
	Type,
	Version,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	BuildOriginal fields.KeyWord
	EphemeralID   fields.KeyWord
	ID            fields.KeyWord
	Name          fields.KeyWord
	Type          fields.KeyWord
	Version       fields.KeyWord
}

var Types TypesType = TypesType{}
