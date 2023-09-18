package agent

import "github.com/iostrovok/kibana-fields/face"

// All available fields as constants
const (
	EphemeralID   face.Field = "agent.ephemeral_id"   // Unique identifier of this agent (if one exists). type: keyword
	BuildOriginal face.Field = "agent.build.original" // Unique identifier of this agent (if one exists). type: keyword
	ID            face.Field = "agent.id"             // Unique identifier of this agent (if one exists). type: keyword
	Name          face.Field = "agent.name"           // Custom name of the agent. type: keyword
	Type          face.Field = "agent.type"           // Type of the agent. type: keyword
	Version       face.Field = "agent.version"        // Version of the agent. type: keyword
)

// All package constants as list
var Fields = []face.Field{
	BuildOriginal,
	EphemeralID,
	ID,
	Name,
	Type,
	Version,
}

// Types describes kibana types of fields
var Types = map[face.Field]face.Type{
	BuildOriginal: face.KeyWord,
	EphemeralID:   face.KeyWord,
	ID:            face.KeyWord,
	Name:          face.KeyWord,
	Type:          face.KeyWord,
	Version:       face.KeyWord,
}
