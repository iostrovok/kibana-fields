package service

/*
	The service fields describe the service for or from which the data was collected.
	These fields help you find and correlate logs for a specific service and version.
*/

import "github.com/iostrovok/kibana-fields/face"

// All available fields as constants
const (
	Address     face.Field = "service.address"      // Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets).
	EphemeralID face.Field = "service.ephemeral_id" // Ephemeral identifier of this service (if one exists). type: keyword
	ID          face.Field = "service.id"           //  Unique identifier of the running service. If the service is comprised of many nodes, the service.id should be the same for all nodes. type: keyword
	Name        face.Field = "service.name"         // Name of the service data is collected from. type: keyword
	NodeName    face.Field = "service.node.name"    // Name of a service node. type: keyword
	NodeRoles   face.Field = "service.node.roles"   // Roles of a service node.
	State       face.Field = "service.state"        //  Current state of the service. type: keyword
	Type        face.Field = "service.type"         // The type of the service data is collected from. type: keyword
	Version     face.Field = "service.version"      //  Version of the service the data was collected from. type: keyword
)

// All package constants as list
var Fields = []face.Field{
	Address,
	EphemeralID,
	ID,
	Name,
	NodeName,
	NodeRoles,
	State,
	Type,
	Version,
}

// Types describes kibana types of fields
var Types = map[face.Field]face.Type{
	Address:     face.KeyWord,
	EphemeralID: face.KeyWord,
	ID:          face.KeyWord,
	Name:        face.KeyWord,
	NodeName:    face.KeyWord,
	NodeRoles:   face.KeyWord,
	State:       face.KeyWord,
	Type:        face.KeyWord,
	Version:     face.KeyWord,
}
