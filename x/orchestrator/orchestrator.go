package orchestrator

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	ApiVersion         fields.Field = "orchestrator.api_version"          // API version being used to carry out the action
	ClusterID          fields.Field = "orchestrator.cluster.id"           // Unique ID of the cluster.
	ClusterName        fields.Field = "orchestrator.cluster.name"         // Name of the cluster.
	ClusterUrl         fields.Field = "orchestrator.cluster.url"          // URL of the API used to manage the cluster.
	ClusterVersion     fields.Field = "orchestrator.cluster.version"      // The version of the cluster.
	Namespace          fields.Field = "orchestrator.namespace"            // Namespace in which the action is taking place.
	Organization       fields.Field = "orchestrator.organization"         // Organization affected by the event (for multi-tenant orchestrator setups).
	ResourceAnnotation fields.Field = "orchestrator.resource.annotation"  // The list of annotations added to the resource.
	ResourceID         fields.Field = "orchestrator.resource.id"          // Unique ID of the resource being acted upon.
	ResourceIp         fields.Field = "orchestrator.resource.ip"          // IP address assigned to the resource associated with the event being observed.
	ResourceLabel      fields.Field = "orchestrator.resource.label"       // The list of labels added to the resource.
	ResourceName       fields.Field = "orchestrator.resource.name"        // Name of the resource being acted upon.
	ResourceParentType fields.Field = "orchestrator.resource.parent.type" // Type or kind of the parent resource associated with the event being observed.
	ResourceType       fields.Field = "orchestrator.resource.type"        // Type of resource being acted upon.
	Type               fields.Field = "orchestrator.type"                 // Orchestrator cluster type (e.g. kubernetes, nomad or cloudfoundry).

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	ApiVersion,
	ClusterID,
	ClusterName,
	ClusterUrl,
	ClusterVersion,
	Namespace,
	Organization,
	ResourceAnnotation,
	ResourceID,
	ResourceIp,
	ResourceLabel,
	ResourceName,
	ResourceParentType,
	ResourceType,
	Type,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	ApiVersion         fields.KeyWord
	ClusterID          fields.KeyWord
	ClusterName        fields.KeyWord
	ClusterUrl         fields.KeyWord
	ClusterVersion     fields.KeyWord
	Namespace          fields.KeyWord
	Organization       fields.KeyWord
	ResourceAnnotation fields.KeyWord
	ResourceID         fields.KeyWord
	ResourceIp         fields.IP
	ResourceLabel      fields.KeyWord
	ResourceName       fields.KeyWord
	ResourceParentType fields.KeyWord
	ResourceType       fields.KeyWord
	Type               fields.KeyWord
}

var Types TypesType = TypesType{}
