package cloud

/*
	Fields related to the cloud or infrastructure the events are coming from.
*/

import "github.com/iostrovok/kibana-fields/face"

// All available fields as constants
const (
	AccountID        face.Field = "cloud.account.id"        // The cloud account or organization id used to identify different entities in a multi-tenant environment, keyword
	AccountName      face.Field = "cloud.account.name"      // The cloud account name or alias used to identify different entities in a multi-tenant environment, keyword
	AvailabilityZone face.Field = "cloud.availability_zone" // Availability zone in which this host is running, keyword
	InstanceID       face.Field = "cloud.instance.id"       // Instance ID of the host machine, keyword
	InstanceName     face.Field = "cloud.instance.name"     // Instance name of the host machine, keyword
	MachineType      face.Field = "cloud.machine.type"      // Machine type of the host machine, keyword
	ProjectID        face.Field = "cloud.project.id"        // The cloud project identifier, keyword
	ProjectName      face.Field = "cloud.project.name"      // The cloud project name, keyword
	Provider         face.Field = "cloud.provider"          // Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean, keyword
	Region           face.Field = "cloud.region"            // Region in which this host is running, keyword
	ServiceName      face.Field = "cloud.service.name"      // Region in which this host is running, keyword
)

// All package constants as list
var Fields = []face.Field{
	AccountID,
	AccountName,
	AvailabilityZone,
	InstanceID,
	InstanceName,
	MachineType,
	ProjectID,
	ProjectName,
	Provider,
	Region,
	ServiceName,
}

// Types describes kibana types of fields
var Types = map[face.Field]face.Type{
	AccountID:        face.KeyWord,
	AccountName:      face.KeyWord,
	AvailabilityZone: face.KeyWord,
	InstanceID:       face.KeyWord,
	InstanceName:     face.KeyWord,
	MachineType:      face.KeyWord,
	ProjectID:        face.KeyWord,
	ProjectName:      face.KeyWord,
	Provider:         face.KeyWord,
	Region:           face.KeyWord,
	ServiceName:      face.KeyWord,
}
