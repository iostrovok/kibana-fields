package cloud

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	AccountID              fields.Field = "cloud.account.id"               // The cloud account or organization id.
	AccountName            fields.Field = "cloud.account.name"             // The cloud account name.
	AvailabilityZone       fields.Field = "cloud.availability_zone"        // Availability zone in which this host, resource, or service is located.
	InstanceID             fields.Field = "cloud.instance.id"              // Instance ID of the host machine.
	InstanceName           fields.Field = "cloud.instance.name"            // Instance name of the host machine.
	MachineType            fields.Field = "cloud.machine.type"             // Machine type of the host machine.
	OriginAccountID        fields.Field = "cloud.origin.account.id"        // The cloud account or organization id.
	OriginAccountName      fields.Field = "cloud.origin.account.name"      // The cloud account name.
	OriginAvailabilityZone fields.Field = "cloud.origin.availability_zone" // Availability zone in which this host, resource, or service is located.
	OriginInstanceID       fields.Field = "cloud.origin.instance.id"       // Instance ID of the host machine.
	OriginInstanceName     fields.Field = "cloud.origin.instance.name"     // Instance name of the host machine.
	OriginMachineType      fields.Field = "cloud.origin.machine.type"      // Machine type of the host machine.
	OriginProjectID        fields.Field = "cloud.origin.project.id"        // The cloud project id.
	OriginProjectName      fields.Field = "cloud.origin.project.name"      // The cloud project name.
	OriginProvider         fields.Field = "cloud.origin.provider"          // Name of the cloud provider.
	OriginRegion           fields.Field = "cloud.origin.region"            // Region in which this host, resource, or service is located.
	OriginServiceName      fields.Field = "cloud.origin.service.name"      // The cloud service name.
	ProjectID              fields.Field = "cloud.project.id"               // The cloud project id.
	ProjectName            fields.Field = "cloud.project.name"             // The cloud project name.
	Provider               fields.Field = "cloud.provider"                 // Name of the cloud provider.
	Region                 fields.Field = "cloud.region"                   // Region in which this host, resource, or service is located.
	ServiceName            fields.Field = "cloud.service.name"             // The cloud service name.
	TargetAccountID        fields.Field = "cloud.target.account.id"        // The cloud account or organization id.
	TargetAccountName      fields.Field = "cloud.target.account.name"      // The cloud account name.
	TargetAvailabilityZone fields.Field = "cloud.target.availability_zone" // Availability zone in which this host, resource, or service is located.
	TargetInstanceID       fields.Field = "cloud.target.instance.id"       // Instance ID of the host machine.
	TargetInstanceName     fields.Field = "cloud.target.instance.name"     // Instance name of the host machine.
	TargetMachineType      fields.Field = "cloud.target.machine.type"      // Machine type of the host machine.
	TargetProjectID        fields.Field = "cloud.target.project.id"        // The cloud project id.
	TargetProjectName      fields.Field = "cloud.target.project.name"      // The cloud project name.
	TargetProvider         fields.Field = "cloud.target.provider"          // Name of the cloud provider.
	TargetRegion           fields.Field = "cloud.target.region"            // Region in which this host, resource, or service is located.
	TargetServiceName      fields.Field = "cloud.target.service.name"      // The cloud service name.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	AccountID,
	AccountName,
	AvailabilityZone,
	InstanceID,
	InstanceName,
	MachineType,
	OriginAccountID,
	OriginAccountName,
	OriginAvailabilityZone,
	OriginInstanceID,
	OriginInstanceName,
	OriginMachineType,
	OriginProjectID,
	OriginProjectName,
	OriginProvider,
	OriginRegion,
	OriginServiceName,
	ProjectID,
	ProjectName,
	Provider,
	Region,
	ServiceName,
	TargetAccountID,
	TargetAccountName,
	TargetAvailabilityZone,
	TargetInstanceID,
	TargetInstanceName,
	TargetMachineType,
	TargetProjectID,
	TargetProjectName,
	TargetProvider,
	TargetRegion,
	TargetServiceName,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	AccountID              fields.KeyWord
	AccountName            fields.KeyWord
	AvailabilityZone       fields.KeyWord
	InstanceID             fields.KeyWord
	InstanceName           fields.KeyWord
	MachineType            fields.KeyWord
	OriginAccountID        fields.KeyWord
	OriginAccountName      fields.KeyWord
	OriginAvailabilityZone fields.KeyWord
	OriginInstanceID       fields.KeyWord
	OriginInstanceName     fields.KeyWord
	OriginMachineType      fields.KeyWord
	OriginProjectID        fields.KeyWord
	OriginProjectName      fields.KeyWord
	OriginProvider         fields.KeyWord
	OriginRegion           fields.KeyWord
	OriginServiceName      fields.KeyWord
	ProjectID              fields.KeyWord
	ProjectName            fields.KeyWord
	Provider               fields.KeyWord
	Region                 fields.KeyWord
	ServiceName            fields.KeyWord
	TargetAccountID        fields.KeyWord
	TargetAccountName      fields.KeyWord
	TargetAvailabilityZone fields.KeyWord
	TargetInstanceID       fields.KeyWord
	TargetInstanceName     fields.KeyWord
	TargetMachineType      fields.KeyWord
	TargetProjectID        fields.KeyWord
	TargetProjectName      fields.KeyWord
	TargetProvider         fields.KeyWord
	TargetRegion           fields.KeyWord
	TargetServiceName      fields.KeyWord
}

var Types TypesType = TypesType{}
