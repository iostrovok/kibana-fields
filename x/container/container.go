package container

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	CpuUsage                  fields.Field = "container.cpu.usage"                   // Percent CPU used, between 0 and 1.
	DiskReadBytes             fields.Field = "container.disk.read.bytes"             // The number of bytes read by all disks.
	DiskWriteBytes            fields.Field = "container.disk.write.bytes"            // The number of bytes written on all disks.
	ID                        fields.Field = "container.id"                          // Unique container id.
	ImageHashAll              fields.Field = "container.image.hash.all"              // An array of digests of the image the container was built on.
	ImageName                 fields.Field = "container.image.name"                  // Name of the image the container was built on.
	ImageTag                  fields.Field = "container.image.tag"                   // Container image tags.
	MemoryUsage               fields.Field = "container.memory.usage"                // Percent memory used, between 0 and 1.
	Name                      fields.Field = "container.name"                        // Container name.
	NetworkEgressBytes        fields.Field = "container.network.egress.bytes"        // The number of bytes sent on all network interfaces.
	NetworkIngressBytes       fields.Field = "container.network.ingress.bytes"       // The number of bytes received on all network interfaces.
	Runtime                   fields.Field = "container.runtime"                     // Runtime managing this container.
	SecurityContextPrivileged fields.Field = "container.security_context.privileged" // Indicates whether the container is running in privileged mode.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	CpuUsage,
	DiskReadBytes,
	DiskWriteBytes,
	ID,
	ImageHashAll,
	ImageName,
	ImageTag,
	MemoryUsage,
	Name,
	NetworkEgressBytes,
	NetworkIngressBytes,
	Runtime,
	SecurityContextPrivileged,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	CpuUsage                  fields.Float
	DiskReadBytes             fields.Long
	DiskWriteBytes            fields.Long
	ID                        fields.KeyWord
	ImageHashAll              fields.KeyWord
	ImageName                 fields.KeyWord
	ImageTag                  fields.KeyWord
	MemoryUsage               fields.Float
	Name                      fields.KeyWord
	NetworkEgressBytes        fields.Long
	NetworkIngressBytes       fields.Long
	Runtime                   fields.KeyWord
	SecurityContextPrivileged fields.Boolean
}

var Types TypesType = TypesType{}
