package network

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Application   fields.Field = "network.application"     // Application level protocol name.
	Bytes         fields.Field = "network.bytes"           // Total bytes transferred in both directions.
	CommunityID   fields.Field = "network.community_id"    // A hash of source and destination IPs and ports.
	Direction     fields.Field = "network.direction"       // Direction of the network traffic.
	ForwardedIp   fields.Field = "network.forwarded_ip"    // Host IP address when the source IP address is the proxy.
	IanaNumber    fields.Field = "network.iana_number"     // IANA Protocol Number.
	Inner         fields.Field = "network.inner"           // Inner VLAN tag information
	InnerVlanID   fields.Field = "network.inner.vlan.id"   // VLAN ID as reported by the observer.
	InnerVlanName fields.Field = "network.inner.vlan.name" // Optional VLAN name as reported by the observer.
	Name          fields.Field = "network.name"            // Name given by operators to sections of their network.
	Packets       fields.Field = "network.packets"         // Total packets transferred in both directions.
	Protocol      fields.Field = "network.protocol"        // Application protocol name.
	Transport     fields.Field = "network.transport"       // Protocol Name corresponding to the field `iana_number`.
	Type          fields.Field = "network.type"            // In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc
	VlanID        fields.Field = "network.vlan.id"         // VLAN ID as reported by the observer.
	VlanName      fields.Field = "network.vlan.name"       // Optional VLAN name as reported by the observer.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Application,
	Bytes,
	CommunityID,
	Direction,
	ForwardedIp,
	IanaNumber,
	Inner,
	InnerVlanID,
	InnerVlanName,
	Name,
	Packets,
	Protocol,
	Transport,
	Type,
	VlanID,
	VlanName,
}

type DirectionExpectedType struct {
	Egress   string
	External string
	Inbound  string
	Ingress  string
	Internal string
	Outbound string
	Unknown  string
}

var DirectionExpectedValues DirectionExpectedType = DirectionExpectedType{
	Egress:   `egress`,
	External: `external`,
	Inbound:  `inbound`,
	Ingress:  `ingress`,
	Internal: `internal`,
	Outbound: `outbound`,
	Unknown:  `unknown`,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Application   fields.Keyword
	Bytes         fields.Long
	CommunityID   fields.Keyword
	Direction     fields.Keyword
	ForwardedIp   fields.IP
	IanaNumber    fields.Keyword
	Inner         fields.Object
	InnerVlanID   fields.Keyword
	InnerVlanName fields.Keyword
	Name          fields.Keyword
	Packets       fields.Long
	Protocol      fields.Keyword
	Transport     fields.Keyword
	Type          fields.Keyword
	VlanID        fields.Keyword
	VlanName      fields.Keyword
}

var Types TypesType = TypesType{}
