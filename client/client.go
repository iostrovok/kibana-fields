package client

import "github.com/iostrovok/kibana-fields/face"

// All available fields as constants
const (
	// Some event client addresses are defined ambiguously.
	// The event will sometimes list an IP, a domain or a unix socket.
	// You should always store the raw address in the .address field.
	// Then it should be duplicated to .ip or .domain, depending on which one it is.
	Address          face.Field = "client.address"
	Bytes            face.Field = "client.bytes"             // Bytes sent from the client to the server, type: long
	Domain           face.Field = "client.domain"            // Client domain, type: keyword
	IP               face.Field = "client.ip"                // IP address of the client. Can be one or multiple IPv4 or IPv6 addresses.
	Mac              face.Field = "client.mac"               // MAC address of the client.
	NatIP            face.Field = "client.nat.ip"            // Translated IP of source based NAT sessions.
	NatPort          face.Field = "client.nat.port"          // Translated port of source based NAT sessions.
	Packets          face.Field = "client.packets"           // Packets sent from the client to the server.
	Port             face.Field = "client.port"              // Port of the client.
	Subdomain        face.Field = "client.subdomain"         // The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.
	RegisteredDomain face.Field = "client.registered_domain" // The highest registered client domain, stripped of the subdomain.
	TopLevelDomain   face.Field = "client.top_level_domain"  // The effective top level domain (eTLD), also known as the domain suffix
)

// All package constants as list
var Fields = []face.Field{
	Address,
	Bytes,
	Domain,
	IP,
	Mac,
	NatIP,
	NatPort,
	Packets,
	Port,
	Subdomain,
	RegisteredDomain,
	TopLevelDomain,
}

// Types describes kibana types of fields
var Types = map[face.Field]face.Type{
	Address:          face.KeyWord,
	Bytes:            face.Long,
	Domain:           face.KeyWord,
	IP:               face.IP,
	Mac:              face.KeyWord,
	NatIP:            face.IP,
	NatPort:          face.Long,
	Packets:          face.Long,
	Port:             face.Long,
	Subdomain:        face.KeyWord,
	RegisteredDomain: face.KeyWord,
	TopLevelDomain:   face.KeyWord,
}
