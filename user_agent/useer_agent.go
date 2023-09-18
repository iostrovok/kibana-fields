package user_agent

/*
	The user_agent fields normally come from a browser request.
	They often show up in web service logs coming from the parsed user agent string.
*/

import "github.com/iostrovok/kibana-fields/face"

// All available fields as constants
const (
	DeviceName face.Field = "user_agent.device.name" // Name of the device.
	Name       face.Field = "user_agent.name"        // Name of the user agent.
	Original   face.Field = "user_agent.original"    // Unparsed user_agent string.
	Version    face.Field = "user_agent.version"     // Version of the user agent.
)

// All package constants as list
var Fields = []face.Field{
	DeviceName,
	Name,
	Original,
	Version,
}

// Types describes kibana types of fields
var Types = map[face.Field]face.Type{
	DeviceName: face.KeyWord,
	Name:       face.KeyWord,
	Original:   face.KeyWord,
	Version:    face.KeyWord,
}
