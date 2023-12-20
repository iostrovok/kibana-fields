package ecs

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Version fields.Field = "ecs.version" // ECS version this event conforms to.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Version,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Version fields.KeyWord
}

var Types TypesType = TypesType{}
