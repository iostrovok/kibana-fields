package rule

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Author      fields.Field = "rule.author"      // Rule author
	Category    fields.Field = "rule.category"    // Rule category
	Description fields.Field = "rule.description" // Rule description
	ID          fields.Field = "rule.id"          // A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event.
	License     fields.Field = "rule.license"     // Rule license
	Name        fields.Field = "rule.name"        // The name of the rule or signature generating the event.
	Reference   fields.Field = "rule.reference"   // Rule reference URL
	Ruleset     fields.Field = "rule.ruleset"     // Rule ruleset
	Uuid        fields.Field = "rule.uuid"        // A rule ID that is unique within the scope of a set or group of agents, observers, or other entities using the rule for detection of this event.
	Version     fields.Field = "rule.version"     // Rule version

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Author,
	Category,
	Description,
	ID,
	License,
	Name,
	Reference,
	Ruleset,
	Uuid,
	Version,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Author      fields.KeyWord
	Category    fields.KeyWord
	Description fields.KeyWord
	ID          fields.KeyWord
	License     fields.KeyWord
	Name        fields.KeyWord
	Reference   fields.KeyWord
	Ruleset     fields.KeyWord
	Uuid        fields.KeyWord
	Version     fields.KeyWord
}

var Types TypesType = TypesType{}
