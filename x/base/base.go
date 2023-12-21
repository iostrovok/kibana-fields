package base

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Labels    fields.Field = "labels"     // Custom key/value pairs.
	Message   fields.Field = "message"    // Log message optimized for viewing in a log viewer.
	Tags      fields.Field = "tags"       // List of keywords used to tag each event.
	Timestamp fields.Field = "@timestamp" // Date/time when the event originated.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Labels,
	Message,
	Tags,
	Timestamp,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Labels    fields.Object
	Message   fields.MatchOnlyText
	Tags      fields.KeyWord
	Timestamp fields.Date
}

var Types TypesType = TypesType{}
