package base

/*
	The base field set contains all fields which are at the root of the events.
	These fields are common across all types of events.
*/

import "github.com/iostrovok/kibana-fields/face"

const (
	Message   face.Field = "message"    // For log events the message field contains the log message, optimized for viewing in a log viewer. type: text
	Timestamp face.Field = "@timestamp" // Date/time when the event originated. type: date
	Labels    face.Field = "labels"     // Custom key/value pairs. type: object
	Tags      face.Field = "tags"       // List of keywords used to tag each event. list of type: keyword
)

var Fields = []face.Field{
	Message,   // For log events the message field contains the log message, optimized for viewing in a log viewer. type: text
	Timestamp, // Date/time when the event originated. type: date
	Labels,    // Custom key/value pairs. type: object
	Tags,      // List of keywords used to tag each event. list of type: keyword
}

// Types describes kibana types of fields
var Types = map[face.Field]face.Type{
	Message:   face.MatchOnlyText,
	Timestamp: face.Date,
	Labels:    face.Object,
	Tags:      face.KeyWord,
}
