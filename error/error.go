package error

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Code       fields.Field = "error.code"        // Error code describing the error.
	ID         fields.Field = "error.id"          // Unique identifier for the error.
	Message    fields.Field = "error.message"     // Error message.
	StackTrace fields.Field = "error.stack_trace" // The stack trace of this error in plain text.
	Type       fields.Field = "error.type"        // The type of the error, for example the class name of the exception.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Code,
	ID,
	Message,
	StackTrace,
	Type,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Code       fields.KeyWord
	ID         fields.KeyWord
	Message    fields.MatchOnlyText
	StackTrace fields.Wildcard
	Type       fields.KeyWord
}

var Types TypesType = TypesType{}
