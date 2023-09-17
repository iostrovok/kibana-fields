package error

import "github.com/iostrovok/kibana-fields/face"

// All available fields as constants
const (
	Code       face.Field = "error.code"        // Error code describing the error. type: keyword
	ID         face.Field = "error.id"          // Unique identifier for the error. type: keyword
	Message    face.Field = "error.message"     // Error message. type: text
	StackTrace face.Field = "error.stack_trace" // The stack trace of this error in plain text. type: keyword
	Type       face.Field = "error.type"        // The type of the error, for example the class name of the exception. type: keyword
)

// All package constants as list
var Fields = []face.Field{
	Code,
	ID,
	Message,
	StackTrace,
	Type,
}

// Types describes kibana types of fields
var Types = map[face.Field]face.Type{
	Code:       face.KeyWord,
	ID:         face.KeyWord,
	Message:    face.MatchOnlyText,
	StackTrace: face.MultiFields,
	Type:       face.KeyWord,
}
