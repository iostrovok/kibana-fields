package tracing

/*
	Distributed tracing makes it possible to analyze performance throughout a microservice architecture all in one view.
	This is accomplished by tracing all of the requests - from the initial web request in the front-end service -
	to queries made through multiple back-end services.

	Unlike most field sets in ECS, the tracing fields are not nested under the field set name. In other words,
	the correct field name is trace.id, not tracing.trace.id, and so on.
*/

import "github.com/iostrovok/kibana-fields/face"

// All available fields as constants
const (
	SpanID        face.Field = "span.id"        // Unique identifier of the span within the scope of its trace, keyword
	TraceID       face.Field = "trace.id"       // Unique identifier of the trace, keyword
	TransactionID face.Field = "transaction.id" // Unique identifier of the transaction within the scope of its trace, keyword
)

// All package constants as list
var Fields = []face.Field{
	SpanID,        // Unique identifier of the span within the scope of its trace, keyword
	TraceID,       // Unique identifier of the trace, keyword
	TransactionID, // Unique identifier of the transaction within the scope of its trace, keyword
}

// Types describes kibana types of fields
var Types = map[face.Field]face.Type{
	SpanID:        face.KeyWord,
	TraceID:       face.KeyWord,
	TransactionID: face.KeyWord,
}
