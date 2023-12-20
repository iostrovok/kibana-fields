package tracing

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	SpanID        fields.Field = "span.id"        // Unique identifier of the span within the scope of its trace.
	TraceID       fields.Field = "trace.id"       // Unique identifier of the trace.
	TransactionID fields.Field = "transaction.id" // Unique identifier of the transaction within the scope of its trace.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	SpanID,
	TraceID,
	TransactionID,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	SpanID        fields.KeyWord
	TraceID       fields.KeyWord
	TransactionID fields.KeyWord
}

var Types TypesType = TypesType{}
