package data_stream

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	DataStreamDataset   fields.Field = "data_stream.dataset"   // The field can contain anything that makes sense to signify the source of the data.
	DataStreamNamespace fields.Field = "data_stream.namespace" // A user defined namespace. Namespaces are useful to allow grouping of data.
	DataStreamType      fields.Field = "data_stream.type"      // An overarching type for the data stream.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	DataStreamDataset,
	DataStreamNamespace,
	DataStreamType,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	DataStreamDataset   fields.ConstantKeyWord
	DataStreamNamespace fields.ConstantKeyWord
	DataStreamType      fields.ConstantKeyWord
}

var Types TypesType = TypesType{}
