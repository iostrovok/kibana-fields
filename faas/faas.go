package faas

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Coldstart        fields.Field = "faas.coldstart"          // Boolean value indicating a cold start of a function.
	Execution        fields.Field = "faas.execution"          // The execution ID of the current function execution.
	ID               fields.Field = "faas.id"                 // The unique identifier of a serverless function.
	Name             fields.Field = "faas.name"               // The name of a serverless function.
	TriggerRequestID fields.Field = "faas.trigger.request_id" // The ID of the trigger request , message, event, etc.
	TriggerType      fields.Field = "faas.trigger.type"       // The trigger for the function execution.
	Version          fields.Field = "faas.version"            // The version of a serverless function.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Coldstart,
	Execution,
	ID,
	Name,
	TriggerRequestID,
	TriggerType,
	Version,
}

type TriggerTypeExpectedType struct {
	Datasource string
	Http       string
	Other      string
	Pubsub     string
	Timer      string
}

var TriggerTypeExpectedValues TriggerTypeExpectedType = TriggerTypeExpectedType{
	Datasource: `datasource`,
	Http:       `http`,
	Other:      `other`,
	Pubsub:     `pubsub`,
	Timer:      `timer`,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Coldstart        fields.Boolean
	Execution        fields.KeyWord
	ID               fields.KeyWord
	Name             fields.KeyWord
	TriggerRequestID fields.KeyWord
	TriggerType      fields.KeyWord
	Version          fields.KeyWord
}

var Types TypesType = TypesType{}
