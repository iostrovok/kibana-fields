package event

/*
	The event fields are used for context information about the log or metric event itself.

	A log is defined as an event containing details of something that happened.
	Log events must include the time at which the thing happened. Examples of log events include
	a process starting on a host, a network packet being sent from a source to a destination,
	or a network connection between a client and a server being initiated or closed.
	A metric is defined as an event containing one or more numerical measurements and the time at which
	the measurement was taken. Examples of metric events include memory pressure measured on a host and
	device temperature. See the event.kind definition in this section for additional
	details about metric and state events.
*/

import "github.com/iostrovok/kibana-fields/face"

// All available fields as constants
const (
	Action        face.Field = "event.action"          // The action captured by the event. type: keyword
	AgentIdStatus face.Field = "event.agent_id_status" // Agents are normally responsible for populating the agent.id field value.

	/*
		event.category:

		This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy.
		type: keyword
		Important: The field value must be one of the following:
		authentication, database, driver, file, host, intrusion_detection, malware, package, process, web
	*/
	Category face.Field = "event.category"

	Code     face.Field = "event.code"     // Identification code for this event, if one exists. type: keyword
	Created  face.Field = "event.created"  // event.created contains the date/time when the event was first read by an agent, or by your pipeline. type: date
	Dataset  face.Field = "event.dataset"  // Name of the dataset. type: keyword
	Duration face.Field = "event.duration" // Duration of the event in nanoseconds. type: long
	End      face.Field = "event.end"      // event.end contains the date when the event ended or when the activity was last observed. type: date
	Hash     face.Field = "event.hash"     // Hash (perhaps logstash fingerprint) of raw field to be able to demonstrate log integrity. type: keyword
	ID       face.Field = "event.id"       // Unique ID to describe the event. type: keyword
	Ingested face.Field = "event.ingested" // Timestamp when an event arrived in the central data store. type: date
	/*
		event.kind:

		This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy.
		type: keyword
		Important: The field value must be one of the following:
		alert, event, metric, state, pipeline_error, signal
	*/
	Kind     face.Field = "event.kind"
	Module   face.Field = "event.module"   // Name of the module this data is coming from. type: keyword
	Original face.Field = "event.original" // Raw text message of entire event. Used to demonstrate log integrity. type: keyword
	/*
		event.outcome:
		This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy.
		type: keyword
		Important: The field value must be one of the following:
		failure, success, unknown
	*/
	Outcome       face.Field = "event.outcome"
	Provider      face.Field = "event.provider"        // Source of the event. type: keyword
	Reason        face.Field = "event.reason"          // Reason why this event happened, according to the source.. type: keyword
	Reference     face.Field = "event.reference"       // Reference URL linking to additional information about this event. type: keyword
	RiskScore     face.Field = "event.risk_score"      // Risk score or priority of the event (e.g. security solutions). Use your system’s original value here. type: float
	RiskScoreNorm face.Field = "event.risk_score_norm" // Normalized risk score or priority of the event, on a scale of 0 to 100. type: float
	Sequence      face.Field = "event.sequence"        // Sequence number of the event. type: long
	Severity      face.Field = "event.severity"        // The numeric severity of the event according to your event source. type: long
	Start         face.Field = "event.start"           // event.start contains the date when the event started or when the activity was first observed. type: date
	Timezone      face.Field = "event.timezone"        // This field should be populated when the event’s timestamp does not include timezone information already (e.g. default Syslog timestamps). It’s optional otherwise. type: keyword

	Url face.Field = "event.url" // URL linking to an external system to continue investigation of this event. type: keyword

	/*
		event.type:

		This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy.
		type: keyword
		Important: The field value must be one of the following:
			authentication, configuration, database, driver, file, host, iam,
			intrusion_detection, malware, network, package, process, web
	*/
	Type face.Field = "event.type"
)

// All package constants as list
var Fields = []face.Field{
	Action,
	AgentIdStatus,
	Code,
	Created,
	Dataset,
	Duration,
	Hash,
	End,
	ID,
	Ingested,
	Provider,
	RiskScore,
	RiskScoreNorm,
	Sequence,
	Severity,
	Start,
	Timezone,
	Module,
	Original,
	Reason,
	Reference,
	Url,
	Category,
	Type,
	Kind,
	Outcome,
}

// Types describes kibana types of fields
var Types = map[face.Field]face.Type{
	Action:        face.KeyWord,
	AgentIdStatus: face.KeyWord,
	Category:      face.KeyWord,
	Code:          face.KeyWord,
	Created:       face.Date,
	Dataset:       face.KeyWord,
	Duration:      face.Long,
	Hash:          face.KeyWord,
	End:           face.Date,
	ID:            face.KeyWord,
	Ingested:      face.Date,
	Kind:          face.KeyWord,
	Module:        face.KeyWord,
	Outcome:       face.KeyWord,
	Original:      face.KeyWord,
	Provider:      face.KeyWord,
	Reason:        face.KeyWord,
	Reference:     face.KeyWord,
	RiskScore:     face.Float,
	RiskScoreNorm: face.Float,
	Sequence:      face.Long,
	Severity:      face.Long,
	Start:         face.Date,
	Timezone:      face.KeyWord,
	Type:          face.KeyWord,
	Url:           face.KeyWord,
}
