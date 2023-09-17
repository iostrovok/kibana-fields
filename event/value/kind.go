package value

/*
Type Kind is used for supporting event.kind.* namespace
This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy.
event.kind gives high-level information about what type of information the event contains, without being
specific to the contents of the event. For example, values of this field distinguish alert events from metric events.
The value of this field can be used to inform how these kinds of events should be handled. They may warrant
different retention, different access control, it may also help understand whether
the data coming in at a regular interval or not.
*/
type Kind string

// All available values for event.kind.*
// https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-kind.html
const (
	Alert         Kind = "alert"
	Asset         Kind = "asset"
	Enrichment    Kind = "enrichment"
	Event         Kind = "event"
	Metric        Kind = "metric"
	State         Kind = "state"
	PipelineError Kind = "pipeline_error"
	Signal        Kind = "signal"
)
