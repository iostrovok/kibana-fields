package value

/*
This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy.

event.outcome simply denotes whether the event represents a success or a failure from
the perspective of the entity that produced the event.

Note that when a single transaction is described in multiple events, each event may populate different
values of event.outcome, according to their perspective.

Also note that in the case of a compound event (a single event that contains multiple logical events),
this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer.

Further note that not all events will have an associated outcome. For example, this field is generally
not populated for metric events, events with event.type:info, or any events for which an outcome does not make logical sense.
*/

// Type Result is used for supporting event.outcome.* namespace
type Outcome string

// All available values for event.outcome.*
// https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-outcome.html
const (
	Failure Outcome = "failure"
	Success Outcome = "success"
	Unknown Outcome = "unknown"
)
