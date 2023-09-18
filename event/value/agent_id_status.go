package value

/*
The allowed values are:

verified - The agent.id field value matches expected value obtained from auth metadata.

mismatch - The agent.id field value does not match the expected value obtained from auth metadata.

missing - There was no agent.id field in the event to validate.

auth_metadata_missing - There was no auth metadata or it was missing information about the agent ID.
*/

// Type Result is used for supporting event.outcome.* namespace
type AgentIdStatus string

// https://www.elastic.co/guide/en/ecs/current/ecs-event.html
const (
	Verified            AgentIdStatus = "verified"
	Mismatch            AgentIdStatus = "mismatch"
	Missing             AgentIdStatus = "missing"
	AuthMetadataMissing AgentIdStatus = "auth_metadata_missing"
)
