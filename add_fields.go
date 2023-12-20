package fields

// Additional fields for APM support

const (
	Environment Field = "environment"
)

// Result for APM transaction
type Result string

const (
	ResultOk      Result = "ok"
	ResultFailure Result = "failure"
	ResultSkipped Result = "skipped"
)
