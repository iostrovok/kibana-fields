package face

// Type Field is used for supporting process.* namespace
type Field string

func (f Field) String() string {
	return string(f)
}

const (
	Environment Field = "environment"
)

// All package constants as list
var Fields = []Field{
	Environment,
}

// Type Result is used for supporting process.* namespace
type Result string

const (
	ResultOk      Result = "ok"
	ResultFailure Result = "failure"
	ResultSkipped Result = "skipped"
)

type Type string

const (
	Date          Type = "date"
	Flattened     Type = "flattened"
	Float         Type = "float"
	IP            Type = "ip"
	KeyWord       Type = "keyword"
	Long          Type = "long"
	MatchOnlyText Type = "match_only_text"
	MultiFields   Type = "multi-fields"
	Object        Type = "object"
	Wildcard      Type = "wildcard"
)

type Value any
