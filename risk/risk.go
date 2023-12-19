package risk

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	CalculatedLevel     fields.Field = "risk.calculated_level"      // A risk classification level calculated by an internal system as part of entity analytics and entity risk scoring.
	CalculatedScore     fields.Field = "risk.calculated_score"      // A risk classification score calculated by an internal system as part of entity analytics and entity risk scoring.
	CalculatedScoreNorm fields.Field = "risk.calculated_score_norm" // A normalized risk score calculated by an internal system.
	StaticLevel         fields.Field = "risk.static_level"          // A risk classification level obtained from outside the system, such as from some external Threat Intelligence Platform.
	StaticScore         fields.Field = "risk.static_score"          // A risk classification score obtained from outside the system, such as from some external Threat Intelligence Platform.
	StaticScoreNorm     fields.Field = "risk.static_score_norm"     // A normalized risk score calculated by an external system.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	CalculatedLevel,
	CalculatedScore,
	CalculatedScoreNorm,
	StaticLevel,
	StaticScore,
	StaticScoreNorm,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	CalculatedLevel     fields.KeyWord
	CalculatedScore     fields.Float
	CalculatedScoreNorm fields.Float
	StaticLevel         fields.KeyWord
	StaticScore         fields.Float
	StaticScoreNorm     fields.Float
}

var Types TypesType = TypesType{}
