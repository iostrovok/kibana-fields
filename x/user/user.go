package user

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	ChangesDomain           fields.Field = "user.changes.domain"             // Name of the directory the user is a member of.
	ChangesEmail            fields.Field = "user.changes.email"              // User email address.
	ChangesFullName         fields.Field = "user.changes.full_name"          // User's full name, if available.
	ChangesGroupDomain      fields.Field = "user.changes.group.domain"       // Name of the directory the group is a member of.
	ChangesGroupID          fields.Field = "user.changes.group.id"           // Unique identifier for the group on the system/platform.
	ChangesGroupName        fields.Field = "user.changes.group.name"         // Name of the group.
	ChangesHash             fields.Field = "user.changes.hash"               // Unique user hash to correlate information for a user in anonymized form.
	ChangesID               fields.Field = "user.changes.id"                 // Unique identifier of the user.
	ChangesName             fields.Field = "user.changes.name"               // Short name or login of the user.
	ChangesRoles            fields.Field = "user.changes.roles"              // Array of user roles at the time of the event.
	Domain                  fields.Field = "user.domain"                     // Name of the directory the user is a member of.
	EffectiveDomain         fields.Field = "user.effective.domain"           // Name of the directory the user is a member of.
	EffectiveEmail          fields.Field = "user.effective.email"            // User email address.
	EffectiveFullName       fields.Field = "user.effective.full_name"        // User's full name, if available.
	EffectiveGroupDomain    fields.Field = "user.effective.group.domain"     // Name of the directory the group is a member of.
	EffectiveGroupID        fields.Field = "user.effective.group.id"         // Unique identifier for the group on the system/platform.
	EffectiveGroupName      fields.Field = "user.effective.group.name"       // Name of the group.
	EffectiveHash           fields.Field = "user.effective.hash"             // Unique user hash to correlate information for a user in anonymized form.
	EffectiveID             fields.Field = "user.effective.id"               // Unique identifier of the user.
	EffectiveName           fields.Field = "user.effective.name"             // Short name or login of the user.
	EffectiveRoles          fields.Field = "user.effective.roles"            // Array of user roles at the time of the event.
	Email                   fields.Field = "user.email"                      // User email address.
	FullName                fields.Field = "user.full_name"                  // User's full name, if available.
	GroupDomain             fields.Field = "user.group.domain"               // Name of the directory the group is a member of.
	GroupID                 fields.Field = "user.group.id"                   // Unique identifier for the group on the system/platform.
	GroupName               fields.Field = "user.group.name"                 // Name of the group.
	Hash                    fields.Field = "user.hash"                       // Unique user hash to correlate information for a user in anonymized form.
	ID                      fields.Field = "user.id"                         // Unique identifier of the user.
	Name                    fields.Field = "user.name"                       // Short name or login of the user.
	RiskCalculatedLevel     fields.Field = "user.risk.calculated_level"      // A risk classification level calculated by an internal system as part of entity analytics and entity risk scoring.
	RiskCalculatedScore     fields.Field = "user.risk.calculated_score"      // A risk classification score calculated by an internal system as part of entity analytics and entity risk scoring.
	RiskCalculatedScoreNorm fields.Field = "user.risk.calculated_score_norm" // A normalized risk score calculated by an internal system.
	RiskStaticLevel         fields.Field = "user.risk.static_level"          // A risk classification level obtained from outside the system, such as from some external Threat Intelligence Platform.
	RiskStaticScore         fields.Field = "user.risk.static_score"          // A risk classification score obtained from outside the system, such as from some external Threat Intelligence Platform.
	RiskStaticScoreNorm     fields.Field = "user.risk.static_score_norm"     // A normalized risk score calculated by an external system.
	Roles                   fields.Field = "user.roles"                      // Array of user roles at the time of the event.
	TargetDomain            fields.Field = "user.target.domain"              // Name of the directory the user is a member of.
	TargetEmail             fields.Field = "user.target.email"               // User email address.
	TargetFullName          fields.Field = "user.target.full_name"           // User's full name, if available.
	TargetGroupDomain       fields.Field = "user.target.group.domain"        // Name of the directory the group is a member of.
	TargetGroupID           fields.Field = "user.target.group.id"            // Unique identifier for the group on the system/platform.
	TargetGroupName         fields.Field = "user.target.group.name"          // Name of the group.
	TargetHash              fields.Field = "user.target.hash"                // Unique user hash to correlate information for a user in anonymized form.
	TargetID                fields.Field = "user.target.id"                  // Unique identifier of the user.
	TargetName              fields.Field = "user.target.name"                // Short name or login of the user.
	TargetRoles             fields.Field = "user.target.roles"               // Array of user roles at the time of the event.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	ChangesDomain,
	ChangesEmail,
	ChangesFullName,
	ChangesGroupDomain,
	ChangesGroupID,
	ChangesGroupName,
	ChangesHash,
	ChangesID,
	ChangesName,
	ChangesRoles,
	Domain,
	EffectiveDomain,
	EffectiveEmail,
	EffectiveFullName,
	EffectiveGroupDomain,
	EffectiveGroupID,
	EffectiveGroupName,
	EffectiveHash,
	EffectiveID,
	EffectiveName,
	EffectiveRoles,
	Email,
	FullName,
	GroupDomain,
	GroupID,
	GroupName,
	Hash,
	ID,
	Name,
	RiskCalculatedLevel,
	RiskCalculatedScore,
	RiskCalculatedScoreNorm,
	RiskStaticLevel,
	RiskStaticScore,
	RiskStaticScoreNorm,
	Roles,
	TargetDomain,
	TargetEmail,
	TargetFullName,
	TargetGroupDomain,
	TargetGroupID,
	TargetGroupName,
	TargetHash,
	TargetID,
	TargetName,
	TargetRoles,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	ChangesDomain           fields.KeyWord
	ChangesEmail            fields.KeyWord
	ChangesFullName         fields.KeyWord
	ChangesGroupDomain      fields.KeyWord
	ChangesGroupID          fields.KeyWord
	ChangesGroupName        fields.KeyWord
	ChangesHash             fields.KeyWord
	ChangesID               fields.KeyWord
	ChangesName             fields.KeyWord
	ChangesRoles            fields.KeyWord
	Domain                  fields.KeyWord
	EffectiveDomain         fields.KeyWord
	EffectiveEmail          fields.KeyWord
	EffectiveFullName       fields.KeyWord
	EffectiveGroupDomain    fields.KeyWord
	EffectiveGroupID        fields.KeyWord
	EffectiveGroupName      fields.KeyWord
	EffectiveHash           fields.KeyWord
	EffectiveID             fields.KeyWord
	EffectiveName           fields.KeyWord
	EffectiveRoles          fields.KeyWord
	Email                   fields.KeyWord
	FullName                fields.KeyWord
	GroupDomain             fields.KeyWord
	GroupID                 fields.KeyWord
	GroupName               fields.KeyWord
	Hash                    fields.KeyWord
	ID                      fields.KeyWord
	Name                    fields.KeyWord
	RiskCalculatedLevel     fields.KeyWord
	RiskCalculatedScore     fields.Float
	RiskCalculatedScoreNorm fields.Float
	RiskStaticLevel         fields.KeyWord
	RiskStaticScore         fields.Float
	RiskStaticScoreNorm     fields.Float
	Roles                   fields.KeyWord
	TargetDomain            fields.KeyWord
	TargetEmail             fields.KeyWord
	TargetFullName          fields.KeyWord
	TargetGroupDomain       fields.KeyWord
	TargetGroupID           fields.KeyWord
	TargetGroupName         fields.KeyWord
	TargetHash              fields.KeyWord
	TargetID                fields.KeyWord
	TargetName              fields.KeyWord
	TargetRoles             fields.KeyWord
}

var Types TypesType = TypesType{}
