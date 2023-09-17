package value

/*
Type Category is used for supporting event.category.* namespace
This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy.
event.type represents a categorization "sub-bucket" that, when used along with the event.category field values,
enables filtering events down to a level appropriate for single visualization.
This field is an array. This will allow proper categorization of some events that fall in multiple event types.
*/
type Type string

// All available values for event.type.*
const (
	Access       Type = "access"
	Admin        Type = "admin"
	Allowed      Type = "allowed"
	Change       Type = "change"
	Connection   Type = "connection"
	Creation     Type = "creation"
	Deletion     Type = "deletion"
	Denied       Type = "denied"
	End          Type = "end"
	Error        Type = "error"
	Group        Type = "group"
	Indicator    Type = "indicator"
	Info         Type = "info"
	Installation Type = "installation"
	Protocol     Type = "protocol"
	Start        Type = "start"
	User         Type = "user"
)
