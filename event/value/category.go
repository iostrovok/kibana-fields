package value

/*
Type Category is used for supporting event.category.* namespace
This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy.
event.category represents the "big buckets" of ECS categories. For example, filtering on event.category:process
yields all events relating to process activity. This field is closely related to event.type,
which is used as a subcategory.
This field is an array. This will allow proper categorization of some events that fall in multiple categories.
*/
type Category string

// All available values for event.category.*
const (
	Api                Category = "api"
	Authentication     Category = "authentication"
	Configuration      Category = "configuration"
	Database           Category = "database"
	Driver             Category = "driver"
	Email              Category = "email"
	File               Category = "file"
	Host               Category = "host"
	Iam                Category = "iam"
	IntrusionDetection Category = "intrusion_detection"
	Library            Category = "library"
	Malware            Category = "malware"
	Network            Category = "network"
	Package            Category = "package"
	Process            Category = "process"
	Registry           Category = "registry"
	Session            Category = "session"
	Threat             Category = "threat"
	Vulnerability      Category = "vulnerability"
	Web                Category = "web"
)
