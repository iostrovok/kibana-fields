package entity

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	AttributesKnownRedirects                  fields.Field = "entity.attributes.known_redirects"                    // Known redirect URIs or URLs associated with this entity.
	AttributesManaged                         fields.Field = "entity.attributes.managed"                            // Indicates whether the entity is managed by an external system.
	AttributesMfaEnabled                      fields.Field = "entity.attributes.mfa_enabled"                        // Indicates whether multi-factor authentication is enabled for this entity.
	AttributesOauthConsentRestriction         fields.Field = "entity.attributes.oauth_consent_restriction"          // Restriction applied to OAuth consent for this entity.
	AttributesPermissions                     fields.Field = "entity.attributes.permissions"                        // Action-level permissions associated with this entity.
	AttributesStorageClass                    fields.Field = "entity.attributes.storage_class"                      // Storage tier or class assigned to an object storage resource.
	Behavior                                  fields.Field = "entity.behavior"                                      // A set of ephemeral characteristics of the entity, derived from observed behaviors during a specific time period.
	DisplayName                               fields.Field = "entity.display_name"                                  // An optional field used when a pretty name is desired for entity-centric operations.
	ID                                        fields.Field = "entity.id"                                            // Unique identifier for the entity.
	LastSeenTimestamp                         fields.Field = "entity.last_seen_timestamp"                           // Indicates the date/time when this entity was last "seen."
	LifecycleLastActivity                     fields.Field = "entity.lifecycle.last_activity"                       // Timestamp of the most recent action performed by or attributed to this entity.
	Metrics                                   fields.Field = "entity.metrics"                                       // Field set for any fields containing numeric entity metrics.
	Name                                      fields.Field = "entity.name"                                          // The name of the entity.
	Raw                                       fields.Field = "entity.raw"                                           // Original, unmodified fields from the source system.
	Reference                                 fields.Field = "entity.reference"                                     // A URI, URL, or other direct reference to access or locate the entity.
	RelationshipsAdministersHostID            fields.Field = "entity.relationships.administers.host.id"             // Referenced host ids.
	RelationshipsAdministersHostName          fields.Field = "entity.relationships.administers.host.name"           // Referenced host names.
	RelationshipsAdministersID                fields.Field = "entity.relationships.administers.entity.id"           // Identifiers of referenced entities.
	RelationshipsAdministersServiceID         fields.Field = "entity.relationships.administers.service.id"          // Referenced service ids.
	RelationshipsAdministersServiceName       fields.Field = "entity.relationships.administers.service.name"        // Referenced service names.
	RelationshipsAdministersUserDomain        fields.Field = "entity.relationships.administers.user.domain"         // Referenced user directory or AD/LDAP domain names.
	RelationshipsAdministersUserEmail         fields.Field = "entity.relationships.administers.user.email"          // Referenced user email addresses.
	RelationshipsAdministersUserID            fields.Field = "entity.relationships.administers.user.id"             // Referenced user ids.
	RelationshipsAdministersUserName          fields.Field = "entity.relationships.administers.user.name"           // Referenced user short names or logins.
	RelationshipsDependsOnHostID              fields.Field = "entity.relationships.depends_on.host.id"              // Referenced host ids.
	RelationshipsDependsOnHostName            fields.Field = "entity.relationships.depends_on.host.name"            // Referenced host names.
	RelationshipsDependsOnID                  fields.Field = "entity.relationships.depends_on.entity.id"            // Identifiers of referenced entities.
	RelationshipsDependsOnServiceID           fields.Field = "entity.relationships.depends_on.service.id"           // Referenced service ids.
	RelationshipsDependsOnServiceName         fields.Field = "entity.relationships.depends_on.service.name"         // Referenced service names.
	RelationshipsDependsOnUserDomain          fields.Field = "entity.relationships.depends_on.user.domain"          // Referenced user directory or AD/LDAP domain names.
	RelationshipsDependsOnUserEmail           fields.Field = "entity.relationships.depends_on.user.email"           // Referenced user email addresses.
	RelationshipsDependsOnUserID              fields.Field = "entity.relationships.depends_on.user.id"              // Referenced user ids.
	RelationshipsDependsOnUserName            fields.Field = "entity.relationships.depends_on.user.name"            // Referenced user short names or logins.
	RelationshipsOwnsHostID                   fields.Field = "entity.relationships.owns.host.id"                    // Referenced host ids.
	RelationshipsOwnsHostName                 fields.Field = "entity.relationships.owns.host.name"                  // Referenced host names.
	RelationshipsOwnsID                       fields.Field = "entity.relationships.owns.entity.id"                  // Identifiers of referenced entities.
	RelationshipsOwnsServiceID                fields.Field = "entity.relationships.owns.service.id"                 // Referenced service ids.
	RelationshipsOwnsServiceName              fields.Field = "entity.relationships.owns.service.name"               // Referenced service names.
	RelationshipsOwnsUserDomain               fields.Field = "entity.relationships.owns.user.domain"                // Referenced user directory or AD/LDAP domain names.
	RelationshipsOwnsUserEmail                fields.Field = "entity.relationships.owns.user.email"                 // Referenced user email addresses.
	RelationshipsOwnsUserID                   fields.Field = "entity.relationships.owns.user.id"                    // Referenced user ids.
	RelationshipsOwnsUserName                 fields.Field = "entity.relationships.owns.user.name"                  // Referenced user short names or logins.
	RelationshipsSupervisesHostID             fields.Field = "entity.relationships.supervises.host.id"              // Referenced host ids.
	RelationshipsSupervisesHostName           fields.Field = "entity.relationships.supervises.host.name"            // Referenced host names.
	RelationshipsSupervisesID                 fields.Field = "entity.relationships.supervises.entity.id"            // Identifiers of referenced entities.
	RelationshipsSupervisesServiceID          fields.Field = "entity.relationships.supervises.service.id"           // Referenced service ids.
	RelationshipsSupervisesServiceName        fields.Field = "entity.relationships.supervises.service.name"         // Referenced service names.
	RelationshipsSupervisesUserDomain         fields.Field = "entity.relationships.supervises.user.domain"          // Referenced user directory or AD/LDAP domain names.
	RelationshipsSupervisesUserEmail          fields.Field = "entity.relationships.supervises.user.email"           // Referenced user email addresses.
	RelationshipsSupervisesUserID             fields.Field = "entity.relationships.supervises.user.id"              // Referenced user ids.
	RelationshipsSupervisesUserName           fields.Field = "entity.relationships.supervises.user.name"            // Referenced user short names or logins.
	Source                                    fields.Field = "entity.source"                                        // Source module or integration that provided the entity data.
	SubType                                   fields.Field = "entity.sub_type"                                      // The specific type designation for the entity as defined by its provider or system.
	TargetAttributesKnownRedirects            fields.Field = "entity.target.attributes.known_redirects"             // Known redirect URIs or URLs associated with this entity.
	TargetAttributesManaged                   fields.Field = "entity.target.attributes.managed"                     // Indicates whether the entity is managed by an external system.
	TargetAttributesMfaEnabled                fields.Field = "entity.target.attributes.mfa_enabled"                 // Indicates whether multi-factor authentication is enabled for this entity.
	TargetAttributesOauthConsentRestriction   fields.Field = "entity.target.attributes.oauth_consent_restriction"   // Restriction applied to OAuth consent for this entity.
	TargetAttributesPermissions               fields.Field = "entity.target.attributes.permissions"                 // Action-level permissions associated with this entity.
	TargetAttributesStorageClass              fields.Field = "entity.target.attributes.storage_class"               // Storage tier or class assigned to an object storage resource.
	TargetBehavior                            fields.Field = "entity.target.behavior"                               // A set of ephemeral characteristics of the entity, derived from observed behaviors during a specific time period.
	TargetDisplayName                         fields.Field = "entity.target.display_name"                           // An optional field used when a pretty name is desired for entity-centric operations.
	TargetID                                  fields.Field = "entity.target.id"                                     // Unique identifier for the entity.
	TargetLastSeenTimestamp                   fields.Field = "entity.target.last_seen_timestamp"                    // Indicates the date/time when this entity was last "seen."
	TargetLifecycleLastActivity               fields.Field = "entity.target.lifecycle.last_activity"                // Timestamp of the most recent action performed by or attributed to this entity.
	TargetMetrics                             fields.Field = "entity.target.metrics"                                // Field set for any fields containing numeric entity metrics.
	TargetName                                fields.Field = "entity.target.name"                                   // The name of the entity.
	TargetRaw                                 fields.Field = "entity.target.raw"                                    // Original, unmodified fields from the source system.
	TargetReference                           fields.Field = "entity.target.reference"                              // A URI, URL, or other direct reference to access or locate the entity.
	TargetRelationshipsAdministersHostID      fields.Field = "entity.target.relationships.administers.host.id"      // Referenced host ids.
	TargetRelationshipsAdministersHostName    fields.Field = "entity.target.relationships.administers.host.name"    // Referenced host names.
	TargetRelationshipsAdministersID          fields.Field = "entity.target.relationships.administers.entity.id"    // Identifiers of referenced entities.
	TargetRelationshipsAdministersServiceID   fields.Field = "entity.target.relationships.administers.service.id"   // Referenced service ids.
	TargetRelationshipsAdministersServiceName fields.Field = "entity.target.relationships.administers.service.name" // Referenced service names.
	TargetRelationshipsAdministersUserDomain  fields.Field = "entity.target.relationships.administers.user.domain"  // Referenced user directory or AD/LDAP domain names.
	TargetRelationshipsAdministersUserEmail   fields.Field = "entity.target.relationships.administers.user.email"   // Referenced user email addresses.
	TargetRelationshipsAdministersUserID      fields.Field = "entity.target.relationships.administers.user.id"      // Referenced user ids.
	TargetRelationshipsAdministersUserName    fields.Field = "entity.target.relationships.administers.user.name"    // Referenced user short names or logins.
	TargetRelationshipsDependsOnHostID        fields.Field = "entity.target.relationships.depends_on.host.id"       // Referenced host ids.
	TargetRelationshipsDependsOnHostName      fields.Field = "entity.target.relationships.depends_on.host.name"     // Referenced host names.
	TargetRelationshipsDependsOnID            fields.Field = "entity.target.relationships.depends_on.entity.id"     // Identifiers of referenced entities.
	TargetRelationshipsDependsOnServiceID     fields.Field = "entity.target.relationships.depends_on.service.id"    // Referenced service ids.
	TargetRelationshipsDependsOnServiceName   fields.Field = "entity.target.relationships.depends_on.service.name"  // Referenced service names.
	TargetRelationshipsDependsOnUserDomain    fields.Field = "entity.target.relationships.depends_on.user.domain"   // Referenced user directory or AD/LDAP domain names.
	TargetRelationshipsDependsOnUserEmail     fields.Field = "entity.target.relationships.depends_on.user.email"    // Referenced user email addresses.
	TargetRelationshipsDependsOnUserID        fields.Field = "entity.target.relationships.depends_on.user.id"       // Referenced user ids.
	TargetRelationshipsDependsOnUserName      fields.Field = "entity.target.relationships.depends_on.user.name"     // Referenced user short names or logins.
	TargetRelationshipsOwnsHostID             fields.Field = "entity.target.relationships.owns.host.id"             // Referenced host ids.
	TargetRelationshipsOwnsHostName           fields.Field = "entity.target.relationships.owns.host.name"           // Referenced host names.
	TargetRelationshipsOwnsID                 fields.Field = "entity.target.relationships.owns.entity.id"           // Identifiers of referenced entities.
	TargetRelationshipsOwnsServiceID          fields.Field = "entity.target.relationships.owns.service.id"          // Referenced service ids.
	TargetRelationshipsOwnsServiceName        fields.Field = "entity.target.relationships.owns.service.name"        // Referenced service names.
	TargetRelationshipsOwnsUserDomain         fields.Field = "entity.target.relationships.owns.user.domain"         // Referenced user directory or AD/LDAP domain names.
	TargetRelationshipsOwnsUserEmail          fields.Field = "entity.target.relationships.owns.user.email"          // Referenced user email addresses.
	TargetRelationshipsOwnsUserID             fields.Field = "entity.target.relationships.owns.user.id"             // Referenced user ids.
	TargetRelationshipsOwnsUserName           fields.Field = "entity.target.relationships.owns.user.name"           // Referenced user short names or logins.
	TargetRelationshipsSupervisesHostID       fields.Field = "entity.target.relationships.supervises.host.id"       // Referenced host ids.
	TargetRelationshipsSupervisesHostName     fields.Field = "entity.target.relationships.supervises.host.name"     // Referenced host names.
	TargetRelationshipsSupervisesID           fields.Field = "entity.target.relationships.supervises.entity.id"     // Identifiers of referenced entities.
	TargetRelationshipsSupervisesServiceID    fields.Field = "entity.target.relationships.supervises.service.id"    // Referenced service ids.
	TargetRelationshipsSupervisesServiceName  fields.Field = "entity.target.relationships.supervises.service.name"  // Referenced service names.
	TargetRelationshipsSupervisesUserDomain   fields.Field = "entity.target.relationships.supervises.user.domain"   // Referenced user directory or AD/LDAP domain names.
	TargetRelationshipsSupervisesUserEmail    fields.Field = "entity.target.relationships.supervises.user.email"    // Referenced user email addresses.
	TargetRelationshipsSupervisesUserID       fields.Field = "entity.target.relationships.supervises.user.id"       // Referenced user ids.
	TargetRelationshipsSupervisesUserName     fields.Field = "entity.target.relationships.supervises.user.name"     // Referenced user short names or logins.
	TargetSource                              fields.Field = "entity.target.source"                                 // Source module or integration that provided the entity data.
	TargetSubType                             fields.Field = "entity.target.sub_type"                               // The specific type designation for the entity as defined by its provider or system.
	TargetType                                fields.Field = "entity.target.type"                                   // Standardized high-level classification of the entity.
	Type                                      fields.Field = "entity.type"                                          // Standardized high-level classification of the entity.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	AttributesKnownRedirects,
	AttributesManaged,
	AttributesMfaEnabled,
	AttributesOauthConsentRestriction,
	AttributesPermissions,
	AttributesStorageClass,
	Behavior,
	DisplayName,
	ID,
	LastSeenTimestamp,
	LifecycleLastActivity,
	Metrics,
	Name,
	Raw,
	Reference,
	RelationshipsAdministersHostID,
	RelationshipsAdministersHostName,
	RelationshipsAdministersID,
	RelationshipsAdministersServiceID,
	RelationshipsAdministersServiceName,
	RelationshipsAdministersUserDomain,
	RelationshipsAdministersUserEmail,
	RelationshipsAdministersUserID,
	RelationshipsAdministersUserName,
	RelationshipsDependsOnHostID,
	RelationshipsDependsOnHostName,
	RelationshipsDependsOnID,
	RelationshipsDependsOnServiceID,
	RelationshipsDependsOnServiceName,
	RelationshipsDependsOnUserDomain,
	RelationshipsDependsOnUserEmail,
	RelationshipsDependsOnUserID,
	RelationshipsDependsOnUserName,
	RelationshipsOwnsHostID,
	RelationshipsOwnsHostName,
	RelationshipsOwnsID,
	RelationshipsOwnsServiceID,
	RelationshipsOwnsServiceName,
	RelationshipsOwnsUserDomain,
	RelationshipsOwnsUserEmail,
	RelationshipsOwnsUserID,
	RelationshipsOwnsUserName,
	RelationshipsSupervisesHostID,
	RelationshipsSupervisesHostName,
	RelationshipsSupervisesID,
	RelationshipsSupervisesServiceID,
	RelationshipsSupervisesServiceName,
	RelationshipsSupervisesUserDomain,
	RelationshipsSupervisesUserEmail,
	RelationshipsSupervisesUserID,
	RelationshipsSupervisesUserName,
	Source,
	SubType,
	TargetAttributesKnownRedirects,
	TargetAttributesManaged,
	TargetAttributesMfaEnabled,
	TargetAttributesOauthConsentRestriction,
	TargetAttributesPermissions,
	TargetAttributesStorageClass,
	TargetBehavior,
	TargetDisplayName,
	TargetID,
	TargetLastSeenTimestamp,
	TargetLifecycleLastActivity,
	TargetMetrics,
	TargetName,
	TargetRaw,
	TargetReference,
	TargetRelationshipsAdministersHostID,
	TargetRelationshipsAdministersHostName,
	TargetRelationshipsAdministersID,
	TargetRelationshipsAdministersServiceID,
	TargetRelationshipsAdministersServiceName,
	TargetRelationshipsAdministersUserDomain,
	TargetRelationshipsAdministersUserEmail,
	TargetRelationshipsAdministersUserID,
	TargetRelationshipsAdministersUserName,
	TargetRelationshipsDependsOnHostID,
	TargetRelationshipsDependsOnHostName,
	TargetRelationshipsDependsOnID,
	TargetRelationshipsDependsOnServiceID,
	TargetRelationshipsDependsOnServiceName,
	TargetRelationshipsDependsOnUserDomain,
	TargetRelationshipsDependsOnUserEmail,
	TargetRelationshipsDependsOnUserID,
	TargetRelationshipsDependsOnUserName,
	TargetRelationshipsOwnsHostID,
	TargetRelationshipsOwnsHostName,
	TargetRelationshipsOwnsID,
	TargetRelationshipsOwnsServiceID,
	TargetRelationshipsOwnsServiceName,
	TargetRelationshipsOwnsUserDomain,
	TargetRelationshipsOwnsUserEmail,
	TargetRelationshipsOwnsUserID,
	TargetRelationshipsOwnsUserName,
	TargetRelationshipsSupervisesHostID,
	TargetRelationshipsSupervisesHostName,
	TargetRelationshipsSupervisesID,
	TargetRelationshipsSupervisesServiceID,
	TargetRelationshipsSupervisesServiceName,
	TargetRelationshipsSupervisesUserDomain,
	TargetRelationshipsSupervisesUserEmail,
	TargetRelationshipsSupervisesUserID,
	TargetRelationshipsSupervisesUserName,
	TargetSource,
	TargetSubType,
	TargetType,
	Type,
}

type TargetTypeAllowedType struct {
	Application  string // Represents a software application or service. This includes web applications, mobile applications, desktop applications, and other software components that provide functionality to users or other systems. Applications may run on various infrastructure components and can span multiple hosts or containers.
	Bucket       string // Represents a storage container or bucket, typically used for object storage. Common examples include AWS S3 buckets, Google Cloud Storage buckets, Azure Blob containers, and other cloud storage services. Buckets are used to organize and store files, objects, or data in cloud environments.
	Cloud        string // Represents a cloud or infrastructure. This includes cloud providers and their services (such as AWS EC2), and is used to identify or correlate resources, entities, and activities across accounts or multi-cloud environments.
	Container    string // Represents a containerized application or process. This includes Docker containers, Kubernetes pods, and other containerization technologies. Containers encapsulate applications and their dependencies, providing isolation and portability across different environments.
	Database     string // Represents a database system or database instance. This includes relational databases (MySQL, PostgreSQL, Oracle), NoSQL databases (MongoDB, Cassandra, DynamoDB), time-series databases, and other data storage systems. The entity may represent the entire database system or a specific database instance.
	Function     string // Represents a serverless function or Function-as-a-Service (FaaS) component. This includes AWS Lambda functions, Azure Functions, Google Cloud Functions, and other serverless computing resources. Functions are typically event-driven and execute code without managing the underlying infrastructure.
	Host         string // Represents a computing host or machine. This includes physical servers, virtual machines, cloud instances, and other computing resources that can run applications or services. Hosts provide the fundamental computing infrastructure for other entity types.
	Orchestrator string // Represents an orchestration system or orchestrator component. This includes container orchestrators like Kubernetes, Docker Swarm, and other systems responsible for automating the deployment, management, scaling, and networking of containers or workloads.
	Queue        string // Represents a message queue or messaging system. This includes message brokers, event queues, and other messaging infrastructure components such as Amazon SQS, RabbitMQ, Apache Kafka, and Azure Service Bus. Queues facilitate asynchronous communication between applications and services.
	Service      string // Represents a service or microservice component. This includes web services, APIs, background services, and other service-oriented architecture components. Services provide specific functionality and may communicate with other services to fulfill business requirements.
	Session      string // Represents a user session or connection session. This includes user login sessions, database connections, network sessions, and other temporary interactive or persistent connections between users, applications, or systems.
	User         string // Represents a user account or identity. This includes human users, service accounts, system accounts, and other identity entities that can interact with systems, applications, or services. Users may have various roles, permissions, and attributes associated with their identity.

}

var TargetTypeAllowedValues TargetTypeAllowedType = TargetTypeAllowedType{
	Application:  `application`,
	Bucket:       `bucket`,
	Cloud:        `cloud`,
	Container:    `container`,
	Database:     `database`,
	Function:     `function`,
	Host:         `host`,
	Orchestrator: `orchestrator`,
	Queue:        `queue`,
	Service:      `service`,
	Session:      `session`,
	User:         `user`,
}

type TypeAllowedType struct {
	Application  string // Represents a software application or service. This includes web applications, mobile applications, desktop applications, and other software components that provide functionality to users or other systems. Applications may run on various infrastructure components and can span multiple hosts or containers.
	Bucket       string // Represents a storage container or bucket, typically used for object storage. Common examples include AWS S3 buckets, Google Cloud Storage buckets, Azure Blob containers, and other cloud storage services. Buckets are used to organize and store files, objects, or data in cloud environments.
	Cloud        string // Represents a cloud or infrastructure. This includes cloud providers and their services (such as AWS EC2), and is used to identify or correlate resources, entities, and activities across accounts or multi-cloud environments.
	Container    string // Represents a containerized application or process. This includes Docker containers, Kubernetes pods, and other containerization technologies. Containers encapsulate applications and their dependencies, providing isolation and portability across different environments.
	Database     string // Represents a database system or database instance. This includes relational databases (MySQL, PostgreSQL, Oracle), NoSQL databases (MongoDB, Cassandra, DynamoDB), time-series databases, and other data storage systems. The entity may represent the entire database system or a specific database instance.
	Function     string // Represents a serverless function or Function-as-a-Service (FaaS) component. This includes AWS Lambda functions, Azure Functions, Google Cloud Functions, and other serverless computing resources. Functions are typically event-driven and execute code without managing the underlying infrastructure.
	Host         string // Represents a computing host or machine. This includes physical servers, virtual machines, cloud instances, and other computing resources that can run applications or services. Hosts provide the fundamental computing infrastructure for other entity types.
	Orchestrator string // Represents an orchestration system or orchestrator component. This includes container orchestrators like Kubernetes, Docker Swarm, and other systems responsible for automating the deployment, management, scaling, and networking of containers or workloads.
	Queue        string // Represents a message queue or messaging system. This includes message brokers, event queues, and other messaging infrastructure components such as Amazon SQS, RabbitMQ, Apache Kafka, and Azure Service Bus. Queues facilitate asynchronous communication between applications and services.
	Service      string // Represents a service or microservice component. This includes web services, APIs, background services, and other service-oriented architecture components. Services provide specific functionality and may communicate with other services to fulfill business requirements.
	Session      string // Represents a user session or connection session. This includes user login sessions, database connections, network sessions, and other temporary interactive or persistent connections between users, applications, or systems.
	User         string // Represents a user account or identity. This includes human users, service accounts, system accounts, and other identity entities that can interact with systems, applications, or services. Users may have various roles, permissions, and attributes associated with their identity.

}

var TypeAllowedValues TypeAllowedType = TypeAllowedType{
	Application:  `application`,
	Bucket:       `bucket`,
	Cloud:        `cloud`,
	Container:    `container`,
	Database:     `database`,
	Function:     `function`,
	Host:         `host`,
	Orchestrator: `orchestrator`,
	Queue:        `queue`,
	Service:      `service`,
	Session:      `session`,
	User:         `user`,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	AttributesKnownRedirects                  fields.Keyword
	AttributesManaged                         fields.Boolean
	AttributesMfaEnabled                      fields.Boolean
	AttributesOauthConsentRestriction         fields.Keyword
	AttributesPermissions                     fields.Keyword
	AttributesStorageClass                    fields.Keyword
	Behavior                                  fields.Object
	DisplayName                               fields.Keyword
	ID                                        fields.Keyword
	LastSeenTimestamp                         fields.Date
	LifecycleLastActivity                     fields.Date
	Metrics                                   fields.Object
	Name                                      fields.Keyword
	Raw                                       fields.Object
	Reference                                 fields.Keyword
	RelationshipsAdministersHostID            fields.Keyword
	RelationshipsAdministersHostName          fields.Keyword
	RelationshipsAdministersID                fields.Keyword
	RelationshipsAdministersServiceID         fields.Keyword
	RelationshipsAdministersServiceName       fields.Keyword
	RelationshipsAdministersUserDomain        fields.Keyword
	RelationshipsAdministersUserEmail         fields.Keyword
	RelationshipsAdministersUserID            fields.Keyword
	RelationshipsAdministersUserName          fields.Keyword
	RelationshipsDependsOnHostID              fields.Keyword
	RelationshipsDependsOnHostName            fields.Keyword
	RelationshipsDependsOnID                  fields.Keyword
	RelationshipsDependsOnServiceID           fields.Keyword
	RelationshipsDependsOnServiceName         fields.Keyword
	RelationshipsDependsOnUserDomain          fields.Keyword
	RelationshipsDependsOnUserEmail           fields.Keyword
	RelationshipsDependsOnUserID              fields.Keyword
	RelationshipsDependsOnUserName            fields.Keyword
	RelationshipsOwnsHostID                   fields.Keyword
	RelationshipsOwnsHostName                 fields.Keyword
	RelationshipsOwnsID                       fields.Keyword
	RelationshipsOwnsServiceID                fields.Keyword
	RelationshipsOwnsServiceName              fields.Keyword
	RelationshipsOwnsUserDomain               fields.Keyword
	RelationshipsOwnsUserEmail                fields.Keyword
	RelationshipsOwnsUserID                   fields.Keyword
	RelationshipsOwnsUserName                 fields.Keyword
	RelationshipsSupervisesHostID             fields.Keyword
	RelationshipsSupervisesHostName           fields.Keyword
	RelationshipsSupervisesID                 fields.Keyword
	RelationshipsSupervisesServiceID          fields.Keyword
	RelationshipsSupervisesServiceName        fields.Keyword
	RelationshipsSupervisesUserDomain         fields.Keyword
	RelationshipsSupervisesUserEmail          fields.Keyword
	RelationshipsSupervisesUserID             fields.Keyword
	RelationshipsSupervisesUserName           fields.Keyword
	Source                                    fields.Keyword
	SubType                                   fields.Keyword
	TargetAttributesKnownRedirects            fields.Keyword
	TargetAttributesManaged                   fields.Boolean
	TargetAttributesMfaEnabled                fields.Boolean
	TargetAttributesOauthConsentRestriction   fields.Keyword
	TargetAttributesPermissions               fields.Keyword
	TargetAttributesStorageClass              fields.Keyword
	TargetBehavior                            fields.Object
	TargetDisplayName                         fields.Keyword
	TargetID                                  fields.Keyword
	TargetLastSeenTimestamp                   fields.Date
	TargetLifecycleLastActivity               fields.Date
	TargetMetrics                             fields.Object
	TargetName                                fields.Keyword
	TargetRaw                                 fields.Object
	TargetReference                           fields.Keyword
	TargetRelationshipsAdministersHostID      fields.Keyword
	TargetRelationshipsAdministersHostName    fields.Keyword
	TargetRelationshipsAdministersID          fields.Keyword
	TargetRelationshipsAdministersServiceID   fields.Keyword
	TargetRelationshipsAdministersServiceName fields.Keyword
	TargetRelationshipsAdministersUserDomain  fields.Keyword
	TargetRelationshipsAdministersUserEmail   fields.Keyword
	TargetRelationshipsAdministersUserID      fields.Keyword
	TargetRelationshipsAdministersUserName    fields.Keyword
	TargetRelationshipsDependsOnHostID        fields.Keyword
	TargetRelationshipsDependsOnHostName      fields.Keyword
	TargetRelationshipsDependsOnID            fields.Keyword
	TargetRelationshipsDependsOnServiceID     fields.Keyword
	TargetRelationshipsDependsOnServiceName   fields.Keyword
	TargetRelationshipsDependsOnUserDomain    fields.Keyword
	TargetRelationshipsDependsOnUserEmail     fields.Keyword
	TargetRelationshipsDependsOnUserID        fields.Keyword
	TargetRelationshipsDependsOnUserName      fields.Keyword
	TargetRelationshipsOwnsHostID             fields.Keyword
	TargetRelationshipsOwnsHostName           fields.Keyword
	TargetRelationshipsOwnsID                 fields.Keyword
	TargetRelationshipsOwnsServiceID          fields.Keyword
	TargetRelationshipsOwnsServiceName        fields.Keyword
	TargetRelationshipsOwnsUserDomain         fields.Keyword
	TargetRelationshipsOwnsUserEmail          fields.Keyword
	TargetRelationshipsOwnsUserID             fields.Keyword
	TargetRelationshipsOwnsUserName           fields.Keyword
	TargetRelationshipsSupervisesHostID       fields.Keyword
	TargetRelationshipsSupervisesHostName     fields.Keyword
	TargetRelationshipsSupervisesID           fields.Keyword
	TargetRelationshipsSupervisesServiceID    fields.Keyword
	TargetRelationshipsSupervisesServiceName  fields.Keyword
	TargetRelationshipsSupervisesUserDomain   fields.Keyword
	TargetRelationshipsSupervisesUserEmail    fields.Keyword
	TargetRelationshipsSupervisesUserID       fields.Keyword
	TargetRelationshipsSupervisesUserName     fields.Keyword
	TargetSource                              fields.Keyword
	TargetSubType                             fields.Keyword
	TargetType                                fields.Keyword
	Type                                      fields.Keyword
}

var Types TypesType = TypesType{}
