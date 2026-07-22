package orchestrator

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	ApiVersion                                fields.Field = "orchestrator.api_version"                                   // API version being used to carry out the action
	ClusterID                                 fields.Field = "orchestrator.cluster.id"                                    // Unique ID of the cluster.
	ClusterName                               fields.Field = "orchestrator.cluster.name"                                  // Name of the cluster.
	ClusterUrl                                fields.Field = "orchestrator.cluster.url"                                   // URL of the API used to manage the cluster.
	ClusterVersion                            fields.Field = "orchestrator.cluster.version"                               // The version of the cluster.
	EntityAttributesKnownRedirects            fields.Field = "orchestrator.entity.attributes.known_redirects"             // Known redirect URIs or URLs associated with this entity.
	EntityAttributesManaged                   fields.Field = "orchestrator.entity.attributes.managed"                     // Indicates whether the entity is managed by an external system.
	EntityAttributesMfaEnabled                fields.Field = "orchestrator.entity.attributes.mfa_enabled"                 // Indicates whether multi-factor authentication is enabled for this entity.
	EntityAttributesOauthConsentRestriction   fields.Field = "orchestrator.entity.attributes.oauth_consent_restriction"   // Restriction applied to OAuth consent for this entity.
	EntityAttributesPermissions               fields.Field = "orchestrator.entity.attributes.permissions"                 // Action-level permissions associated with this entity.
	EntityAttributesStorageClass              fields.Field = "orchestrator.entity.attributes.storage_class"               // Storage tier or class assigned to an object storage resource.
	EntityBehavior                            fields.Field = "orchestrator.entity.behavior"                               // A set of ephemeral characteristics of the entity, derived from observed behaviors during a specific time period.
	EntityDisplayName                         fields.Field = "orchestrator.entity.display_name"                           // An optional field used when a pretty name is desired for entity-centric operations.
	EntityID                                  fields.Field = "orchestrator.entity.id"                                     // Unique identifier for the entity.
	EntityLastSeenTimestamp                   fields.Field = "orchestrator.entity.last_seen_timestamp"                    // Indicates the date/time when this entity was last "seen."
	EntityLifecycleLastActivity               fields.Field = "orchestrator.entity.lifecycle.last_activity"                // Timestamp of the most recent action performed by or attributed to this entity.
	EntityMetrics                             fields.Field = "orchestrator.entity.metrics"                                // Field set for any fields containing numeric entity metrics.
	EntityName                                fields.Field = "orchestrator.entity.name"                                   // The name of the entity.
	EntityRaw                                 fields.Field = "orchestrator.entity.raw"                                    // Original, unmodified fields from the source system.
	EntityReference                           fields.Field = "orchestrator.entity.reference"                              // A URI, URL, or other direct reference to access or locate the entity.
	EntityRelationshipsAdministersEntityID    fields.Field = "orchestrator.entity.relationships.administers.entity.id"    // Identifiers of referenced entities.
	EntityRelationshipsAdministersHostID      fields.Field = "orchestrator.entity.relationships.administers.host.id"      // Referenced host ids.
	EntityRelationshipsAdministersHostName    fields.Field = "orchestrator.entity.relationships.administers.host.name"    // Referenced host names.
	EntityRelationshipsAdministersServiceID   fields.Field = "orchestrator.entity.relationships.administers.service.id"   // Referenced service ids.
	EntityRelationshipsAdministersServiceName fields.Field = "orchestrator.entity.relationships.administers.service.name" // Referenced service names.
	EntityRelationshipsAdministersUserDomain  fields.Field = "orchestrator.entity.relationships.administers.user.domain"  // Referenced user directory or AD/LDAP domain names.
	EntityRelationshipsAdministersUserEmail   fields.Field = "orchestrator.entity.relationships.administers.user.email"   // Referenced user email addresses.
	EntityRelationshipsAdministersUserID      fields.Field = "orchestrator.entity.relationships.administers.user.id"      // Referenced user ids.
	EntityRelationshipsAdministersUserName    fields.Field = "orchestrator.entity.relationships.administers.user.name"    // Referenced user short names or logins.
	EntityRelationshipsDependsOnEntityID      fields.Field = "orchestrator.entity.relationships.depends_on.entity.id"     // Identifiers of referenced entities.
	EntityRelationshipsDependsOnHostID        fields.Field = "orchestrator.entity.relationships.depends_on.host.id"       // Referenced host ids.
	EntityRelationshipsDependsOnHostName      fields.Field = "orchestrator.entity.relationships.depends_on.host.name"     // Referenced host names.
	EntityRelationshipsDependsOnServiceID     fields.Field = "orchestrator.entity.relationships.depends_on.service.id"    // Referenced service ids.
	EntityRelationshipsDependsOnServiceName   fields.Field = "orchestrator.entity.relationships.depends_on.service.name"  // Referenced service names.
	EntityRelationshipsDependsOnUserDomain    fields.Field = "orchestrator.entity.relationships.depends_on.user.domain"   // Referenced user directory or AD/LDAP domain names.
	EntityRelationshipsDependsOnUserEmail     fields.Field = "orchestrator.entity.relationships.depends_on.user.email"    // Referenced user email addresses.
	EntityRelationshipsDependsOnUserID        fields.Field = "orchestrator.entity.relationships.depends_on.user.id"       // Referenced user ids.
	EntityRelationshipsDependsOnUserName      fields.Field = "orchestrator.entity.relationships.depends_on.user.name"     // Referenced user short names or logins.
	EntityRelationshipsOwnsEntityID           fields.Field = "orchestrator.entity.relationships.owns.entity.id"           // Identifiers of referenced entities.
	EntityRelationshipsOwnsHostID             fields.Field = "orchestrator.entity.relationships.owns.host.id"             // Referenced host ids.
	EntityRelationshipsOwnsHostName           fields.Field = "orchestrator.entity.relationships.owns.host.name"           // Referenced host names.
	EntityRelationshipsOwnsServiceID          fields.Field = "orchestrator.entity.relationships.owns.service.id"          // Referenced service ids.
	EntityRelationshipsOwnsServiceName        fields.Field = "orchestrator.entity.relationships.owns.service.name"        // Referenced service names.
	EntityRelationshipsOwnsUserDomain         fields.Field = "orchestrator.entity.relationships.owns.user.domain"         // Referenced user directory or AD/LDAP domain names.
	EntityRelationshipsOwnsUserEmail          fields.Field = "orchestrator.entity.relationships.owns.user.email"          // Referenced user email addresses.
	EntityRelationshipsOwnsUserID             fields.Field = "orchestrator.entity.relationships.owns.user.id"             // Referenced user ids.
	EntityRelationshipsOwnsUserName           fields.Field = "orchestrator.entity.relationships.owns.user.name"           // Referenced user short names or logins.
	EntityRelationshipsSupervisesEntityID     fields.Field = "orchestrator.entity.relationships.supervises.entity.id"     // Identifiers of referenced entities.
	EntityRelationshipsSupervisesHostID       fields.Field = "orchestrator.entity.relationships.supervises.host.id"       // Referenced host ids.
	EntityRelationshipsSupervisesHostName     fields.Field = "orchestrator.entity.relationships.supervises.host.name"     // Referenced host names.
	EntityRelationshipsSupervisesServiceID    fields.Field = "orchestrator.entity.relationships.supervises.service.id"    // Referenced service ids.
	EntityRelationshipsSupervisesServiceName  fields.Field = "orchestrator.entity.relationships.supervises.service.name"  // Referenced service names.
	EntityRelationshipsSupervisesUserDomain   fields.Field = "orchestrator.entity.relationships.supervises.user.domain"   // Referenced user directory or AD/LDAP domain names.
	EntityRelationshipsSupervisesUserEmail    fields.Field = "orchestrator.entity.relationships.supervises.user.email"    // Referenced user email addresses.
	EntityRelationshipsSupervisesUserID       fields.Field = "orchestrator.entity.relationships.supervises.user.id"       // Referenced user ids.
	EntityRelationshipsSupervisesUserName     fields.Field = "orchestrator.entity.relationships.supervises.user.name"     // Referenced user short names or logins.
	EntitySource                              fields.Field = "orchestrator.entity.source"                                 // Source module or integration that provided the entity data.
	EntitySubType                             fields.Field = "orchestrator.entity.sub_type"                               // The specific type designation for the entity as defined by its provider or system.
	EntityType                                fields.Field = "orchestrator.entity.type"                                   // Standardized high-level classification of the entity.
	Namespace                                 fields.Field = "orchestrator.namespace"                                     // Namespace in which the action is taking place.
	Organization                              fields.Field = "orchestrator.organization"                                  // Organization affected by the event (for multi-tenant orchestrator setups).
	ResourceAnnotation                        fields.Field = "orchestrator.resource.annotation"                           // The list of annotations added to the resource.
	ResourceID                                fields.Field = "orchestrator.resource.id"                                   // Unique ID of the resource being acted upon.
	ResourceIp                                fields.Field = "orchestrator.resource.ip"                                   // IP address assigned to the resource associated with the event being observed.
	ResourceLabel                             fields.Field = "orchestrator.resource.label"                                // The list of labels added to the resource.
	ResourceName                              fields.Field = "orchestrator.resource.name"                                 // Name of the resource being acted upon.
	ResourceParentType                        fields.Field = "orchestrator.resource.parent.type"                          // Type or kind of the parent resource associated with the event being observed.
	ResourceType                              fields.Field = "orchestrator.resource.type"                                 // Type of resource being acted upon.
	Type                                      fields.Field = "orchestrator.type"                                          // Orchestrator cluster type (e.g. kubernetes, nomad or cloudfoundry).

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	ApiVersion,
	ClusterID,
	ClusterName,
	ClusterUrl,
	ClusterVersion,
	EntityAttributesKnownRedirects,
	EntityAttributesManaged,
	EntityAttributesMfaEnabled,
	EntityAttributesOauthConsentRestriction,
	EntityAttributesPermissions,
	EntityAttributesStorageClass,
	EntityBehavior,
	EntityDisplayName,
	EntityID,
	EntityLastSeenTimestamp,
	EntityLifecycleLastActivity,
	EntityMetrics,
	EntityName,
	EntityRaw,
	EntityReference,
	EntityRelationshipsAdministersEntityID,
	EntityRelationshipsAdministersHostID,
	EntityRelationshipsAdministersHostName,
	EntityRelationshipsAdministersServiceID,
	EntityRelationshipsAdministersServiceName,
	EntityRelationshipsAdministersUserDomain,
	EntityRelationshipsAdministersUserEmail,
	EntityRelationshipsAdministersUserID,
	EntityRelationshipsAdministersUserName,
	EntityRelationshipsDependsOnEntityID,
	EntityRelationshipsDependsOnHostID,
	EntityRelationshipsDependsOnHostName,
	EntityRelationshipsDependsOnServiceID,
	EntityRelationshipsDependsOnServiceName,
	EntityRelationshipsDependsOnUserDomain,
	EntityRelationshipsDependsOnUserEmail,
	EntityRelationshipsDependsOnUserID,
	EntityRelationshipsDependsOnUserName,
	EntityRelationshipsOwnsEntityID,
	EntityRelationshipsOwnsHostID,
	EntityRelationshipsOwnsHostName,
	EntityRelationshipsOwnsServiceID,
	EntityRelationshipsOwnsServiceName,
	EntityRelationshipsOwnsUserDomain,
	EntityRelationshipsOwnsUserEmail,
	EntityRelationshipsOwnsUserID,
	EntityRelationshipsOwnsUserName,
	EntityRelationshipsSupervisesEntityID,
	EntityRelationshipsSupervisesHostID,
	EntityRelationshipsSupervisesHostName,
	EntityRelationshipsSupervisesServiceID,
	EntityRelationshipsSupervisesServiceName,
	EntityRelationshipsSupervisesUserDomain,
	EntityRelationshipsSupervisesUserEmail,
	EntityRelationshipsSupervisesUserID,
	EntityRelationshipsSupervisesUserName,
	EntitySource,
	EntitySubType,
	EntityType,
	Namespace,
	Organization,
	ResourceAnnotation,
	ResourceID,
	ResourceIp,
	ResourceLabel,
	ResourceName,
	ResourceParentType,
	ResourceType,
	Type,
}

type EntityTypeAllowedType struct {
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

var EntityTypeAllowedValues EntityTypeAllowedType = EntityTypeAllowedType{
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
	ApiVersion                                fields.Keyword
	ClusterID                                 fields.Keyword
	ClusterName                               fields.Keyword
	ClusterUrl                                fields.Keyword
	ClusterVersion                            fields.Keyword
	EntityAttributesKnownRedirects            fields.Keyword
	EntityAttributesManaged                   fields.Boolean
	EntityAttributesMfaEnabled                fields.Boolean
	EntityAttributesOauthConsentRestriction   fields.Keyword
	EntityAttributesPermissions               fields.Keyword
	EntityAttributesStorageClass              fields.Keyword
	EntityBehavior                            fields.Object
	EntityDisplayName                         fields.Keyword
	EntityID                                  fields.Keyword
	EntityLastSeenTimestamp                   fields.Date
	EntityLifecycleLastActivity               fields.Date
	EntityMetrics                             fields.Object
	EntityName                                fields.Keyword
	EntityRaw                                 fields.Object
	EntityReference                           fields.Keyword
	EntityRelationshipsAdministersEntityID    fields.Keyword
	EntityRelationshipsAdministersHostID      fields.Keyword
	EntityRelationshipsAdministersHostName    fields.Keyword
	EntityRelationshipsAdministersServiceID   fields.Keyword
	EntityRelationshipsAdministersServiceName fields.Keyword
	EntityRelationshipsAdministersUserDomain  fields.Keyword
	EntityRelationshipsAdministersUserEmail   fields.Keyword
	EntityRelationshipsAdministersUserID      fields.Keyword
	EntityRelationshipsAdministersUserName    fields.Keyword
	EntityRelationshipsDependsOnEntityID      fields.Keyword
	EntityRelationshipsDependsOnHostID        fields.Keyword
	EntityRelationshipsDependsOnHostName      fields.Keyword
	EntityRelationshipsDependsOnServiceID     fields.Keyword
	EntityRelationshipsDependsOnServiceName   fields.Keyword
	EntityRelationshipsDependsOnUserDomain    fields.Keyword
	EntityRelationshipsDependsOnUserEmail     fields.Keyword
	EntityRelationshipsDependsOnUserID        fields.Keyword
	EntityRelationshipsDependsOnUserName      fields.Keyword
	EntityRelationshipsOwnsEntityID           fields.Keyword
	EntityRelationshipsOwnsHostID             fields.Keyword
	EntityRelationshipsOwnsHostName           fields.Keyword
	EntityRelationshipsOwnsServiceID          fields.Keyword
	EntityRelationshipsOwnsServiceName        fields.Keyword
	EntityRelationshipsOwnsUserDomain         fields.Keyword
	EntityRelationshipsOwnsUserEmail          fields.Keyword
	EntityRelationshipsOwnsUserID             fields.Keyword
	EntityRelationshipsOwnsUserName           fields.Keyword
	EntityRelationshipsSupervisesEntityID     fields.Keyword
	EntityRelationshipsSupervisesHostID       fields.Keyword
	EntityRelationshipsSupervisesHostName     fields.Keyword
	EntityRelationshipsSupervisesServiceID    fields.Keyword
	EntityRelationshipsSupervisesServiceName  fields.Keyword
	EntityRelationshipsSupervisesUserDomain   fields.Keyword
	EntityRelationshipsSupervisesUserEmail    fields.Keyword
	EntityRelationshipsSupervisesUserID       fields.Keyword
	EntityRelationshipsSupervisesUserName     fields.Keyword
	EntitySource                              fields.Keyword
	EntitySubType                             fields.Keyword
	EntityType                                fields.Keyword
	Namespace                                 fields.Keyword
	Organization                              fields.Keyword
	ResourceAnnotation                        fields.Keyword
	ResourceID                                fields.Keyword
	ResourceIp                                fields.IP
	ResourceLabel                             fields.Keyword
	ResourceName                              fields.Keyword
	ResourceParentType                        fields.Keyword
	ResourceType                              fields.Keyword
	Type                                      fields.Keyword
}

var Types TypesType = TypesType{}
