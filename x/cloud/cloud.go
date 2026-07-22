package cloud

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	AccountID                                       fields.Field = "cloud.account.id"                                           // The cloud account or organization id.
	AccountName                                     fields.Field = "cloud.account.name"                                         // The cloud account name.
	AvailabilityZone                                fields.Field = "cloud.availability_zone"                                    // Availability zone in which this host, resource, or service is located.
	EntityAttributesKnownRedirects                  fields.Field = "cloud.entity.attributes.known_redirects"                    // Known redirect URIs or URLs associated with this entity.
	EntityAttributesManaged                         fields.Field = "cloud.entity.attributes.managed"                            // Indicates whether the entity is managed by an external system.
	EntityAttributesMfaEnabled                      fields.Field = "cloud.entity.attributes.mfa_enabled"                        // Indicates whether multi-factor authentication is enabled for this entity.
	EntityAttributesOauthConsentRestriction         fields.Field = "cloud.entity.attributes.oauth_consent_restriction"          // Restriction applied to OAuth consent for this entity.
	EntityAttributesPermissions                     fields.Field = "cloud.entity.attributes.permissions"                        // Action-level permissions associated with this entity.
	EntityAttributesStorageClass                    fields.Field = "cloud.entity.attributes.storage_class"                      // Storage tier or class assigned to an object storage resource.
	EntityBehavior                                  fields.Field = "cloud.entity.behavior"                                      // A set of ephemeral characteristics of the entity, derived from observed behaviors during a specific time period.
	EntityDisplayName                               fields.Field = "cloud.entity.display_name"                                  // An optional field used when a pretty name is desired for entity-centric operations.
	EntityID                                        fields.Field = "cloud.entity.id"                                            // Unique identifier for the entity.
	EntityLastSeenTimestamp                         fields.Field = "cloud.entity.last_seen_timestamp"                           // Indicates the date/time when this entity was last "seen."
	EntityLifecycleLastActivity                     fields.Field = "cloud.entity.lifecycle.last_activity"                       // Timestamp of the most recent action performed by or attributed to this entity.
	EntityMetrics                                   fields.Field = "cloud.entity.metrics"                                       // Field set for any fields containing numeric entity metrics.
	EntityName                                      fields.Field = "cloud.entity.name"                                          // The name of the entity.
	EntityRaw                                       fields.Field = "cloud.entity.raw"                                           // Original, unmodified fields from the source system.
	EntityReference                                 fields.Field = "cloud.entity.reference"                                     // A URI, URL, or other direct reference to access or locate the entity.
	EntityRelationshipsAdministersEntityID          fields.Field = "cloud.entity.relationships.administers.entity.id"           // Identifiers of referenced entities.
	EntityRelationshipsAdministersHostID            fields.Field = "cloud.entity.relationships.administers.host.id"             // Referenced host ids.
	EntityRelationshipsAdministersHostName          fields.Field = "cloud.entity.relationships.administers.host.name"           // Referenced host names.
	EntityRelationshipsAdministersServiceID         fields.Field = "cloud.entity.relationships.administers.service.id"          // Referenced service ids.
	EntityRelationshipsAdministersServiceName       fields.Field = "cloud.entity.relationships.administers.service.name"        // Referenced service names.
	EntityRelationshipsAdministersUserDomain        fields.Field = "cloud.entity.relationships.administers.user.domain"         // Referenced user directory or AD/LDAP domain names.
	EntityRelationshipsAdministersUserEmail         fields.Field = "cloud.entity.relationships.administers.user.email"          // Referenced user email addresses.
	EntityRelationshipsAdministersUserID            fields.Field = "cloud.entity.relationships.administers.user.id"             // Referenced user ids.
	EntityRelationshipsAdministersUserName          fields.Field = "cloud.entity.relationships.administers.user.name"           // Referenced user short names or logins.
	EntityRelationshipsDependsOnEntityID            fields.Field = "cloud.entity.relationships.depends_on.entity.id"            // Identifiers of referenced entities.
	EntityRelationshipsDependsOnHostID              fields.Field = "cloud.entity.relationships.depends_on.host.id"              // Referenced host ids.
	EntityRelationshipsDependsOnHostName            fields.Field = "cloud.entity.relationships.depends_on.host.name"            // Referenced host names.
	EntityRelationshipsDependsOnServiceID           fields.Field = "cloud.entity.relationships.depends_on.service.id"           // Referenced service ids.
	EntityRelationshipsDependsOnServiceName         fields.Field = "cloud.entity.relationships.depends_on.service.name"         // Referenced service names.
	EntityRelationshipsDependsOnUserDomain          fields.Field = "cloud.entity.relationships.depends_on.user.domain"          // Referenced user directory or AD/LDAP domain names.
	EntityRelationshipsDependsOnUserEmail           fields.Field = "cloud.entity.relationships.depends_on.user.email"           // Referenced user email addresses.
	EntityRelationshipsDependsOnUserID              fields.Field = "cloud.entity.relationships.depends_on.user.id"              // Referenced user ids.
	EntityRelationshipsDependsOnUserName            fields.Field = "cloud.entity.relationships.depends_on.user.name"            // Referenced user short names or logins.
	EntityRelationshipsOwnsEntityID                 fields.Field = "cloud.entity.relationships.owns.entity.id"                  // Identifiers of referenced entities.
	EntityRelationshipsOwnsHostID                   fields.Field = "cloud.entity.relationships.owns.host.id"                    // Referenced host ids.
	EntityRelationshipsOwnsHostName                 fields.Field = "cloud.entity.relationships.owns.host.name"                  // Referenced host names.
	EntityRelationshipsOwnsServiceID                fields.Field = "cloud.entity.relationships.owns.service.id"                 // Referenced service ids.
	EntityRelationshipsOwnsServiceName              fields.Field = "cloud.entity.relationships.owns.service.name"               // Referenced service names.
	EntityRelationshipsOwnsUserDomain               fields.Field = "cloud.entity.relationships.owns.user.domain"                // Referenced user directory or AD/LDAP domain names.
	EntityRelationshipsOwnsUserEmail                fields.Field = "cloud.entity.relationships.owns.user.email"                 // Referenced user email addresses.
	EntityRelationshipsOwnsUserID                   fields.Field = "cloud.entity.relationships.owns.user.id"                    // Referenced user ids.
	EntityRelationshipsOwnsUserName                 fields.Field = "cloud.entity.relationships.owns.user.name"                  // Referenced user short names or logins.
	EntityRelationshipsSupervisesEntityID           fields.Field = "cloud.entity.relationships.supervises.entity.id"            // Identifiers of referenced entities.
	EntityRelationshipsSupervisesHostID             fields.Field = "cloud.entity.relationships.supervises.host.id"              // Referenced host ids.
	EntityRelationshipsSupervisesHostName           fields.Field = "cloud.entity.relationships.supervises.host.name"            // Referenced host names.
	EntityRelationshipsSupervisesServiceID          fields.Field = "cloud.entity.relationships.supervises.service.id"           // Referenced service ids.
	EntityRelationshipsSupervisesServiceName        fields.Field = "cloud.entity.relationships.supervises.service.name"         // Referenced service names.
	EntityRelationshipsSupervisesUserDomain         fields.Field = "cloud.entity.relationships.supervises.user.domain"          // Referenced user directory or AD/LDAP domain names.
	EntityRelationshipsSupervisesUserEmail          fields.Field = "cloud.entity.relationships.supervises.user.email"           // Referenced user email addresses.
	EntityRelationshipsSupervisesUserID             fields.Field = "cloud.entity.relationships.supervises.user.id"              // Referenced user ids.
	EntityRelationshipsSupervisesUserName           fields.Field = "cloud.entity.relationships.supervises.user.name"            // Referenced user short names or logins.
	EntitySource                                    fields.Field = "cloud.entity.source"                                        // Source module or integration that provided the entity data.
	EntitySubType                                   fields.Field = "cloud.entity.sub_type"                                      // The specific type designation for the entity as defined by its provider or system.
	EntityType                                      fields.Field = "cloud.entity.type"                                          // Standardized high-level classification of the entity.
	InstanceID                                      fields.Field = "cloud.instance.id"                                          // Instance ID of the host machine.
	InstanceName                                    fields.Field = "cloud.instance.name"                                        // Instance name of the host machine.
	MachineType                                     fields.Field = "cloud.machine.type"                                         // Machine type of the host machine.
	OriginAccountID                                 fields.Field = "cloud.origin.account.id"                                    // The cloud account or organization id.
	OriginAccountName                               fields.Field = "cloud.origin.account.name"                                  // The cloud account name.
	OriginAvailabilityZone                          fields.Field = "cloud.origin.availability_zone"                             // Availability zone in which this host, resource, or service is located.
	OriginEntityAttributesKnownRedirects            fields.Field = "cloud.origin.entity.attributes.known_redirects"             // Known redirect URIs or URLs associated with this entity.
	OriginEntityAttributesManaged                   fields.Field = "cloud.origin.entity.attributes.managed"                     // Indicates whether the entity is managed by an external system.
	OriginEntityAttributesMfaEnabled                fields.Field = "cloud.origin.entity.attributes.mfa_enabled"                 // Indicates whether multi-factor authentication is enabled for this entity.
	OriginEntityAttributesOauthConsentRestriction   fields.Field = "cloud.origin.entity.attributes.oauth_consent_restriction"   // Restriction applied to OAuth consent for this entity.
	OriginEntityAttributesPermissions               fields.Field = "cloud.origin.entity.attributes.permissions"                 // Action-level permissions associated with this entity.
	OriginEntityAttributesStorageClass              fields.Field = "cloud.origin.entity.attributes.storage_class"               // Storage tier or class assigned to an object storage resource.
	OriginEntityBehavior                            fields.Field = "cloud.origin.entity.behavior"                               // A set of ephemeral characteristics of the entity, derived from observed behaviors during a specific time period.
	OriginEntityDisplayName                         fields.Field = "cloud.origin.entity.display_name"                           // An optional field used when a pretty name is desired for entity-centric operations.
	OriginEntityID                                  fields.Field = "cloud.origin.entity.id"                                     // Unique identifier for the entity.
	OriginEntityLastSeenTimestamp                   fields.Field = "cloud.origin.entity.last_seen_timestamp"                    // Indicates the date/time when this entity was last "seen."
	OriginEntityLifecycleLastActivity               fields.Field = "cloud.origin.entity.lifecycle.last_activity"                // Timestamp of the most recent action performed by or attributed to this entity.
	OriginEntityMetrics                             fields.Field = "cloud.origin.entity.metrics"                                // Field set for any fields containing numeric entity metrics.
	OriginEntityName                                fields.Field = "cloud.origin.entity.name"                                   // The name of the entity.
	OriginEntityRaw                                 fields.Field = "cloud.origin.entity.raw"                                    // Original, unmodified fields from the source system.
	OriginEntityReference                           fields.Field = "cloud.origin.entity.reference"                              // A URI, URL, or other direct reference to access or locate the entity.
	OriginEntityRelationshipsAdministersEntityID    fields.Field = "cloud.origin.entity.relationships.administers.entity.id"    // Identifiers of referenced entities.
	OriginEntityRelationshipsAdministersHostID      fields.Field = "cloud.origin.entity.relationships.administers.host.id"      // Referenced host ids.
	OriginEntityRelationshipsAdministersHostName    fields.Field = "cloud.origin.entity.relationships.administers.host.name"    // Referenced host names.
	OriginEntityRelationshipsAdministersServiceID   fields.Field = "cloud.origin.entity.relationships.administers.service.id"   // Referenced service ids.
	OriginEntityRelationshipsAdministersServiceName fields.Field = "cloud.origin.entity.relationships.administers.service.name" // Referenced service names.
	OriginEntityRelationshipsAdministersUserDomain  fields.Field = "cloud.origin.entity.relationships.administers.user.domain"  // Referenced user directory or AD/LDAP domain names.
	OriginEntityRelationshipsAdministersUserEmail   fields.Field = "cloud.origin.entity.relationships.administers.user.email"   // Referenced user email addresses.
	OriginEntityRelationshipsAdministersUserID      fields.Field = "cloud.origin.entity.relationships.administers.user.id"      // Referenced user ids.
	OriginEntityRelationshipsAdministersUserName    fields.Field = "cloud.origin.entity.relationships.administers.user.name"    // Referenced user short names or logins.
	OriginEntityRelationshipsDependsOnEntityID      fields.Field = "cloud.origin.entity.relationships.depends_on.entity.id"     // Identifiers of referenced entities.
	OriginEntityRelationshipsDependsOnHostID        fields.Field = "cloud.origin.entity.relationships.depends_on.host.id"       // Referenced host ids.
	OriginEntityRelationshipsDependsOnHostName      fields.Field = "cloud.origin.entity.relationships.depends_on.host.name"     // Referenced host names.
	OriginEntityRelationshipsDependsOnServiceID     fields.Field = "cloud.origin.entity.relationships.depends_on.service.id"    // Referenced service ids.
	OriginEntityRelationshipsDependsOnServiceName   fields.Field = "cloud.origin.entity.relationships.depends_on.service.name"  // Referenced service names.
	OriginEntityRelationshipsDependsOnUserDomain    fields.Field = "cloud.origin.entity.relationships.depends_on.user.domain"   // Referenced user directory or AD/LDAP domain names.
	OriginEntityRelationshipsDependsOnUserEmail     fields.Field = "cloud.origin.entity.relationships.depends_on.user.email"    // Referenced user email addresses.
	OriginEntityRelationshipsDependsOnUserID        fields.Field = "cloud.origin.entity.relationships.depends_on.user.id"       // Referenced user ids.
	OriginEntityRelationshipsDependsOnUserName      fields.Field = "cloud.origin.entity.relationships.depends_on.user.name"     // Referenced user short names or logins.
	OriginEntityRelationshipsOwnsEntityID           fields.Field = "cloud.origin.entity.relationships.owns.entity.id"           // Identifiers of referenced entities.
	OriginEntityRelationshipsOwnsHostID             fields.Field = "cloud.origin.entity.relationships.owns.host.id"             // Referenced host ids.
	OriginEntityRelationshipsOwnsHostName           fields.Field = "cloud.origin.entity.relationships.owns.host.name"           // Referenced host names.
	OriginEntityRelationshipsOwnsServiceID          fields.Field = "cloud.origin.entity.relationships.owns.service.id"          // Referenced service ids.
	OriginEntityRelationshipsOwnsServiceName        fields.Field = "cloud.origin.entity.relationships.owns.service.name"        // Referenced service names.
	OriginEntityRelationshipsOwnsUserDomain         fields.Field = "cloud.origin.entity.relationships.owns.user.domain"         // Referenced user directory or AD/LDAP domain names.
	OriginEntityRelationshipsOwnsUserEmail          fields.Field = "cloud.origin.entity.relationships.owns.user.email"          // Referenced user email addresses.
	OriginEntityRelationshipsOwnsUserID             fields.Field = "cloud.origin.entity.relationships.owns.user.id"             // Referenced user ids.
	OriginEntityRelationshipsOwnsUserName           fields.Field = "cloud.origin.entity.relationships.owns.user.name"           // Referenced user short names or logins.
	OriginEntityRelationshipsSupervisesEntityID     fields.Field = "cloud.origin.entity.relationships.supervises.entity.id"     // Identifiers of referenced entities.
	OriginEntityRelationshipsSupervisesHostID       fields.Field = "cloud.origin.entity.relationships.supervises.host.id"       // Referenced host ids.
	OriginEntityRelationshipsSupervisesHostName     fields.Field = "cloud.origin.entity.relationships.supervises.host.name"     // Referenced host names.
	OriginEntityRelationshipsSupervisesServiceID    fields.Field = "cloud.origin.entity.relationships.supervises.service.id"    // Referenced service ids.
	OriginEntityRelationshipsSupervisesServiceName  fields.Field = "cloud.origin.entity.relationships.supervises.service.name"  // Referenced service names.
	OriginEntityRelationshipsSupervisesUserDomain   fields.Field = "cloud.origin.entity.relationships.supervises.user.domain"   // Referenced user directory or AD/LDAP domain names.
	OriginEntityRelationshipsSupervisesUserEmail    fields.Field = "cloud.origin.entity.relationships.supervises.user.email"    // Referenced user email addresses.
	OriginEntityRelationshipsSupervisesUserID       fields.Field = "cloud.origin.entity.relationships.supervises.user.id"       // Referenced user ids.
	OriginEntityRelationshipsSupervisesUserName     fields.Field = "cloud.origin.entity.relationships.supervises.user.name"     // Referenced user short names or logins.
	OriginEntitySource                              fields.Field = "cloud.origin.entity.source"                                 // Source module or integration that provided the entity data.
	OriginEntitySubType                             fields.Field = "cloud.origin.entity.sub_type"                               // The specific type designation for the entity as defined by its provider or system.
	OriginEntityType                                fields.Field = "cloud.origin.entity.type"                                   // Standardized high-level classification of the entity.
	OriginInstanceID                                fields.Field = "cloud.origin.instance.id"                                   // Instance ID of the host machine.
	OriginInstanceName                              fields.Field = "cloud.origin.instance.name"                                 // Instance name of the host machine.
	OriginMachineType                               fields.Field = "cloud.origin.machine.type"                                  // Machine type of the host machine.
	OriginProjectID                                 fields.Field = "cloud.origin.project.id"                                    // The cloud project id.
	OriginProjectName                               fields.Field = "cloud.origin.project.name"                                  // The cloud project name.
	OriginProvider                                  fields.Field = "cloud.origin.provider"                                      // Name of the cloud provider.
	OriginRegion                                    fields.Field = "cloud.origin.region"                                        // Region in which this host, resource, or service is located.
	OriginServiceName                               fields.Field = "cloud.origin.service.name"                                  // The cloud service name.
	ProjectID                                       fields.Field = "cloud.project.id"                                           // The cloud project id.
	ProjectName                                     fields.Field = "cloud.project.name"                                         // The cloud project name.
	Provider                                        fields.Field = "cloud.provider"                                             // Name of the cloud provider.
	Region                                          fields.Field = "cloud.region"                                               // Region in which this host, resource, or service is located.
	ServiceName                                     fields.Field = "cloud.service.name"                                         // The cloud service name.
	TargetAccountID                                 fields.Field = "cloud.target.account.id"                                    // The cloud account or organization id.
	TargetAccountName                               fields.Field = "cloud.target.account.name"                                  // The cloud account name.
	TargetAvailabilityZone                          fields.Field = "cloud.target.availability_zone"                             // Availability zone in which this host, resource, or service is located.
	TargetEntityAttributesKnownRedirects            fields.Field = "cloud.target.entity.attributes.known_redirects"             // Known redirect URIs or URLs associated with this entity.
	TargetEntityAttributesManaged                   fields.Field = "cloud.target.entity.attributes.managed"                     // Indicates whether the entity is managed by an external system.
	TargetEntityAttributesMfaEnabled                fields.Field = "cloud.target.entity.attributes.mfa_enabled"                 // Indicates whether multi-factor authentication is enabled for this entity.
	TargetEntityAttributesOauthConsentRestriction   fields.Field = "cloud.target.entity.attributes.oauth_consent_restriction"   // Restriction applied to OAuth consent for this entity.
	TargetEntityAttributesPermissions               fields.Field = "cloud.target.entity.attributes.permissions"                 // Action-level permissions associated with this entity.
	TargetEntityAttributesStorageClass              fields.Field = "cloud.target.entity.attributes.storage_class"               // Storage tier or class assigned to an object storage resource.
	TargetEntityBehavior                            fields.Field = "cloud.target.entity.behavior"                               // A set of ephemeral characteristics of the entity, derived from observed behaviors during a specific time period.
	TargetEntityDisplayName                         fields.Field = "cloud.target.entity.display_name"                           // An optional field used when a pretty name is desired for entity-centric operations.
	TargetEntityID                                  fields.Field = "cloud.target.entity.id"                                     // Unique identifier for the entity.
	TargetEntityLastSeenTimestamp                   fields.Field = "cloud.target.entity.last_seen_timestamp"                    // Indicates the date/time when this entity was last "seen."
	TargetEntityLifecycleLastActivity               fields.Field = "cloud.target.entity.lifecycle.last_activity"                // Timestamp of the most recent action performed by or attributed to this entity.
	TargetEntityMetrics                             fields.Field = "cloud.target.entity.metrics"                                // Field set for any fields containing numeric entity metrics.
	TargetEntityName                                fields.Field = "cloud.target.entity.name"                                   // The name of the entity.
	TargetEntityRaw                                 fields.Field = "cloud.target.entity.raw"                                    // Original, unmodified fields from the source system.
	TargetEntityReference                           fields.Field = "cloud.target.entity.reference"                              // A URI, URL, or other direct reference to access or locate the entity.
	TargetEntityRelationshipsAdministersEntityID    fields.Field = "cloud.target.entity.relationships.administers.entity.id"    // Identifiers of referenced entities.
	TargetEntityRelationshipsAdministersHostID      fields.Field = "cloud.target.entity.relationships.administers.host.id"      // Referenced host ids.
	TargetEntityRelationshipsAdministersHostName    fields.Field = "cloud.target.entity.relationships.administers.host.name"    // Referenced host names.
	TargetEntityRelationshipsAdministersServiceID   fields.Field = "cloud.target.entity.relationships.administers.service.id"   // Referenced service ids.
	TargetEntityRelationshipsAdministersServiceName fields.Field = "cloud.target.entity.relationships.administers.service.name" // Referenced service names.
	TargetEntityRelationshipsAdministersUserDomain  fields.Field = "cloud.target.entity.relationships.administers.user.domain"  // Referenced user directory or AD/LDAP domain names.
	TargetEntityRelationshipsAdministersUserEmail   fields.Field = "cloud.target.entity.relationships.administers.user.email"   // Referenced user email addresses.
	TargetEntityRelationshipsAdministersUserID      fields.Field = "cloud.target.entity.relationships.administers.user.id"      // Referenced user ids.
	TargetEntityRelationshipsAdministersUserName    fields.Field = "cloud.target.entity.relationships.administers.user.name"    // Referenced user short names or logins.
	TargetEntityRelationshipsDependsOnEntityID      fields.Field = "cloud.target.entity.relationships.depends_on.entity.id"     // Identifiers of referenced entities.
	TargetEntityRelationshipsDependsOnHostID        fields.Field = "cloud.target.entity.relationships.depends_on.host.id"       // Referenced host ids.
	TargetEntityRelationshipsDependsOnHostName      fields.Field = "cloud.target.entity.relationships.depends_on.host.name"     // Referenced host names.
	TargetEntityRelationshipsDependsOnServiceID     fields.Field = "cloud.target.entity.relationships.depends_on.service.id"    // Referenced service ids.
	TargetEntityRelationshipsDependsOnServiceName   fields.Field = "cloud.target.entity.relationships.depends_on.service.name"  // Referenced service names.
	TargetEntityRelationshipsDependsOnUserDomain    fields.Field = "cloud.target.entity.relationships.depends_on.user.domain"   // Referenced user directory or AD/LDAP domain names.
	TargetEntityRelationshipsDependsOnUserEmail     fields.Field = "cloud.target.entity.relationships.depends_on.user.email"    // Referenced user email addresses.
	TargetEntityRelationshipsDependsOnUserID        fields.Field = "cloud.target.entity.relationships.depends_on.user.id"       // Referenced user ids.
	TargetEntityRelationshipsDependsOnUserName      fields.Field = "cloud.target.entity.relationships.depends_on.user.name"     // Referenced user short names or logins.
	TargetEntityRelationshipsOwnsEntityID           fields.Field = "cloud.target.entity.relationships.owns.entity.id"           // Identifiers of referenced entities.
	TargetEntityRelationshipsOwnsHostID             fields.Field = "cloud.target.entity.relationships.owns.host.id"             // Referenced host ids.
	TargetEntityRelationshipsOwnsHostName           fields.Field = "cloud.target.entity.relationships.owns.host.name"           // Referenced host names.
	TargetEntityRelationshipsOwnsServiceID          fields.Field = "cloud.target.entity.relationships.owns.service.id"          // Referenced service ids.
	TargetEntityRelationshipsOwnsServiceName        fields.Field = "cloud.target.entity.relationships.owns.service.name"        // Referenced service names.
	TargetEntityRelationshipsOwnsUserDomain         fields.Field = "cloud.target.entity.relationships.owns.user.domain"         // Referenced user directory or AD/LDAP domain names.
	TargetEntityRelationshipsOwnsUserEmail          fields.Field = "cloud.target.entity.relationships.owns.user.email"          // Referenced user email addresses.
	TargetEntityRelationshipsOwnsUserID             fields.Field = "cloud.target.entity.relationships.owns.user.id"             // Referenced user ids.
	TargetEntityRelationshipsOwnsUserName           fields.Field = "cloud.target.entity.relationships.owns.user.name"           // Referenced user short names or logins.
	TargetEntityRelationshipsSupervisesEntityID     fields.Field = "cloud.target.entity.relationships.supervises.entity.id"     // Identifiers of referenced entities.
	TargetEntityRelationshipsSupervisesHostID       fields.Field = "cloud.target.entity.relationships.supervises.host.id"       // Referenced host ids.
	TargetEntityRelationshipsSupervisesHostName     fields.Field = "cloud.target.entity.relationships.supervises.host.name"     // Referenced host names.
	TargetEntityRelationshipsSupervisesServiceID    fields.Field = "cloud.target.entity.relationships.supervises.service.id"    // Referenced service ids.
	TargetEntityRelationshipsSupervisesServiceName  fields.Field = "cloud.target.entity.relationships.supervises.service.name"  // Referenced service names.
	TargetEntityRelationshipsSupervisesUserDomain   fields.Field = "cloud.target.entity.relationships.supervises.user.domain"   // Referenced user directory or AD/LDAP domain names.
	TargetEntityRelationshipsSupervisesUserEmail    fields.Field = "cloud.target.entity.relationships.supervises.user.email"    // Referenced user email addresses.
	TargetEntityRelationshipsSupervisesUserID       fields.Field = "cloud.target.entity.relationships.supervises.user.id"       // Referenced user ids.
	TargetEntityRelationshipsSupervisesUserName     fields.Field = "cloud.target.entity.relationships.supervises.user.name"     // Referenced user short names or logins.
	TargetEntitySource                              fields.Field = "cloud.target.entity.source"                                 // Source module or integration that provided the entity data.
	TargetEntitySubType                             fields.Field = "cloud.target.entity.sub_type"                               // The specific type designation for the entity as defined by its provider or system.
	TargetEntityType                                fields.Field = "cloud.target.entity.type"                                   // Standardized high-level classification of the entity.
	TargetInstanceID                                fields.Field = "cloud.target.instance.id"                                   // Instance ID of the host machine.
	TargetInstanceName                              fields.Field = "cloud.target.instance.name"                                 // Instance name of the host machine.
	TargetMachineType                               fields.Field = "cloud.target.machine.type"                                  // Machine type of the host machine.
	TargetProjectID                                 fields.Field = "cloud.target.project.id"                                    // The cloud project id.
	TargetProjectName                               fields.Field = "cloud.target.project.name"                                  // The cloud project name.
	TargetProvider                                  fields.Field = "cloud.target.provider"                                      // Name of the cloud provider.
	TargetRegion                                    fields.Field = "cloud.target.region"                                        // Region in which this host, resource, or service is located.
	TargetServiceName                               fields.Field = "cloud.target.service.name"                                  // The cloud service name.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	AccountID,
	AccountName,
	AvailabilityZone,
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
	InstanceID,
	InstanceName,
	MachineType,
	OriginAccountID,
	OriginAccountName,
	OriginAvailabilityZone,
	OriginEntityAttributesKnownRedirects,
	OriginEntityAttributesManaged,
	OriginEntityAttributesMfaEnabled,
	OriginEntityAttributesOauthConsentRestriction,
	OriginEntityAttributesPermissions,
	OriginEntityAttributesStorageClass,
	OriginEntityBehavior,
	OriginEntityDisplayName,
	OriginEntityID,
	OriginEntityLastSeenTimestamp,
	OriginEntityLifecycleLastActivity,
	OriginEntityMetrics,
	OriginEntityName,
	OriginEntityRaw,
	OriginEntityReference,
	OriginEntityRelationshipsAdministersEntityID,
	OriginEntityRelationshipsAdministersHostID,
	OriginEntityRelationshipsAdministersHostName,
	OriginEntityRelationshipsAdministersServiceID,
	OriginEntityRelationshipsAdministersServiceName,
	OriginEntityRelationshipsAdministersUserDomain,
	OriginEntityRelationshipsAdministersUserEmail,
	OriginEntityRelationshipsAdministersUserID,
	OriginEntityRelationshipsAdministersUserName,
	OriginEntityRelationshipsDependsOnEntityID,
	OriginEntityRelationshipsDependsOnHostID,
	OriginEntityRelationshipsDependsOnHostName,
	OriginEntityRelationshipsDependsOnServiceID,
	OriginEntityRelationshipsDependsOnServiceName,
	OriginEntityRelationshipsDependsOnUserDomain,
	OriginEntityRelationshipsDependsOnUserEmail,
	OriginEntityRelationshipsDependsOnUserID,
	OriginEntityRelationshipsDependsOnUserName,
	OriginEntityRelationshipsOwnsEntityID,
	OriginEntityRelationshipsOwnsHostID,
	OriginEntityRelationshipsOwnsHostName,
	OriginEntityRelationshipsOwnsServiceID,
	OriginEntityRelationshipsOwnsServiceName,
	OriginEntityRelationshipsOwnsUserDomain,
	OriginEntityRelationshipsOwnsUserEmail,
	OriginEntityRelationshipsOwnsUserID,
	OriginEntityRelationshipsOwnsUserName,
	OriginEntityRelationshipsSupervisesEntityID,
	OriginEntityRelationshipsSupervisesHostID,
	OriginEntityRelationshipsSupervisesHostName,
	OriginEntityRelationshipsSupervisesServiceID,
	OriginEntityRelationshipsSupervisesServiceName,
	OriginEntityRelationshipsSupervisesUserDomain,
	OriginEntityRelationshipsSupervisesUserEmail,
	OriginEntityRelationshipsSupervisesUserID,
	OriginEntityRelationshipsSupervisesUserName,
	OriginEntitySource,
	OriginEntitySubType,
	OriginEntityType,
	OriginInstanceID,
	OriginInstanceName,
	OriginMachineType,
	OriginProjectID,
	OriginProjectName,
	OriginProvider,
	OriginRegion,
	OriginServiceName,
	ProjectID,
	ProjectName,
	Provider,
	Region,
	ServiceName,
	TargetAccountID,
	TargetAccountName,
	TargetAvailabilityZone,
	TargetEntityAttributesKnownRedirects,
	TargetEntityAttributesManaged,
	TargetEntityAttributesMfaEnabled,
	TargetEntityAttributesOauthConsentRestriction,
	TargetEntityAttributesPermissions,
	TargetEntityAttributesStorageClass,
	TargetEntityBehavior,
	TargetEntityDisplayName,
	TargetEntityID,
	TargetEntityLastSeenTimestamp,
	TargetEntityLifecycleLastActivity,
	TargetEntityMetrics,
	TargetEntityName,
	TargetEntityRaw,
	TargetEntityReference,
	TargetEntityRelationshipsAdministersEntityID,
	TargetEntityRelationshipsAdministersHostID,
	TargetEntityRelationshipsAdministersHostName,
	TargetEntityRelationshipsAdministersServiceID,
	TargetEntityRelationshipsAdministersServiceName,
	TargetEntityRelationshipsAdministersUserDomain,
	TargetEntityRelationshipsAdministersUserEmail,
	TargetEntityRelationshipsAdministersUserID,
	TargetEntityRelationshipsAdministersUserName,
	TargetEntityRelationshipsDependsOnEntityID,
	TargetEntityRelationshipsDependsOnHostID,
	TargetEntityRelationshipsDependsOnHostName,
	TargetEntityRelationshipsDependsOnServiceID,
	TargetEntityRelationshipsDependsOnServiceName,
	TargetEntityRelationshipsDependsOnUserDomain,
	TargetEntityRelationshipsDependsOnUserEmail,
	TargetEntityRelationshipsDependsOnUserID,
	TargetEntityRelationshipsDependsOnUserName,
	TargetEntityRelationshipsOwnsEntityID,
	TargetEntityRelationshipsOwnsHostID,
	TargetEntityRelationshipsOwnsHostName,
	TargetEntityRelationshipsOwnsServiceID,
	TargetEntityRelationshipsOwnsServiceName,
	TargetEntityRelationshipsOwnsUserDomain,
	TargetEntityRelationshipsOwnsUserEmail,
	TargetEntityRelationshipsOwnsUserID,
	TargetEntityRelationshipsOwnsUserName,
	TargetEntityRelationshipsSupervisesEntityID,
	TargetEntityRelationshipsSupervisesHostID,
	TargetEntityRelationshipsSupervisesHostName,
	TargetEntityRelationshipsSupervisesServiceID,
	TargetEntityRelationshipsSupervisesServiceName,
	TargetEntityRelationshipsSupervisesUserDomain,
	TargetEntityRelationshipsSupervisesUserEmail,
	TargetEntityRelationshipsSupervisesUserID,
	TargetEntityRelationshipsSupervisesUserName,
	TargetEntitySource,
	TargetEntitySubType,
	TargetEntityType,
	TargetInstanceID,
	TargetInstanceName,
	TargetMachineType,
	TargetProjectID,
	TargetProjectName,
	TargetProvider,
	TargetRegion,
	TargetServiceName,
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

type OriginEntityTypeAllowedType struct {
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

var OriginEntityTypeAllowedValues OriginEntityTypeAllowedType = OriginEntityTypeAllowedType{
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

type TargetEntityTypeAllowedType struct {
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

var TargetEntityTypeAllowedValues TargetEntityTypeAllowedType = TargetEntityTypeAllowedType{
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
	AccountID                                       fields.Keyword
	AccountName                                     fields.Keyword
	AvailabilityZone                                fields.Keyword
	EntityAttributesKnownRedirects                  fields.Keyword
	EntityAttributesManaged                         fields.Boolean
	EntityAttributesMfaEnabled                      fields.Boolean
	EntityAttributesOauthConsentRestriction         fields.Keyword
	EntityAttributesPermissions                     fields.Keyword
	EntityAttributesStorageClass                    fields.Keyword
	EntityBehavior                                  fields.Object
	EntityDisplayName                               fields.Keyword
	EntityID                                        fields.Keyword
	EntityLastSeenTimestamp                         fields.Date
	EntityLifecycleLastActivity                     fields.Date
	EntityMetrics                                   fields.Object
	EntityName                                      fields.Keyword
	EntityRaw                                       fields.Object
	EntityReference                                 fields.Keyword
	EntityRelationshipsAdministersEntityID          fields.Keyword
	EntityRelationshipsAdministersHostID            fields.Keyword
	EntityRelationshipsAdministersHostName          fields.Keyword
	EntityRelationshipsAdministersServiceID         fields.Keyword
	EntityRelationshipsAdministersServiceName       fields.Keyword
	EntityRelationshipsAdministersUserDomain        fields.Keyword
	EntityRelationshipsAdministersUserEmail         fields.Keyword
	EntityRelationshipsAdministersUserID            fields.Keyword
	EntityRelationshipsAdministersUserName          fields.Keyword
	EntityRelationshipsDependsOnEntityID            fields.Keyword
	EntityRelationshipsDependsOnHostID              fields.Keyword
	EntityRelationshipsDependsOnHostName            fields.Keyword
	EntityRelationshipsDependsOnServiceID           fields.Keyword
	EntityRelationshipsDependsOnServiceName         fields.Keyword
	EntityRelationshipsDependsOnUserDomain          fields.Keyword
	EntityRelationshipsDependsOnUserEmail           fields.Keyword
	EntityRelationshipsDependsOnUserID              fields.Keyword
	EntityRelationshipsDependsOnUserName            fields.Keyword
	EntityRelationshipsOwnsEntityID                 fields.Keyword
	EntityRelationshipsOwnsHostID                   fields.Keyword
	EntityRelationshipsOwnsHostName                 fields.Keyword
	EntityRelationshipsOwnsServiceID                fields.Keyword
	EntityRelationshipsOwnsServiceName              fields.Keyword
	EntityRelationshipsOwnsUserDomain               fields.Keyword
	EntityRelationshipsOwnsUserEmail                fields.Keyword
	EntityRelationshipsOwnsUserID                   fields.Keyword
	EntityRelationshipsOwnsUserName                 fields.Keyword
	EntityRelationshipsSupervisesEntityID           fields.Keyword
	EntityRelationshipsSupervisesHostID             fields.Keyword
	EntityRelationshipsSupervisesHostName           fields.Keyword
	EntityRelationshipsSupervisesServiceID          fields.Keyword
	EntityRelationshipsSupervisesServiceName        fields.Keyword
	EntityRelationshipsSupervisesUserDomain         fields.Keyword
	EntityRelationshipsSupervisesUserEmail          fields.Keyword
	EntityRelationshipsSupervisesUserID             fields.Keyword
	EntityRelationshipsSupervisesUserName           fields.Keyword
	EntitySource                                    fields.Keyword
	EntitySubType                                   fields.Keyword
	EntityType                                      fields.Keyword
	InstanceID                                      fields.Keyword
	InstanceName                                    fields.Keyword
	MachineType                                     fields.Keyword
	OriginAccountID                                 fields.Keyword
	OriginAccountName                               fields.Keyword
	OriginAvailabilityZone                          fields.Keyword
	OriginEntityAttributesKnownRedirects            fields.Keyword
	OriginEntityAttributesManaged                   fields.Boolean
	OriginEntityAttributesMfaEnabled                fields.Boolean
	OriginEntityAttributesOauthConsentRestriction   fields.Keyword
	OriginEntityAttributesPermissions               fields.Keyword
	OriginEntityAttributesStorageClass              fields.Keyword
	OriginEntityBehavior                            fields.Object
	OriginEntityDisplayName                         fields.Keyword
	OriginEntityID                                  fields.Keyword
	OriginEntityLastSeenTimestamp                   fields.Date
	OriginEntityLifecycleLastActivity               fields.Date
	OriginEntityMetrics                             fields.Object
	OriginEntityName                                fields.Keyword
	OriginEntityRaw                                 fields.Object
	OriginEntityReference                           fields.Keyword
	OriginEntityRelationshipsAdministersEntityID    fields.Keyword
	OriginEntityRelationshipsAdministersHostID      fields.Keyword
	OriginEntityRelationshipsAdministersHostName    fields.Keyword
	OriginEntityRelationshipsAdministersServiceID   fields.Keyword
	OriginEntityRelationshipsAdministersServiceName fields.Keyword
	OriginEntityRelationshipsAdministersUserDomain  fields.Keyword
	OriginEntityRelationshipsAdministersUserEmail   fields.Keyword
	OriginEntityRelationshipsAdministersUserID      fields.Keyword
	OriginEntityRelationshipsAdministersUserName    fields.Keyword
	OriginEntityRelationshipsDependsOnEntityID      fields.Keyword
	OriginEntityRelationshipsDependsOnHostID        fields.Keyword
	OriginEntityRelationshipsDependsOnHostName      fields.Keyword
	OriginEntityRelationshipsDependsOnServiceID     fields.Keyword
	OriginEntityRelationshipsDependsOnServiceName   fields.Keyword
	OriginEntityRelationshipsDependsOnUserDomain    fields.Keyword
	OriginEntityRelationshipsDependsOnUserEmail     fields.Keyword
	OriginEntityRelationshipsDependsOnUserID        fields.Keyword
	OriginEntityRelationshipsDependsOnUserName      fields.Keyword
	OriginEntityRelationshipsOwnsEntityID           fields.Keyword
	OriginEntityRelationshipsOwnsHostID             fields.Keyword
	OriginEntityRelationshipsOwnsHostName           fields.Keyword
	OriginEntityRelationshipsOwnsServiceID          fields.Keyword
	OriginEntityRelationshipsOwnsServiceName        fields.Keyword
	OriginEntityRelationshipsOwnsUserDomain         fields.Keyword
	OriginEntityRelationshipsOwnsUserEmail          fields.Keyword
	OriginEntityRelationshipsOwnsUserID             fields.Keyword
	OriginEntityRelationshipsOwnsUserName           fields.Keyword
	OriginEntityRelationshipsSupervisesEntityID     fields.Keyword
	OriginEntityRelationshipsSupervisesHostID       fields.Keyword
	OriginEntityRelationshipsSupervisesHostName     fields.Keyword
	OriginEntityRelationshipsSupervisesServiceID    fields.Keyword
	OriginEntityRelationshipsSupervisesServiceName  fields.Keyword
	OriginEntityRelationshipsSupervisesUserDomain   fields.Keyword
	OriginEntityRelationshipsSupervisesUserEmail    fields.Keyword
	OriginEntityRelationshipsSupervisesUserID       fields.Keyword
	OriginEntityRelationshipsSupervisesUserName     fields.Keyword
	OriginEntitySource                              fields.Keyword
	OriginEntitySubType                             fields.Keyword
	OriginEntityType                                fields.Keyword
	OriginInstanceID                                fields.Keyword
	OriginInstanceName                              fields.Keyword
	OriginMachineType                               fields.Keyword
	OriginProjectID                                 fields.Keyword
	OriginProjectName                               fields.Keyword
	OriginProvider                                  fields.Keyword
	OriginRegion                                    fields.Keyword
	OriginServiceName                               fields.Keyword
	ProjectID                                       fields.Keyword
	ProjectName                                     fields.Keyword
	Provider                                        fields.Keyword
	Region                                          fields.Keyword
	ServiceName                                     fields.Keyword
	TargetAccountID                                 fields.Keyword
	TargetAccountName                               fields.Keyword
	TargetAvailabilityZone                          fields.Keyword
	TargetEntityAttributesKnownRedirects            fields.Keyword
	TargetEntityAttributesManaged                   fields.Boolean
	TargetEntityAttributesMfaEnabled                fields.Boolean
	TargetEntityAttributesOauthConsentRestriction   fields.Keyword
	TargetEntityAttributesPermissions               fields.Keyword
	TargetEntityAttributesStorageClass              fields.Keyword
	TargetEntityBehavior                            fields.Object
	TargetEntityDisplayName                         fields.Keyword
	TargetEntityID                                  fields.Keyword
	TargetEntityLastSeenTimestamp                   fields.Date
	TargetEntityLifecycleLastActivity               fields.Date
	TargetEntityMetrics                             fields.Object
	TargetEntityName                                fields.Keyword
	TargetEntityRaw                                 fields.Object
	TargetEntityReference                           fields.Keyword
	TargetEntityRelationshipsAdministersEntityID    fields.Keyword
	TargetEntityRelationshipsAdministersHostID      fields.Keyword
	TargetEntityRelationshipsAdministersHostName    fields.Keyword
	TargetEntityRelationshipsAdministersServiceID   fields.Keyword
	TargetEntityRelationshipsAdministersServiceName fields.Keyword
	TargetEntityRelationshipsAdministersUserDomain  fields.Keyword
	TargetEntityRelationshipsAdministersUserEmail   fields.Keyword
	TargetEntityRelationshipsAdministersUserID      fields.Keyword
	TargetEntityRelationshipsAdministersUserName    fields.Keyword
	TargetEntityRelationshipsDependsOnEntityID      fields.Keyword
	TargetEntityRelationshipsDependsOnHostID        fields.Keyword
	TargetEntityRelationshipsDependsOnHostName      fields.Keyword
	TargetEntityRelationshipsDependsOnServiceID     fields.Keyword
	TargetEntityRelationshipsDependsOnServiceName   fields.Keyword
	TargetEntityRelationshipsDependsOnUserDomain    fields.Keyword
	TargetEntityRelationshipsDependsOnUserEmail     fields.Keyword
	TargetEntityRelationshipsDependsOnUserID        fields.Keyword
	TargetEntityRelationshipsDependsOnUserName      fields.Keyword
	TargetEntityRelationshipsOwnsEntityID           fields.Keyword
	TargetEntityRelationshipsOwnsHostID             fields.Keyword
	TargetEntityRelationshipsOwnsHostName           fields.Keyword
	TargetEntityRelationshipsOwnsServiceID          fields.Keyword
	TargetEntityRelationshipsOwnsServiceName        fields.Keyword
	TargetEntityRelationshipsOwnsUserDomain         fields.Keyword
	TargetEntityRelationshipsOwnsUserEmail          fields.Keyword
	TargetEntityRelationshipsOwnsUserID             fields.Keyword
	TargetEntityRelationshipsOwnsUserName           fields.Keyword
	TargetEntityRelationshipsSupervisesEntityID     fields.Keyword
	TargetEntityRelationshipsSupervisesHostID       fields.Keyword
	TargetEntityRelationshipsSupervisesHostName     fields.Keyword
	TargetEntityRelationshipsSupervisesServiceID    fields.Keyword
	TargetEntityRelationshipsSupervisesServiceName  fields.Keyword
	TargetEntityRelationshipsSupervisesUserDomain   fields.Keyword
	TargetEntityRelationshipsSupervisesUserEmail    fields.Keyword
	TargetEntityRelationshipsSupervisesUserID       fields.Keyword
	TargetEntityRelationshipsSupervisesUserName     fields.Keyword
	TargetEntitySource                              fields.Keyword
	TargetEntitySubType                             fields.Keyword
	TargetEntityType                                fields.Keyword
	TargetInstanceID                                fields.Keyword
	TargetInstanceName                              fields.Keyword
	TargetMachineType                               fields.Keyword
	TargetProjectID                                 fields.Keyword
	TargetProjectName                               fields.Keyword
	TargetProvider                                  fields.Keyword
	TargetRegion                                    fields.Keyword
	TargetServiceName                               fields.Keyword
}

var Types TypesType = TypesType{}
