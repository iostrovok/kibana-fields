package service

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Address                                        fields.Field = "service.address"                                              // Address of this service.
	EntityAttributesKnownRedirects                 fields.Field = "service.entity.attributes.known_redirects"                    // Known redirect URIs or URLs associated with this entity.
	EntityAttributesManaged                        fields.Field = "service.entity.attributes.managed"                            // Indicates whether the entity is managed by an external system.
	EntityAttributesMfaEnabled                     fields.Field = "service.entity.attributes.mfa_enabled"                        // Indicates whether multi-factor authentication is enabled for this entity.
	EntityAttributesOauthConsentRestriction        fields.Field = "service.entity.attributes.oauth_consent_restriction"          // Restriction applied to OAuth consent for this entity.
	EntityAttributesPermissions                    fields.Field = "service.entity.attributes.permissions"                        // Action-level permissions associated with this entity.
	EntityAttributesStorageClass                   fields.Field = "service.entity.attributes.storage_class"                      // Storage tier or class assigned to an object storage resource.
	EntityBehavior                                 fields.Field = "service.entity.behavior"                                      // A set of ephemeral characteristics of the entity, derived from observed behaviors during a specific time period.
	EntityDisplayName                              fields.Field = "service.entity.display_name"                                  // An optional field used when a pretty name is desired for entity-centric operations.
	EntityID                                       fields.Field = "service.entity.id"                                            // Unique identifier for the entity.
	EntityLastSeenTimestamp                        fields.Field = "service.entity.last_seen_timestamp"                           // Indicates the date/time when this entity was last "seen."
	EntityLifecycleLastActivity                    fields.Field = "service.entity.lifecycle.last_activity"                       // Timestamp of the most recent action performed by or attributed to this entity.
	EntityMetrics                                  fields.Field = "service.entity.metrics"                                       // Field set for any fields containing numeric entity metrics.
	EntityName                                     fields.Field = "service.entity.name"                                          // The name of the entity.
	EntityRaw                                      fields.Field = "service.entity.raw"                                           // Original, unmodified fields from the source system.
	EntityReference                                fields.Field = "service.entity.reference"                                     // A URI, URL, or other direct reference to access or locate the entity.
	EntityRelationshipsAdministersEntityID         fields.Field = "service.entity.relationships.administers.entity.id"           // Identifiers of referenced entities.
	EntityRelationshipsAdministersHostID           fields.Field = "service.entity.relationships.administers.host.id"             // Referenced host ids.
	EntityRelationshipsAdministersHostName         fields.Field = "service.entity.relationships.administers.host.name"           // Referenced host names.
	EntityRelationshipsAdministersID               fields.Field = "service.entity.relationships.administers.service.id"          // Referenced service ids.
	EntityRelationshipsAdministersName             fields.Field = "service.entity.relationships.administers.service.name"        // Referenced service names.
	EntityRelationshipsAdministersUserDomain       fields.Field = "service.entity.relationships.administers.user.domain"         // Referenced user directory or AD/LDAP domain names.
	EntityRelationshipsAdministersUserEmail        fields.Field = "service.entity.relationships.administers.user.email"          // Referenced user email addresses.
	EntityRelationshipsAdministersUserID           fields.Field = "service.entity.relationships.administers.user.id"             // Referenced user ids.
	EntityRelationshipsAdministersUserName         fields.Field = "service.entity.relationships.administers.user.name"           // Referenced user short names or logins.
	EntityRelationshipsDependsOnEntityID           fields.Field = "service.entity.relationships.depends_on.entity.id"            // Identifiers of referenced entities.
	EntityRelationshipsDependsOnHostID             fields.Field = "service.entity.relationships.depends_on.host.id"              // Referenced host ids.
	EntityRelationshipsDependsOnHostName           fields.Field = "service.entity.relationships.depends_on.host.name"            // Referenced host names.
	EntityRelationshipsDependsOnID                 fields.Field = "service.entity.relationships.depends_on.service.id"           // Referenced service ids.
	EntityRelationshipsDependsOnName               fields.Field = "service.entity.relationships.depends_on.service.name"         // Referenced service names.
	EntityRelationshipsDependsOnUserDomain         fields.Field = "service.entity.relationships.depends_on.user.domain"          // Referenced user directory or AD/LDAP domain names.
	EntityRelationshipsDependsOnUserEmail          fields.Field = "service.entity.relationships.depends_on.user.email"           // Referenced user email addresses.
	EntityRelationshipsDependsOnUserID             fields.Field = "service.entity.relationships.depends_on.user.id"              // Referenced user ids.
	EntityRelationshipsDependsOnUserName           fields.Field = "service.entity.relationships.depends_on.user.name"            // Referenced user short names or logins.
	EntityRelationshipsOwnsEntityID                fields.Field = "service.entity.relationships.owns.entity.id"                  // Identifiers of referenced entities.
	EntityRelationshipsOwnsHostID                  fields.Field = "service.entity.relationships.owns.host.id"                    // Referenced host ids.
	EntityRelationshipsOwnsHostName                fields.Field = "service.entity.relationships.owns.host.name"                  // Referenced host names.
	EntityRelationshipsOwnsID                      fields.Field = "service.entity.relationships.owns.service.id"                 // Referenced service ids.
	EntityRelationshipsOwnsName                    fields.Field = "service.entity.relationships.owns.service.name"               // Referenced service names.
	EntityRelationshipsOwnsUserDomain              fields.Field = "service.entity.relationships.owns.user.domain"                // Referenced user directory or AD/LDAP domain names.
	EntityRelationshipsOwnsUserEmail               fields.Field = "service.entity.relationships.owns.user.email"                 // Referenced user email addresses.
	EntityRelationshipsOwnsUserID                  fields.Field = "service.entity.relationships.owns.user.id"                    // Referenced user ids.
	EntityRelationshipsOwnsUserName                fields.Field = "service.entity.relationships.owns.user.name"                  // Referenced user short names or logins.
	EntityRelationshipsSupervisesEntityID          fields.Field = "service.entity.relationships.supervises.entity.id"            // Identifiers of referenced entities.
	EntityRelationshipsSupervisesHostID            fields.Field = "service.entity.relationships.supervises.host.id"              // Referenced host ids.
	EntityRelationshipsSupervisesHostName          fields.Field = "service.entity.relationships.supervises.host.name"            // Referenced host names.
	EntityRelationshipsSupervisesID                fields.Field = "service.entity.relationships.supervises.service.id"           // Referenced service ids.
	EntityRelationshipsSupervisesName              fields.Field = "service.entity.relationships.supervises.service.name"         // Referenced service names.
	EntityRelationshipsSupervisesUserDomain        fields.Field = "service.entity.relationships.supervises.user.domain"          // Referenced user directory or AD/LDAP domain names.
	EntityRelationshipsSupervisesUserEmail         fields.Field = "service.entity.relationships.supervises.user.email"           // Referenced user email addresses.
	EntityRelationshipsSupervisesUserID            fields.Field = "service.entity.relationships.supervises.user.id"              // Referenced user ids.
	EntityRelationshipsSupervisesUserName          fields.Field = "service.entity.relationships.supervises.user.name"            // Referenced user short names or logins.
	EntitySource                                   fields.Field = "service.entity.source"                                        // Source module or integration that provided the entity data.
	EntitySubType                                  fields.Field = "service.entity.sub_type"                                      // The specific type designation for the entity as defined by its provider or system.
	EntityType                                     fields.Field = "service.entity.type"                                          // Standardized high-level classification of the entity.
	Environment                                    fields.Field = "service.environment"                                          // Environment of the service.
	EphemeralID                                    fields.Field = "service.ephemeral_id"                                         // Ephemeral identifier of this service.
	ID                                             fields.Field = "service.id"                                                   // Unique identifier of the running service.
	Name                                           fields.Field = "service.name"                                                 // Name of the service.
	NodeName                                       fields.Field = "service.node.name"                                            // Name of the service node.
	NodeRole                                       fields.Field = "service.node.role"                                            // Deprecated role (singular) of the service node.
	NodeRoles                                      fields.Field = "service.node.roles"                                           // Roles of the service node.
	OriginAddress                                  fields.Field = "service.origin.address"                                       // Address of this service.
	OriginEntityAttributesKnownRedirects           fields.Field = "service.origin.entity.attributes.known_redirects"             // Known redirect URIs or URLs associated with this entity.
	OriginEntityAttributesManaged                  fields.Field = "service.origin.entity.attributes.managed"                     // Indicates whether the entity is managed by an external system.
	OriginEntityAttributesMfaEnabled               fields.Field = "service.origin.entity.attributes.mfa_enabled"                 // Indicates whether multi-factor authentication is enabled for this entity.
	OriginEntityAttributesOauthConsentRestriction  fields.Field = "service.origin.entity.attributes.oauth_consent_restriction"   // Restriction applied to OAuth consent for this entity.
	OriginEntityAttributesPermissions              fields.Field = "service.origin.entity.attributes.permissions"                 // Action-level permissions associated with this entity.
	OriginEntityAttributesStorageClass             fields.Field = "service.origin.entity.attributes.storage_class"               // Storage tier or class assigned to an object storage resource.
	OriginEntityBehavior                           fields.Field = "service.origin.entity.behavior"                               // A set of ephemeral characteristics of the entity, derived from observed behaviors during a specific time period.
	OriginEntityDisplayName                        fields.Field = "service.origin.entity.display_name"                           // An optional field used when a pretty name is desired for entity-centric operations.
	OriginEntityID                                 fields.Field = "service.origin.entity.id"                                     // Unique identifier for the entity.
	OriginEntityLastSeenTimestamp                  fields.Field = "service.origin.entity.last_seen_timestamp"                    // Indicates the date/time when this entity was last "seen."
	OriginEntityLifecycleLastActivity              fields.Field = "service.origin.entity.lifecycle.last_activity"                // Timestamp of the most recent action performed by or attributed to this entity.
	OriginEntityMetrics                            fields.Field = "service.origin.entity.metrics"                                // Field set for any fields containing numeric entity metrics.
	OriginEntityName                               fields.Field = "service.origin.entity.name"                                   // The name of the entity.
	OriginEntityRaw                                fields.Field = "service.origin.entity.raw"                                    // Original, unmodified fields from the source system.
	OriginEntityReference                          fields.Field = "service.origin.entity.reference"                              // A URI, URL, or other direct reference to access or locate the entity.
	OriginEntityRelationshipsAdministersEntityID   fields.Field = "service.origin.entity.relationships.administers.entity.id"    // Identifiers of referenced entities.
	OriginEntityRelationshipsAdministersHostID     fields.Field = "service.origin.entity.relationships.administers.host.id"      // Referenced host ids.
	OriginEntityRelationshipsAdministersHostName   fields.Field = "service.origin.entity.relationships.administers.host.name"    // Referenced host names.
	OriginEntityRelationshipsAdministersID         fields.Field = "service.origin.entity.relationships.administers.service.id"   // Referenced service ids.
	OriginEntityRelationshipsAdministersName       fields.Field = "service.origin.entity.relationships.administers.service.name" // Referenced service names.
	OriginEntityRelationshipsAdministersUserDomain fields.Field = "service.origin.entity.relationships.administers.user.domain"  // Referenced user directory or AD/LDAP domain names.
	OriginEntityRelationshipsAdministersUserEmail  fields.Field = "service.origin.entity.relationships.administers.user.email"   // Referenced user email addresses.
	OriginEntityRelationshipsAdministersUserID     fields.Field = "service.origin.entity.relationships.administers.user.id"      // Referenced user ids.
	OriginEntityRelationshipsAdministersUserName   fields.Field = "service.origin.entity.relationships.administers.user.name"    // Referenced user short names or logins.
	OriginEntityRelationshipsDependsOnEntityID     fields.Field = "service.origin.entity.relationships.depends_on.entity.id"     // Identifiers of referenced entities.
	OriginEntityRelationshipsDependsOnHostID       fields.Field = "service.origin.entity.relationships.depends_on.host.id"       // Referenced host ids.
	OriginEntityRelationshipsDependsOnHostName     fields.Field = "service.origin.entity.relationships.depends_on.host.name"     // Referenced host names.
	OriginEntityRelationshipsDependsOnID           fields.Field = "service.origin.entity.relationships.depends_on.service.id"    // Referenced service ids.
	OriginEntityRelationshipsDependsOnName         fields.Field = "service.origin.entity.relationships.depends_on.service.name"  // Referenced service names.
	OriginEntityRelationshipsDependsOnUserDomain   fields.Field = "service.origin.entity.relationships.depends_on.user.domain"   // Referenced user directory or AD/LDAP domain names.
	OriginEntityRelationshipsDependsOnUserEmail    fields.Field = "service.origin.entity.relationships.depends_on.user.email"    // Referenced user email addresses.
	OriginEntityRelationshipsDependsOnUserID       fields.Field = "service.origin.entity.relationships.depends_on.user.id"       // Referenced user ids.
	OriginEntityRelationshipsDependsOnUserName     fields.Field = "service.origin.entity.relationships.depends_on.user.name"     // Referenced user short names or logins.
	OriginEntityRelationshipsOwnsEntityID          fields.Field = "service.origin.entity.relationships.owns.entity.id"           // Identifiers of referenced entities.
	OriginEntityRelationshipsOwnsHostID            fields.Field = "service.origin.entity.relationships.owns.host.id"             // Referenced host ids.
	OriginEntityRelationshipsOwnsHostName          fields.Field = "service.origin.entity.relationships.owns.host.name"           // Referenced host names.
	OriginEntityRelationshipsOwnsID                fields.Field = "service.origin.entity.relationships.owns.service.id"          // Referenced service ids.
	OriginEntityRelationshipsOwnsName              fields.Field = "service.origin.entity.relationships.owns.service.name"        // Referenced service names.
	OriginEntityRelationshipsOwnsUserDomain        fields.Field = "service.origin.entity.relationships.owns.user.domain"         // Referenced user directory or AD/LDAP domain names.
	OriginEntityRelationshipsOwnsUserEmail         fields.Field = "service.origin.entity.relationships.owns.user.email"          // Referenced user email addresses.
	OriginEntityRelationshipsOwnsUserID            fields.Field = "service.origin.entity.relationships.owns.user.id"             // Referenced user ids.
	OriginEntityRelationshipsOwnsUserName          fields.Field = "service.origin.entity.relationships.owns.user.name"           // Referenced user short names or logins.
	OriginEntityRelationshipsSupervisesEntityID    fields.Field = "service.origin.entity.relationships.supervises.entity.id"     // Identifiers of referenced entities.
	OriginEntityRelationshipsSupervisesHostID      fields.Field = "service.origin.entity.relationships.supervises.host.id"       // Referenced host ids.
	OriginEntityRelationshipsSupervisesHostName    fields.Field = "service.origin.entity.relationships.supervises.host.name"     // Referenced host names.
	OriginEntityRelationshipsSupervisesID          fields.Field = "service.origin.entity.relationships.supervises.service.id"    // Referenced service ids.
	OriginEntityRelationshipsSupervisesName        fields.Field = "service.origin.entity.relationships.supervises.service.name"  // Referenced service names.
	OriginEntityRelationshipsSupervisesUserDomain  fields.Field = "service.origin.entity.relationships.supervises.user.domain"   // Referenced user directory or AD/LDAP domain names.
	OriginEntityRelationshipsSupervisesUserEmail   fields.Field = "service.origin.entity.relationships.supervises.user.email"    // Referenced user email addresses.
	OriginEntityRelationshipsSupervisesUserID      fields.Field = "service.origin.entity.relationships.supervises.user.id"       // Referenced user ids.
	OriginEntityRelationshipsSupervisesUserName    fields.Field = "service.origin.entity.relationships.supervises.user.name"     // Referenced user short names or logins.
	OriginEntitySource                             fields.Field = "service.origin.entity.source"                                 // Source module or integration that provided the entity data.
	OriginEntitySubType                            fields.Field = "service.origin.entity.sub_type"                               // The specific type designation for the entity as defined by its provider or system.
	OriginEntityType                               fields.Field = "service.origin.entity.type"                                   // Standardized high-level classification of the entity.
	OriginEnvironment                              fields.Field = "service.origin.environment"                                   // Environment of the service.
	OriginEphemeralID                              fields.Field = "service.origin.ephemeral_id"                                  // Ephemeral identifier of this service.
	OriginID                                       fields.Field = "service.origin.id"                                            // Unique identifier of the running service.
	OriginName                                     fields.Field = "service.origin.name"                                          // Name of the service.
	OriginNodeName                                 fields.Field = "service.origin.node.name"                                     // Name of the service node.
	OriginNodeRole                                 fields.Field = "service.origin.node.role"                                     // Deprecated role (singular) of the service node.
	OriginNodeRoles                                fields.Field = "service.origin.node.roles"                                    // Roles of the service node.
	OriginState                                    fields.Field = "service.origin.state"                                         // Current state of the service.
	OriginType                                     fields.Field = "service.origin.type"                                          // The type of the service.
	OriginVersion                                  fields.Field = "service.origin.version"                                       // Version of the service.
	State                                          fields.Field = "service.state"                                                // Current state of the service.
	TargetAddress                                  fields.Field = "service.target.address"                                       // Address of this service.
	TargetEntityAttributesKnownRedirects           fields.Field = "service.target.entity.attributes.known_redirects"             // Known redirect URIs or URLs associated with this entity.
	TargetEntityAttributesManaged                  fields.Field = "service.target.entity.attributes.managed"                     // Indicates whether the entity is managed by an external system.
	TargetEntityAttributesMfaEnabled               fields.Field = "service.target.entity.attributes.mfa_enabled"                 // Indicates whether multi-factor authentication is enabled for this entity.
	TargetEntityAttributesOauthConsentRestriction  fields.Field = "service.target.entity.attributes.oauth_consent_restriction"   // Restriction applied to OAuth consent for this entity.
	TargetEntityAttributesPermissions              fields.Field = "service.target.entity.attributes.permissions"                 // Action-level permissions associated with this entity.
	TargetEntityAttributesStorageClass             fields.Field = "service.target.entity.attributes.storage_class"               // Storage tier or class assigned to an object storage resource.
	TargetEntityBehavior                           fields.Field = "service.target.entity.behavior"                               // A set of ephemeral characteristics of the entity, derived from observed behaviors during a specific time period.
	TargetEntityDisplayName                        fields.Field = "service.target.entity.display_name"                           // An optional field used when a pretty name is desired for entity-centric operations.
	TargetEntityID                                 fields.Field = "service.target.entity.id"                                     // Unique identifier for the entity.
	TargetEntityLastSeenTimestamp                  fields.Field = "service.target.entity.last_seen_timestamp"                    // Indicates the date/time when this entity was last "seen."
	TargetEntityLifecycleLastActivity              fields.Field = "service.target.entity.lifecycle.last_activity"                // Timestamp of the most recent action performed by or attributed to this entity.
	TargetEntityMetrics                            fields.Field = "service.target.entity.metrics"                                // Field set for any fields containing numeric entity metrics.
	TargetEntityName                               fields.Field = "service.target.entity.name"                                   // The name of the entity.
	TargetEntityRaw                                fields.Field = "service.target.entity.raw"                                    // Original, unmodified fields from the source system.
	TargetEntityReference                          fields.Field = "service.target.entity.reference"                              // A URI, URL, or other direct reference to access or locate the entity.
	TargetEntityRelationshipsAdministersEntityID   fields.Field = "service.target.entity.relationships.administers.entity.id"    // Identifiers of referenced entities.
	TargetEntityRelationshipsAdministersHostID     fields.Field = "service.target.entity.relationships.administers.host.id"      // Referenced host ids.
	TargetEntityRelationshipsAdministersHostName   fields.Field = "service.target.entity.relationships.administers.host.name"    // Referenced host names.
	TargetEntityRelationshipsAdministersID         fields.Field = "service.target.entity.relationships.administers.service.id"   // Referenced service ids.
	TargetEntityRelationshipsAdministersName       fields.Field = "service.target.entity.relationships.administers.service.name" // Referenced service names.
	TargetEntityRelationshipsAdministersUserDomain fields.Field = "service.target.entity.relationships.administers.user.domain"  // Referenced user directory or AD/LDAP domain names.
	TargetEntityRelationshipsAdministersUserEmail  fields.Field = "service.target.entity.relationships.administers.user.email"   // Referenced user email addresses.
	TargetEntityRelationshipsAdministersUserID     fields.Field = "service.target.entity.relationships.administers.user.id"      // Referenced user ids.
	TargetEntityRelationshipsAdministersUserName   fields.Field = "service.target.entity.relationships.administers.user.name"    // Referenced user short names or logins.
	TargetEntityRelationshipsDependsOnEntityID     fields.Field = "service.target.entity.relationships.depends_on.entity.id"     // Identifiers of referenced entities.
	TargetEntityRelationshipsDependsOnHostID       fields.Field = "service.target.entity.relationships.depends_on.host.id"       // Referenced host ids.
	TargetEntityRelationshipsDependsOnHostName     fields.Field = "service.target.entity.relationships.depends_on.host.name"     // Referenced host names.
	TargetEntityRelationshipsDependsOnID           fields.Field = "service.target.entity.relationships.depends_on.service.id"    // Referenced service ids.
	TargetEntityRelationshipsDependsOnName         fields.Field = "service.target.entity.relationships.depends_on.service.name"  // Referenced service names.
	TargetEntityRelationshipsDependsOnUserDomain   fields.Field = "service.target.entity.relationships.depends_on.user.domain"   // Referenced user directory or AD/LDAP domain names.
	TargetEntityRelationshipsDependsOnUserEmail    fields.Field = "service.target.entity.relationships.depends_on.user.email"    // Referenced user email addresses.
	TargetEntityRelationshipsDependsOnUserID       fields.Field = "service.target.entity.relationships.depends_on.user.id"       // Referenced user ids.
	TargetEntityRelationshipsDependsOnUserName     fields.Field = "service.target.entity.relationships.depends_on.user.name"     // Referenced user short names or logins.
	TargetEntityRelationshipsOwnsEntityID          fields.Field = "service.target.entity.relationships.owns.entity.id"           // Identifiers of referenced entities.
	TargetEntityRelationshipsOwnsHostID            fields.Field = "service.target.entity.relationships.owns.host.id"             // Referenced host ids.
	TargetEntityRelationshipsOwnsHostName          fields.Field = "service.target.entity.relationships.owns.host.name"           // Referenced host names.
	TargetEntityRelationshipsOwnsID                fields.Field = "service.target.entity.relationships.owns.service.id"          // Referenced service ids.
	TargetEntityRelationshipsOwnsName              fields.Field = "service.target.entity.relationships.owns.service.name"        // Referenced service names.
	TargetEntityRelationshipsOwnsUserDomain        fields.Field = "service.target.entity.relationships.owns.user.domain"         // Referenced user directory or AD/LDAP domain names.
	TargetEntityRelationshipsOwnsUserEmail         fields.Field = "service.target.entity.relationships.owns.user.email"          // Referenced user email addresses.
	TargetEntityRelationshipsOwnsUserID            fields.Field = "service.target.entity.relationships.owns.user.id"             // Referenced user ids.
	TargetEntityRelationshipsOwnsUserName          fields.Field = "service.target.entity.relationships.owns.user.name"           // Referenced user short names or logins.
	TargetEntityRelationshipsSupervisesEntityID    fields.Field = "service.target.entity.relationships.supervises.entity.id"     // Identifiers of referenced entities.
	TargetEntityRelationshipsSupervisesHostID      fields.Field = "service.target.entity.relationships.supervises.host.id"       // Referenced host ids.
	TargetEntityRelationshipsSupervisesHostName    fields.Field = "service.target.entity.relationships.supervises.host.name"     // Referenced host names.
	TargetEntityRelationshipsSupervisesID          fields.Field = "service.target.entity.relationships.supervises.service.id"    // Referenced service ids.
	TargetEntityRelationshipsSupervisesName        fields.Field = "service.target.entity.relationships.supervises.service.name"  // Referenced service names.
	TargetEntityRelationshipsSupervisesUserDomain  fields.Field = "service.target.entity.relationships.supervises.user.domain"   // Referenced user directory or AD/LDAP domain names.
	TargetEntityRelationshipsSupervisesUserEmail   fields.Field = "service.target.entity.relationships.supervises.user.email"    // Referenced user email addresses.
	TargetEntityRelationshipsSupervisesUserID      fields.Field = "service.target.entity.relationships.supervises.user.id"       // Referenced user ids.
	TargetEntityRelationshipsSupervisesUserName    fields.Field = "service.target.entity.relationships.supervises.user.name"     // Referenced user short names or logins.
	TargetEntitySource                             fields.Field = "service.target.entity.source"                                 // Source module or integration that provided the entity data.
	TargetEntitySubType                            fields.Field = "service.target.entity.sub_type"                               // The specific type designation for the entity as defined by its provider or system.
	TargetEntityType                               fields.Field = "service.target.entity.type"                                   // Standardized high-level classification of the entity.
	TargetEnvironment                              fields.Field = "service.target.environment"                                   // Environment of the service.
	TargetEphemeralID                              fields.Field = "service.target.ephemeral_id"                                  // Ephemeral identifier of this service.
	TargetID                                       fields.Field = "service.target.id"                                            // Unique identifier of the running service.
	TargetName                                     fields.Field = "service.target.name"                                          // Name of the service.
	TargetNodeName                                 fields.Field = "service.target.node.name"                                     // Name of the service node.
	TargetNodeRole                                 fields.Field = "service.target.node.role"                                     // Deprecated role (singular) of the service node.
	TargetNodeRoles                                fields.Field = "service.target.node.roles"                                    // Roles of the service node.
	TargetState                                    fields.Field = "service.target.state"                                         // Current state of the service.
	TargetType                                     fields.Field = "service.target.type"                                          // The type of the service.
	TargetVersion                                  fields.Field = "service.target.version"                                       // Version of the service.
	Type                                           fields.Field = "service.type"                                                 // The type of the service.
	Version                                        fields.Field = "service.version"                                              // Version of the service.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Address,
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
	EntityRelationshipsAdministersID,
	EntityRelationshipsAdministersName,
	EntityRelationshipsAdministersUserDomain,
	EntityRelationshipsAdministersUserEmail,
	EntityRelationshipsAdministersUserID,
	EntityRelationshipsAdministersUserName,
	EntityRelationshipsDependsOnEntityID,
	EntityRelationshipsDependsOnHostID,
	EntityRelationshipsDependsOnHostName,
	EntityRelationshipsDependsOnID,
	EntityRelationshipsDependsOnName,
	EntityRelationshipsDependsOnUserDomain,
	EntityRelationshipsDependsOnUserEmail,
	EntityRelationshipsDependsOnUserID,
	EntityRelationshipsDependsOnUserName,
	EntityRelationshipsOwnsEntityID,
	EntityRelationshipsOwnsHostID,
	EntityRelationshipsOwnsHostName,
	EntityRelationshipsOwnsID,
	EntityRelationshipsOwnsName,
	EntityRelationshipsOwnsUserDomain,
	EntityRelationshipsOwnsUserEmail,
	EntityRelationshipsOwnsUserID,
	EntityRelationshipsOwnsUserName,
	EntityRelationshipsSupervisesEntityID,
	EntityRelationshipsSupervisesHostID,
	EntityRelationshipsSupervisesHostName,
	EntityRelationshipsSupervisesID,
	EntityRelationshipsSupervisesName,
	EntityRelationshipsSupervisesUserDomain,
	EntityRelationshipsSupervisesUserEmail,
	EntityRelationshipsSupervisesUserID,
	EntityRelationshipsSupervisesUserName,
	EntitySource,
	EntitySubType,
	EntityType,
	Environment,
	EphemeralID,
	ID,
	Name,
	NodeName,
	NodeRole,
	NodeRoles,
	OriginAddress,
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
	OriginEntityRelationshipsAdministersID,
	OriginEntityRelationshipsAdministersName,
	OriginEntityRelationshipsAdministersUserDomain,
	OriginEntityRelationshipsAdministersUserEmail,
	OriginEntityRelationshipsAdministersUserID,
	OriginEntityRelationshipsAdministersUserName,
	OriginEntityRelationshipsDependsOnEntityID,
	OriginEntityRelationshipsDependsOnHostID,
	OriginEntityRelationshipsDependsOnHostName,
	OriginEntityRelationshipsDependsOnID,
	OriginEntityRelationshipsDependsOnName,
	OriginEntityRelationshipsDependsOnUserDomain,
	OriginEntityRelationshipsDependsOnUserEmail,
	OriginEntityRelationshipsDependsOnUserID,
	OriginEntityRelationshipsDependsOnUserName,
	OriginEntityRelationshipsOwnsEntityID,
	OriginEntityRelationshipsOwnsHostID,
	OriginEntityRelationshipsOwnsHostName,
	OriginEntityRelationshipsOwnsID,
	OriginEntityRelationshipsOwnsName,
	OriginEntityRelationshipsOwnsUserDomain,
	OriginEntityRelationshipsOwnsUserEmail,
	OriginEntityRelationshipsOwnsUserID,
	OriginEntityRelationshipsOwnsUserName,
	OriginEntityRelationshipsSupervisesEntityID,
	OriginEntityRelationshipsSupervisesHostID,
	OriginEntityRelationshipsSupervisesHostName,
	OriginEntityRelationshipsSupervisesID,
	OriginEntityRelationshipsSupervisesName,
	OriginEntityRelationshipsSupervisesUserDomain,
	OriginEntityRelationshipsSupervisesUserEmail,
	OriginEntityRelationshipsSupervisesUserID,
	OriginEntityRelationshipsSupervisesUserName,
	OriginEntitySource,
	OriginEntitySubType,
	OriginEntityType,
	OriginEnvironment,
	OriginEphemeralID,
	OriginID,
	OriginName,
	OriginNodeName,
	OriginNodeRole,
	OriginNodeRoles,
	OriginState,
	OriginType,
	OriginVersion,
	State,
	TargetAddress,
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
	TargetEntityRelationshipsAdministersID,
	TargetEntityRelationshipsAdministersName,
	TargetEntityRelationshipsAdministersUserDomain,
	TargetEntityRelationshipsAdministersUserEmail,
	TargetEntityRelationshipsAdministersUserID,
	TargetEntityRelationshipsAdministersUserName,
	TargetEntityRelationshipsDependsOnEntityID,
	TargetEntityRelationshipsDependsOnHostID,
	TargetEntityRelationshipsDependsOnHostName,
	TargetEntityRelationshipsDependsOnID,
	TargetEntityRelationshipsDependsOnName,
	TargetEntityRelationshipsDependsOnUserDomain,
	TargetEntityRelationshipsDependsOnUserEmail,
	TargetEntityRelationshipsDependsOnUserID,
	TargetEntityRelationshipsDependsOnUserName,
	TargetEntityRelationshipsOwnsEntityID,
	TargetEntityRelationshipsOwnsHostID,
	TargetEntityRelationshipsOwnsHostName,
	TargetEntityRelationshipsOwnsID,
	TargetEntityRelationshipsOwnsName,
	TargetEntityRelationshipsOwnsUserDomain,
	TargetEntityRelationshipsOwnsUserEmail,
	TargetEntityRelationshipsOwnsUserID,
	TargetEntityRelationshipsOwnsUserName,
	TargetEntityRelationshipsSupervisesEntityID,
	TargetEntityRelationshipsSupervisesHostID,
	TargetEntityRelationshipsSupervisesHostName,
	TargetEntityRelationshipsSupervisesID,
	TargetEntityRelationshipsSupervisesName,
	TargetEntityRelationshipsSupervisesUserDomain,
	TargetEntityRelationshipsSupervisesUserEmail,
	TargetEntityRelationshipsSupervisesUserID,
	TargetEntityRelationshipsSupervisesUserName,
	TargetEntitySource,
	TargetEntitySubType,
	TargetEntityType,
	TargetEnvironment,
	TargetEphemeralID,
	TargetID,
	TargetName,
	TargetNodeName,
	TargetNodeRole,
	TargetNodeRoles,
	TargetState,
	TargetType,
	TargetVersion,
	Type,
	Version,
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
	Address                                        fields.Keyword
	EntityAttributesKnownRedirects                 fields.Keyword
	EntityAttributesManaged                        fields.Boolean
	EntityAttributesMfaEnabled                     fields.Boolean
	EntityAttributesOauthConsentRestriction        fields.Keyword
	EntityAttributesPermissions                    fields.Keyword
	EntityAttributesStorageClass                   fields.Keyword
	EntityBehavior                                 fields.Object
	EntityDisplayName                              fields.Keyword
	EntityID                                       fields.Keyword
	EntityLastSeenTimestamp                        fields.Date
	EntityLifecycleLastActivity                    fields.Date
	EntityMetrics                                  fields.Object
	EntityName                                     fields.Keyword
	EntityRaw                                      fields.Object
	EntityReference                                fields.Keyword
	EntityRelationshipsAdministersEntityID         fields.Keyword
	EntityRelationshipsAdministersHostID           fields.Keyword
	EntityRelationshipsAdministersHostName         fields.Keyword
	EntityRelationshipsAdministersID               fields.Keyword
	EntityRelationshipsAdministersName             fields.Keyword
	EntityRelationshipsAdministersUserDomain       fields.Keyword
	EntityRelationshipsAdministersUserEmail        fields.Keyword
	EntityRelationshipsAdministersUserID           fields.Keyword
	EntityRelationshipsAdministersUserName         fields.Keyword
	EntityRelationshipsDependsOnEntityID           fields.Keyword
	EntityRelationshipsDependsOnHostID             fields.Keyword
	EntityRelationshipsDependsOnHostName           fields.Keyword
	EntityRelationshipsDependsOnID                 fields.Keyword
	EntityRelationshipsDependsOnName               fields.Keyword
	EntityRelationshipsDependsOnUserDomain         fields.Keyword
	EntityRelationshipsDependsOnUserEmail          fields.Keyword
	EntityRelationshipsDependsOnUserID             fields.Keyword
	EntityRelationshipsDependsOnUserName           fields.Keyword
	EntityRelationshipsOwnsEntityID                fields.Keyword
	EntityRelationshipsOwnsHostID                  fields.Keyword
	EntityRelationshipsOwnsHostName                fields.Keyword
	EntityRelationshipsOwnsID                      fields.Keyword
	EntityRelationshipsOwnsName                    fields.Keyword
	EntityRelationshipsOwnsUserDomain              fields.Keyword
	EntityRelationshipsOwnsUserEmail               fields.Keyword
	EntityRelationshipsOwnsUserID                  fields.Keyword
	EntityRelationshipsOwnsUserName                fields.Keyword
	EntityRelationshipsSupervisesEntityID          fields.Keyword
	EntityRelationshipsSupervisesHostID            fields.Keyword
	EntityRelationshipsSupervisesHostName          fields.Keyword
	EntityRelationshipsSupervisesID                fields.Keyword
	EntityRelationshipsSupervisesName              fields.Keyword
	EntityRelationshipsSupervisesUserDomain        fields.Keyword
	EntityRelationshipsSupervisesUserEmail         fields.Keyword
	EntityRelationshipsSupervisesUserID            fields.Keyword
	EntityRelationshipsSupervisesUserName          fields.Keyword
	EntitySource                                   fields.Keyword
	EntitySubType                                  fields.Keyword
	EntityType                                     fields.Keyword
	Environment                                    fields.Keyword
	EphemeralID                                    fields.Keyword
	ID                                             fields.Keyword
	Name                                           fields.Keyword
	NodeName                                       fields.Keyword
	NodeRole                                       fields.Keyword
	NodeRoles                                      fields.Keyword
	OriginAddress                                  fields.Keyword
	OriginEntityAttributesKnownRedirects           fields.Keyword
	OriginEntityAttributesManaged                  fields.Boolean
	OriginEntityAttributesMfaEnabled               fields.Boolean
	OriginEntityAttributesOauthConsentRestriction  fields.Keyword
	OriginEntityAttributesPermissions              fields.Keyword
	OriginEntityAttributesStorageClass             fields.Keyword
	OriginEntityBehavior                           fields.Object
	OriginEntityDisplayName                        fields.Keyword
	OriginEntityID                                 fields.Keyword
	OriginEntityLastSeenTimestamp                  fields.Date
	OriginEntityLifecycleLastActivity              fields.Date
	OriginEntityMetrics                            fields.Object
	OriginEntityName                               fields.Keyword
	OriginEntityRaw                                fields.Object
	OriginEntityReference                          fields.Keyword
	OriginEntityRelationshipsAdministersEntityID   fields.Keyword
	OriginEntityRelationshipsAdministersHostID     fields.Keyword
	OriginEntityRelationshipsAdministersHostName   fields.Keyword
	OriginEntityRelationshipsAdministersID         fields.Keyword
	OriginEntityRelationshipsAdministersName       fields.Keyword
	OriginEntityRelationshipsAdministersUserDomain fields.Keyword
	OriginEntityRelationshipsAdministersUserEmail  fields.Keyword
	OriginEntityRelationshipsAdministersUserID     fields.Keyword
	OriginEntityRelationshipsAdministersUserName   fields.Keyword
	OriginEntityRelationshipsDependsOnEntityID     fields.Keyword
	OriginEntityRelationshipsDependsOnHostID       fields.Keyword
	OriginEntityRelationshipsDependsOnHostName     fields.Keyword
	OriginEntityRelationshipsDependsOnID           fields.Keyword
	OriginEntityRelationshipsDependsOnName         fields.Keyword
	OriginEntityRelationshipsDependsOnUserDomain   fields.Keyword
	OriginEntityRelationshipsDependsOnUserEmail    fields.Keyword
	OriginEntityRelationshipsDependsOnUserID       fields.Keyword
	OriginEntityRelationshipsDependsOnUserName     fields.Keyword
	OriginEntityRelationshipsOwnsEntityID          fields.Keyword
	OriginEntityRelationshipsOwnsHostID            fields.Keyword
	OriginEntityRelationshipsOwnsHostName          fields.Keyword
	OriginEntityRelationshipsOwnsID                fields.Keyword
	OriginEntityRelationshipsOwnsName              fields.Keyword
	OriginEntityRelationshipsOwnsUserDomain        fields.Keyword
	OriginEntityRelationshipsOwnsUserEmail         fields.Keyword
	OriginEntityRelationshipsOwnsUserID            fields.Keyword
	OriginEntityRelationshipsOwnsUserName          fields.Keyword
	OriginEntityRelationshipsSupervisesEntityID    fields.Keyword
	OriginEntityRelationshipsSupervisesHostID      fields.Keyword
	OriginEntityRelationshipsSupervisesHostName    fields.Keyword
	OriginEntityRelationshipsSupervisesID          fields.Keyword
	OriginEntityRelationshipsSupervisesName        fields.Keyword
	OriginEntityRelationshipsSupervisesUserDomain  fields.Keyword
	OriginEntityRelationshipsSupervisesUserEmail   fields.Keyword
	OriginEntityRelationshipsSupervisesUserID      fields.Keyword
	OriginEntityRelationshipsSupervisesUserName    fields.Keyword
	OriginEntitySource                             fields.Keyword
	OriginEntitySubType                            fields.Keyword
	OriginEntityType                               fields.Keyword
	OriginEnvironment                              fields.Keyword
	OriginEphemeralID                              fields.Keyword
	OriginID                                       fields.Keyword
	OriginName                                     fields.Keyword
	OriginNodeName                                 fields.Keyword
	OriginNodeRole                                 fields.Keyword
	OriginNodeRoles                                fields.Keyword
	OriginState                                    fields.Keyword
	OriginType                                     fields.Keyword
	OriginVersion                                  fields.Keyword
	State                                          fields.Keyword
	TargetAddress                                  fields.Keyword
	TargetEntityAttributesKnownRedirects           fields.Keyword
	TargetEntityAttributesManaged                  fields.Boolean
	TargetEntityAttributesMfaEnabled               fields.Boolean
	TargetEntityAttributesOauthConsentRestriction  fields.Keyword
	TargetEntityAttributesPermissions              fields.Keyword
	TargetEntityAttributesStorageClass             fields.Keyword
	TargetEntityBehavior                           fields.Object
	TargetEntityDisplayName                        fields.Keyword
	TargetEntityID                                 fields.Keyword
	TargetEntityLastSeenTimestamp                  fields.Date
	TargetEntityLifecycleLastActivity              fields.Date
	TargetEntityMetrics                            fields.Object
	TargetEntityName                               fields.Keyword
	TargetEntityRaw                                fields.Object
	TargetEntityReference                          fields.Keyword
	TargetEntityRelationshipsAdministersEntityID   fields.Keyword
	TargetEntityRelationshipsAdministersHostID     fields.Keyword
	TargetEntityRelationshipsAdministersHostName   fields.Keyword
	TargetEntityRelationshipsAdministersID         fields.Keyword
	TargetEntityRelationshipsAdministersName       fields.Keyword
	TargetEntityRelationshipsAdministersUserDomain fields.Keyword
	TargetEntityRelationshipsAdministersUserEmail  fields.Keyword
	TargetEntityRelationshipsAdministersUserID     fields.Keyword
	TargetEntityRelationshipsAdministersUserName   fields.Keyword
	TargetEntityRelationshipsDependsOnEntityID     fields.Keyword
	TargetEntityRelationshipsDependsOnHostID       fields.Keyword
	TargetEntityRelationshipsDependsOnHostName     fields.Keyword
	TargetEntityRelationshipsDependsOnID           fields.Keyword
	TargetEntityRelationshipsDependsOnName         fields.Keyword
	TargetEntityRelationshipsDependsOnUserDomain   fields.Keyword
	TargetEntityRelationshipsDependsOnUserEmail    fields.Keyword
	TargetEntityRelationshipsDependsOnUserID       fields.Keyword
	TargetEntityRelationshipsDependsOnUserName     fields.Keyword
	TargetEntityRelationshipsOwnsEntityID          fields.Keyword
	TargetEntityRelationshipsOwnsHostID            fields.Keyword
	TargetEntityRelationshipsOwnsHostName          fields.Keyword
	TargetEntityRelationshipsOwnsID                fields.Keyword
	TargetEntityRelationshipsOwnsName              fields.Keyword
	TargetEntityRelationshipsOwnsUserDomain        fields.Keyword
	TargetEntityRelationshipsOwnsUserEmail         fields.Keyword
	TargetEntityRelationshipsOwnsUserID            fields.Keyword
	TargetEntityRelationshipsOwnsUserName          fields.Keyword
	TargetEntityRelationshipsSupervisesEntityID    fields.Keyword
	TargetEntityRelationshipsSupervisesHostID      fields.Keyword
	TargetEntityRelationshipsSupervisesHostName    fields.Keyword
	TargetEntityRelationshipsSupervisesID          fields.Keyword
	TargetEntityRelationshipsSupervisesName        fields.Keyword
	TargetEntityRelationshipsSupervisesUserDomain  fields.Keyword
	TargetEntityRelationshipsSupervisesUserEmail   fields.Keyword
	TargetEntityRelationshipsSupervisesUserID      fields.Keyword
	TargetEntityRelationshipsSupervisesUserName    fields.Keyword
	TargetEntitySource                             fields.Keyword
	TargetEntitySubType                            fields.Keyword
	TargetEntityType                               fields.Keyword
	TargetEnvironment                              fields.Keyword
	TargetEphemeralID                              fields.Keyword
	TargetID                                       fields.Keyword
	TargetName                                     fields.Keyword
	TargetNodeName                                 fields.Keyword
	TargetNodeRole                                 fields.Keyword
	TargetNodeRoles                                fields.Keyword
	TargetState                                    fields.Keyword
	TargetType                                     fields.Keyword
	TargetVersion                                  fields.Keyword
	Type                                           fields.Keyword
	Version                                        fields.Keyword
}

var Types TypesType = TypesType{}
