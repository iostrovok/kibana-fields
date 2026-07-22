package user

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	ChangesDomain                                      fields.Field = "user.changes.domain"                                          // Name of the directory the user is a member of.
	ChangesEmail                                       fields.Field = "user.changes.email"                                           // User email address.
	ChangesEntityAttributesKnownRedirects              fields.Field = "user.changes.entity.attributes.known_redirects"               // Known redirect URIs or URLs associated with this entity.
	ChangesEntityAttributesManaged                     fields.Field = "user.changes.entity.attributes.managed"                       // Indicates whether the entity is managed by an external system.
	ChangesEntityAttributesMfaEnabled                  fields.Field = "user.changes.entity.attributes.mfa_enabled"                   // Indicates whether multi-factor authentication is enabled for this entity.
	ChangesEntityAttributesOauthConsentRestriction     fields.Field = "user.changes.entity.attributes.oauth_consent_restriction"     // Restriction applied to OAuth consent for this entity.
	ChangesEntityAttributesPermissions                 fields.Field = "user.changes.entity.attributes.permissions"                   // Action-level permissions associated with this entity.
	ChangesEntityAttributesStorageClass                fields.Field = "user.changes.entity.attributes.storage_class"                 // Storage tier or class assigned to an object storage resource.
	ChangesEntityBehavior                              fields.Field = "user.changes.entity.behavior"                                 // A set of ephemeral characteristics of the entity, derived from observed behaviors during a specific time period.
	ChangesEntityDisplayName                           fields.Field = "user.changes.entity.display_name"                             // An optional field used when a pretty name is desired for entity-centric operations.
	ChangesEntityID                                    fields.Field = "user.changes.entity.id"                                       // Unique identifier for the entity.
	ChangesEntityLastSeenTimestamp                     fields.Field = "user.changes.entity.last_seen_timestamp"                      // Indicates the date/time when this entity was last "seen."
	ChangesEntityLifecycleLastActivity                 fields.Field = "user.changes.entity.lifecycle.last_activity"                  // Timestamp of the most recent action performed by or attributed to this entity.
	ChangesEntityMetrics                               fields.Field = "user.changes.entity.metrics"                                  // Field set for any fields containing numeric entity metrics.
	ChangesEntityName                                  fields.Field = "user.changes.entity.name"                                     // The name of the entity.
	ChangesEntityRaw                                   fields.Field = "user.changes.entity.raw"                                      // Original, unmodified fields from the source system.
	ChangesEntityReference                             fields.Field = "user.changes.entity.reference"                                // A URI, URL, or other direct reference to access or locate the entity.
	ChangesEntityRelationshipsAdministersDomain        fields.Field = "user.changes.entity.relationships.administers.user.domain"    // Referenced user directory or AD/LDAP domain names.
	ChangesEntityRelationshipsAdministersEmail         fields.Field = "user.changes.entity.relationships.administers.user.email"     // Referenced user email addresses.
	ChangesEntityRelationshipsAdministersEntityID      fields.Field = "user.changes.entity.relationships.administers.entity.id"      // Identifiers of referenced entities.
	ChangesEntityRelationshipsAdministersHostID        fields.Field = "user.changes.entity.relationships.administers.host.id"        // Referenced host ids.
	ChangesEntityRelationshipsAdministersHostName      fields.Field = "user.changes.entity.relationships.administers.host.name"      // Referenced host names.
	ChangesEntityRelationshipsAdministersID            fields.Field = "user.changes.entity.relationships.administers.user.id"        // Referenced user ids.
	ChangesEntityRelationshipsAdministersName          fields.Field = "user.changes.entity.relationships.administers.user.name"      // Referenced user short names or logins.
	ChangesEntityRelationshipsAdministersServiceID     fields.Field = "user.changes.entity.relationships.administers.service.id"     // Referenced service ids.
	ChangesEntityRelationshipsAdministersServiceName   fields.Field = "user.changes.entity.relationships.administers.service.name"   // Referenced service names.
	ChangesEntityRelationshipsDependsOnDomain          fields.Field = "user.changes.entity.relationships.depends_on.user.domain"     // Referenced user directory or AD/LDAP domain names.
	ChangesEntityRelationshipsDependsOnEmail           fields.Field = "user.changes.entity.relationships.depends_on.user.email"      // Referenced user email addresses.
	ChangesEntityRelationshipsDependsOnEntityID        fields.Field = "user.changes.entity.relationships.depends_on.entity.id"       // Identifiers of referenced entities.
	ChangesEntityRelationshipsDependsOnHostID          fields.Field = "user.changes.entity.relationships.depends_on.host.id"         // Referenced host ids.
	ChangesEntityRelationshipsDependsOnHostName        fields.Field = "user.changes.entity.relationships.depends_on.host.name"       // Referenced host names.
	ChangesEntityRelationshipsDependsOnID              fields.Field = "user.changes.entity.relationships.depends_on.user.id"         // Referenced user ids.
	ChangesEntityRelationshipsDependsOnName            fields.Field = "user.changes.entity.relationships.depends_on.user.name"       // Referenced user short names or logins.
	ChangesEntityRelationshipsDependsOnServiceID       fields.Field = "user.changes.entity.relationships.depends_on.service.id"      // Referenced service ids.
	ChangesEntityRelationshipsDependsOnServiceName     fields.Field = "user.changes.entity.relationships.depends_on.service.name"    // Referenced service names.
	ChangesEntityRelationshipsOwnsDomain               fields.Field = "user.changes.entity.relationships.owns.user.domain"           // Referenced user directory or AD/LDAP domain names.
	ChangesEntityRelationshipsOwnsEmail                fields.Field = "user.changes.entity.relationships.owns.user.email"            // Referenced user email addresses.
	ChangesEntityRelationshipsOwnsEntityID             fields.Field = "user.changes.entity.relationships.owns.entity.id"             // Identifiers of referenced entities.
	ChangesEntityRelationshipsOwnsHostID               fields.Field = "user.changes.entity.relationships.owns.host.id"               // Referenced host ids.
	ChangesEntityRelationshipsOwnsHostName             fields.Field = "user.changes.entity.relationships.owns.host.name"             // Referenced host names.
	ChangesEntityRelationshipsOwnsID                   fields.Field = "user.changes.entity.relationships.owns.user.id"               // Referenced user ids.
	ChangesEntityRelationshipsOwnsName                 fields.Field = "user.changes.entity.relationships.owns.user.name"             // Referenced user short names or logins.
	ChangesEntityRelationshipsOwnsServiceID            fields.Field = "user.changes.entity.relationships.owns.service.id"            // Referenced service ids.
	ChangesEntityRelationshipsOwnsServiceName          fields.Field = "user.changes.entity.relationships.owns.service.name"          // Referenced service names.
	ChangesEntityRelationshipsSupervisesDomain         fields.Field = "user.changes.entity.relationships.supervises.user.domain"     // Referenced user directory or AD/LDAP domain names.
	ChangesEntityRelationshipsSupervisesEmail          fields.Field = "user.changes.entity.relationships.supervises.user.email"      // Referenced user email addresses.
	ChangesEntityRelationshipsSupervisesEntityID       fields.Field = "user.changes.entity.relationships.supervises.entity.id"       // Identifiers of referenced entities.
	ChangesEntityRelationshipsSupervisesHostID         fields.Field = "user.changes.entity.relationships.supervises.host.id"         // Referenced host ids.
	ChangesEntityRelationshipsSupervisesHostName       fields.Field = "user.changes.entity.relationships.supervises.host.name"       // Referenced host names.
	ChangesEntityRelationshipsSupervisesID             fields.Field = "user.changes.entity.relationships.supervises.user.id"         // Referenced user ids.
	ChangesEntityRelationshipsSupervisesName           fields.Field = "user.changes.entity.relationships.supervises.user.name"       // Referenced user short names or logins.
	ChangesEntityRelationshipsSupervisesServiceID      fields.Field = "user.changes.entity.relationships.supervises.service.id"      // Referenced service ids.
	ChangesEntityRelationshipsSupervisesServiceName    fields.Field = "user.changes.entity.relationships.supervises.service.name"    // Referenced service names.
	ChangesEntitySource                                fields.Field = "user.changes.entity.source"                                   // Source module or integration that provided the entity data.
	ChangesEntitySubType                               fields.Field = "user.changes.entity.sub_type"                                 // The specific type designation for the entity as defined by its provider or system.
	ChangesEntityType                                  fields.Field = "user.changes.entity.type"                                     // Standardized high-level classification of the entity.
	ChangesFullName                                    fields.Field = "user.changes.full_name"                                       // User's full name, if available.
	ChangesGroupDomain                                 fields.Field = "user.changes.group.domain"                                    // Name of the directory the group is a member of.
	ChangesGroupID                                     fields.Field = "user.changes.group.id"                                        // Unique identifier for the group on the system/platform.
	ChangesGroupName                                   fields.Field = "user.changes.group.name"                                      // Name of the group.
	ChangesHash                                        fields.Field = "user.changes.hash"                                            // Unique user hash to correlate information for a user in anonymized form.
	ChangesID                                          fields.Field = "user.changes.id"                                              // Unique identifier of the user.
	ChangesName                                        fields.Field = "user.changes.name"                                            // Short name or login of the user.
	ChangesRiskCalculatedLevel                         fields.Field = "user.changes.risk.calculated_level"                           // A risk classification level calculated by an internal system as part of entity analytics and entity risk scoring.
	ChangesRiskCalculatedScore                         fields.Field = "user.changes.risk.calculated_score"                           // A risk classification score calculated by an internal system as part of entity analytics and entity risk scoring.
	ChangesRiskCalculatedScoreNorm                     fields.Field = "user.changes.risk.calculated_score_norm"                      // A normalized risk score calculated by an internal system.
	ChangesRiskStaticLevel                             fields.Field = "user.changes.risk.static_level"                               // A risk classification level obtained from outside the system, such as from some external Threat Intelligence Platform.
	ChangesRiskStaticScore                             fields.Field = "user.changes.risk.static_score"                               // A risk classification score obtained from outside the system, such as from some external Threat Intelligence Platform.
	ChangesRiskStaticScoreNorm                         fields.Field = "user.changes.risk.static_score_norm"                          // A normalized risk score calculated by an external system.
	ChangesRoles                                       fields.Field = "user.changes.roles"                                           // Array of user roles at the time of the event.
	Domain                                             fields.Field = "user.domain"                                                  // Name of the directory the user is a member of.
	EffectiveDomain                                    fields.Field = "user.effective.domain"                                        // Name of the directory the user is a member of.
	EffectiveEmail                                     fields.Field = "user.effective.email"                                         // User email address.
	EffectiveEntityAttributesKnownRedirects            fields.Field = "user.effective.entity.attributes.known_redirects"             // Known redirect URIs or URLs associated with this entity.
	EffectiveEntityAttributesManaged                   fields.Field = "user.effective.entity.attributes.managed"                     // Indicates whether the entity is managed by an external system.
	EffectiveEntityAttributesMfaEnabled                fields.Field = "user.effective.entity.attributes.mfa_enabled"                 // Indicates whether multi-factor authentication is enabled for this entity.
	EffectiveEntityAttributesOauthConsentRestriction   fields.Field = "user.effective.entity.attributes.oauth_consent_restriction"   // Restriction applied to OAuth consent for this entity.
	EffectiveEntityAttributesPermissions               fields.Field = "user.effective.entity.attributes.permissions"                 // Action-level permissions associated with this entity.
	EffectiveEntityAttributesStorageClass              fields.Field = "user.effective.entity.attributes.storage_class"               // Storage tier or class assigned to an object storage resource.
	EffectiveEntityBehavior                            fields.Field = "user.effective.entity.behavior"                               // A set of ephemeral characteristics of the entity, derived from observed behaviors during a specific time period.
	EffectiveEntityDisplayName                         fields.Field = "user.effective.entity.display_name"                           // An optional field used when a pretty name is desired for entity-centric operations.
	EffectiveEntityID                                  fields.Field = "user.effective.entity.id"                                     // Unique identifier for the entity.
	EffectiveEntityLastSeenTimestamp                   fields.Field = "user.effective.entity.last_seen_timestamp"                    // Indicates the date/time when this entity was last "seen."
	EffectiveEntityLifecycleLastActivity               fields.Field = "user.effective.entity.lifecycle.last_activity"                // Timestamp of the most recent action performed by or attributed to this entity.
	EffectiveEntityMetrics                             fields.Field = "user.effective.entity.metrics"                                // Field set for any fields containing numeric entity metrics.
	EffectiveEntityName                                fields.Field = "user.effective.entity.name"                                   // The name of the entity.
	EffectiveEntityRaw                                 fields.Field = "user.effective.entity.raw"                                    // Original, unmodified fields from the source system.
	EffectiveEntityReference                           fields.Field = "user.effective.entity.reference"                              // A URI, URL, or other direct reference to access or locate the entity.
	EffectiveEntityRelationshipsAdministersDomain      fields.Field = "user.effective.entity.relationships.administers.user.domain"  // Referenced user directory or AD/LDAP domain names.
	EffectiveEntityRelationshipsAdministersEmail       fields.Field = "user.effective.entity.relationships.administers.user.email"   // Referenced user email addresses.
	EffectiveEntityRelationshipsAdministersEntityID    fields.Field = "user.effective.entity.relationships.administers.entity.id"    // Identifiers of referenced entities.
	EffectiveEntityRelationshipsAdministersHostID      fields.Field = "user.effective.entity.relationships.administers.host.id"      // Referenced host ids.
	EffectiveEntityRelationshipsAdministersHostName    fields.Field = "user.effective.entity.relationships.administers.host.name"    // Referenced host names.
	EffectiveEntityRelationshipsAdministersID          fields.Field = "user.effective.entity.relationships.administers.user.id"      // Referenced user ids.
	EffectiveEntityRelationshipsAdministersName        fields.Field = "user.effective.entity.relationships.administers.user.name"    // Referenced user short names or logins.
	EffectiveEntityRelationshipsAdministersServiceID   fields.Field = "user.effective.entity.relationships.administers.service.id"   // Referenced service ids.
	EffectiveEntityRelationshipsAdministersServiceName fields.Field = "user.effective.entity.relationships.administers.service.name" // Referenced service names.
	EffectiveEntityRelationshipsDependsOnDomain        fields.Field = "user.effective.entity.relationships.depends_on.user.domain"   // Referenced user directory or AD/LDAP domain names.
	EffectiveEntityRelationshipsDependsOnEmail         fields.Field = "user.effective.entity.relationships.depends_on.user.email"    // Referenced user email addresses.
	EffectiveEntityRelationshipsDependsOnEntityID      fields.Field = "user.effective.entity.relationships.depends_on.entity.id"     // Identifiers of referenced entities.
	EffectiveEntityRelationshipsDependsOnHostID        fields.Field = "user.effective.entity.relationships.depends_on.host.id"       // Referenced host ids.
	EffectiveEntityRelationshipsDependsOnHostName      fields.Field = "user.effective.entity.relationships.depends_on.host.name"     // Referenced host names.
	EffectiveEntityRelationshipsDependsOnID            fields.Field = "user.effective.entity.relationships.depends_on.user.id"       // Referenced user ids.
	EffectiveEntityRelationshipsDependsOnName          fields.Field = "user.effective.entity.relationships.depends_on.user.name"     // Referenced user short names or logins.
	EffectiveEntityRelationshipsDependsOnServiceID     fields.Field = "user.effective.entity.relationships.depends_on.service.id"    // Referenced service ids.
	EffectiveEntityRelationshipsDependsOnServiceName   fields.Field = "user.effective.entity.relationships.depends_on.service.name"  // Referenced service names.
	EffectiveEntityRelationshipsOwnsDomain             fields.Field = "user.effective.entity.relationships.owns.user.domain"         // Referenced user directory or AD/LDAP domain names.
	EffectiveEntityRelationshipsOwnsEmail              fields.Field = "user.effective.entity.relationships.owns.user.email"          // Referenced user email addresses.
	EffectiveEntityRelationshipsOwnsEntityID           fields.Field = "user.effective.entity.relationships.owns.entity.id"           // Identifiers of referenced entities.
	EffectiveEntityRelationshipsOwnsHostID             fields.Field = "user.effective.entity.relationships.owns.host.id"             // Referenced host ids.
	EffectiveEntityRelationshipsOwnsHostName           fields.Field = "user.effective.entity.relationships.owns.host.name"           // Referenced host names.
	EffectiveEntityRelationshipsOwnsID                 fields.Field = "user.effective.entity.relationships.owns.user.id"             // Referenced user ids.
	EffectiveEntityRelationshipsOwnsName               fields.Field = "user.effective.entity.relationships.owns.user.name"           // Referenced user short names or logins.
	EffectiveEntityRelationshipsOwnsServiceID          fields.Field = "user.effective.entity.relationships.owns.service.id"          // Referenced service ids.
	EffectiveEntityRelationshipsOwnsServiceName        fields.Field = "user.effective.entity.relationships.owns.service.name"        // Referenced service names.
	EffectiveEntityRelationshipsSupervisesDomain       fields.Field = "user.effective.entity.relationships.supervises.user.domain"   // Referenced user directory or AD/LDAP domain names.
	EffectiveEntityRelationshipsSupervisesEmail        fields.Field = "user.effective.entity.relationships.supervises.user.email"    // Referenced user email addresses.
	EffectiveEntityRelationshipsSupervisesEntityID     fields.Field = "user.effective.entity.relationships.supervises.entity.id"     // Identifiers of referenced entities.
	EffectiveEntityRelationshipsSupervisesHostID       fields.Field = "user.effective.entity.relationships.supervises.host.id"       // Referenced host ids.
	EffectiveEntityRelationshipsSupervisesHostName     fields.Field = "user.effective.entity.relationships.supervises.host.name"     // Referenced host names.
	EffectiveEntityRelationshipsSupervisesID           fields.Field = "user.effective.entity.relationships.supervises.user.id"       // Referenced user ids.
	EffectiveEntityRelationshipsSupervisesName         fields.Field = "user.effective.entity.relationships.supervises.user.name"     // Referenced user short names or logins.
	EffectiveEntityRelationshipsSupervisesServiceID    fields.Field = "user.effective.entity.relationships.supervises.service.id"    // Referenced service ids.
	EffectiveEntityRelationshipsSupervisesServiceName  fields.Field = "user.effective.entity.relationships.supervises.service.name"  // Referenced service names.
	EffectiveEntitySource                              fields.Field = "user.effective.entity.source"                                 // Source module or integration that provided the entity data.
	EffectiveEntitySubType                             fields.Field = "user.effective.entity.sub_type"                               // The specific type designation for the entity as defined by its provider or system.
	EffectiveEntityType                                fields.Field = "user.effective.entity.type"                                   // Standardized high-level classification of the entity.
	EffectiveFullName                                  fields.Field = "user.effective.full_name"                                     // User's full name, if available.
	EffectiveGroupDomain                               fields.Field = "user.effective.group.domain"                                  // Name of the directory the group is a member of.
	EffectiveGroupID                                   fields.Field = "user.effective.group.id"                                      // Unique identifier for the group on the system/platform.
	EffectiveGroupName                                 fields.Field = "user.effective.group.name"                                    // Name of the group.
	EffectiveHash                                      fields.Field = "user.effective.hash"                                          // Unique user hash to correlate information for a user in anonymized form.
	EffectiveID                                        fields.Field = "user.effective.id"                                            // Unique identifier of the user.
	EffectiveName                                      fields.Field = "user.effective.name"                                          // Short name or login of the user.
	EffectiveRiskCalculatedLevel                       fields.Field = "user.effective.risk.calculated_level"                         // A risk classification level calculated by an internal system as part of entity analytics and entity risk scoring.
	EffectiveRiskCalculatedScore                       fields.Field = "user.effective.risk.calculated_score"                         // A risk classification score calculated by an internal system as part of entity analytics and entity risk scoring.
	EffectiveRiskCalculatedScoreNorm                   fields.Field = "user.effective.risk.calculated_score_norm"                    // A normalized risk score calculated by an internal system.
	EffectiveRiskStaticLevel                           fields.Field = "user.effective.risk.static_level"                             // A risk classification level obtained from outside the system, such as from some external Threat Intelligence Platform.
	EffectiveRiskStaticScore                           fields.Field = "user.effective.risk.static_score"                             // A risk classification score obtained from outside the system, such as from some external Threat Intelligence Platform.
	EffectiveRiskStaticScoreNorm                       fields.Field = "user.effective.risk.static_score_norm"                        // A normalized risk score calculated by an external system.
	EffectiveRoles                                     fields.Field = "user.effective.roles"                                         // Array of user roles at the time of the event.
	Email                                              fields.Field = "user.email"                                                   // User email address.
	EntityAttributesKnownRedirects                     fields.Field = "user.entity.attributes.known_redirects"                       // Known redirect URIs or URLs associated with this entity.
	EntityAttributesManaged                            fields.Field = "user.entity.attributes.managed"                               // Indicates whether the entity is managed by an external system.
	EntityAttributesMfaEnabled                         fields.Field = "user.entity.attributes.mfa_enabled"                           // Indicates whether multi-factor authentication is enabled for this entity.
	EntityAttributesOauthConsentRestriction            fields.Field = "user.entity.attributes.oauth_consent_restriction"             // Restriction applied to OAuth consent for this entity.
	EntityAttributesPermissions                        fields.Field = "user.entity.attributes.permissions"                           // Action-level permissions associated with this entity.
	EntityAttributesStorageClass                       fields.Field = "user.entity.attributes.storage_class"                         // Storage tier or class assigned to an object storage resource.
	EntityBehavior                                     fields.Field = "user.entity.behavior"                                         // A set of ephemeral characteristics of the entity, derived from observed behaviors during a specific time period.
	EntityDisplayName                                  fields.Field = "user.entity.display_name"                                     // An optional field used when a pretty name is desired for entity-centric operations.
	EntityID                                           fields.Field = "user.entity.id"                                               // Unique identifier for the entity.
	EntityLastSeenTimestamp                            fields.Field = "user.entity.last_seen_timestamp"                              // Indicates the date/time when this entity was last "seen."
	EntityLifecycleLastActivity                        fields.Field = "user.entity.lifecycle.last_activity"                          // Timestamp of the most recent action performed by or attributed to this entity.
	EntityMetrics                                      fields.Field = "user.entity.metrics"                                          // Field set for any fields containing numeric entity metrics.
	EntityName                                         fields.Field = "user.entity.name"                                             // The name of the entity.
	EntityRaw                                          fields.Field = "user.entity.raw"                                              // Original, unmodified fields from the source system.
	EntityReference                                    fields.Field = "user.entity.reference"                                        // A URI, URL, or other direct reference to access or locate the entity.
	EntityRelationshipsAdministersDomain               fields.Field = "user.entity.relationships.administers.user.domain"            // Referenced user directory or AD/LDAP domain names.
	EntityRelationshipsAdministersEmail                fields.Field = "user.entity.relationships.administers.user.email"             // Referenced user email addresses.
	EntityRelationshipsAdministersEntityID             fields.Field = "user.entity.relationships.administers.entity.id"              // Identifiers of referenced entities.
	EntityRelationshipsAdministersHostID               fields.Field = "user.entity.relationships.administers.host.id"                // Referenced host ids.
	EntityRelationshipsAdministersHostName             fields.Field = "user.entity.relationships.administers.host.name"              // Referenced host names.
	EntityRelationshipsAdministersID                   fields.Field = "user.entity.relationships.administers.user.id"                // Referenced user ids.
	EntityRelationshipsAdministersName                 fields.Field = "user.entity.relationships.administers.user.name"              // Referenced user short names or logins.
	EntityRelationshipsAdministersServiceID            fields.Field = "user.entity.relationships.administers.service.id"             // Referenced service ids.
	EntityRelationshipsAdministersServiceName          fields.Field = "user.entity.relationships.administers.service.name"           // Referenced service names.
	EntityRelationshipsDependsOnDomain                 fields.Field = "user.entity.relationships.depends_on.user.domain"             // Referenced user directory or AD/LDAP domain names.
	EntityRelationshipsDependsOnEmail                  fields.Field = "user.entity.relationships.depends_on.user.email"              // Referenced user email addresses.
	EntityRelationshipsDependsOnEntityID               fields.Field = "user.entity.relationships.depends_on.entity.id"               // Identifiers of referenced entities.
	EntityRelationshipsDependsOnHostID                 fields.Field = "user.entity.relationships.depends_on.host.id"                 // Referenced host ids.
	EntityRelationshipsDependsOnHostName               fields.Field = "user.entity.relationships.depends_on.host.name"               // Referenced host names.
	EntityRelationshipsDependsOnID                     fields.Field = "user.entity.relationships.depends_on.user.id"                 // Referenced user ids.
	EntityRelationshipsDependsOnName                   fields.Field = "user.entity.relationships.depends_on.user.name"               // Referenced user short names or logins.
	EntityRelationshipsDependsOnServiceID              fields.Field = "user.entity.relationships.depends_on.service.id"              // Referenced service ids.
	EntityRelationshipsDependsOnServiceName            fields.Field = "user.entity.relationships.depends_on.service.name"            // Referenced service names.
	EntityRelationshipsOwnsDomain                      fields.Field = "user.entity.relationships.owns.user.domain"                   // Referenced user directory or AD/LDAP domain names.
	EntityRelationshipsOwnsEmail                       fields.Field = "user.entity.relationships.owns.user.email"                    // Referenced user email addresses.
	EntityRelationshipsOwnsEntityID                    fields.Field = "user.entity.relationships.owns.entity.id"                     // Identifiers of referenced entities.
	EntityRelationshipsOwnsHostID                      fields.Field = "user.entity.relationships.owns.host.id"                       // Referenced host ids.
	EntityRelationshipsOwnsHostName                    fields.Field = "user.entity.relationships.owns.host.name"                     // Referenced host names.
	EntityRelationshipsOwnsID                          fields.Field = "user.entity.relationships.owns.user.id"                       // Referenced user ids.
	EntityRelationshipsOwnsName                        fields.Field = "user.entity.relationships.owns.user.name"                     // Referenced user short names or logins.
	EntityRelationshipsOwnsServiceID                   fields.Field = "user.entity.relationships.owns.service.id"                    // Referenced service ids.
	EntityRelationshipsOwnsServiceName                 fields.Field = "user.entity.relationships.owns.service.name"                  // Referenced service names.
	EntityRelationshipsSupervisesDomain                fields.Field = "user.entity.relationships.supervises.user.domain"             // Referenced user directory or AD/LDAP domain names.
	EntityRelationshipsSupervisesEmail                 fields.Field = "user.entity.relationships.supervises.user.email"              // Referenced user email addresses.
	EntityRelationshipsSupervisesEntityID              fields.Field = "user.entity.relationships.supervises.entity.id"               // Identifiers of referenced entities.
	EntityRelationshipsSupervisesHostID                fields.Field = "user.entity.relationships.supervises.host.id"                 // Referenced host ids.
	EntityRelationshipsSupervisesHostName              fields.Field = "user.entity.relationships.supervises.host.name"               // Referenced host names.
	EntityRelationshipsSupervisesID                    fields.Field = "user.entity.relationships.supervises.user.id"                 // Referenced user ids.
	EntityRelationshipsSupervisesName                  fields.Field = "user.entity.relationships.supervises.user.name"               // Referenced user short names or logins.
	EntityRelationshipsSupervisesServiceID             fields.Field = "user.entity.relationships.supervises.service.id"              // Referenced service ids.
	EntityRelationshipsSupervisesServiceName           fields.Field = "user.entity.relationships.supervises.service.name"            // Referenced service names.
	EntitySource                                       fields.Field = "user.entity.source"                                           // Source module or integration that provided the entity data.
	EntitySubType                                      fields.Field = "user.entity.sub_type"                                         // The specific type designation for the entity as defined by its provider or system.
	EntityType                                         fields.Field = "user.entity.type"                                             // Standardized high-level classification of the entity.
	FullName                                           fields.Field = "user.full_name"                                               // User's full name, if available.
	GroupDomain                                        fields.Field = "user.group.domain"                                            // Name of the directory the group is a member of.
	GroupID                                            fields.Field = "user.group.id"                                                // Unique identifier for the group on the system/platform.
	GroupName                                          fields.Field = "user.group.name"                                              // Name of the group.
	Hash                                               fields.Field = "user.hash"                                                    // Unique user hash to correlate information for a user in anonymized form.
	ID                                                 fields.Field = "user.id"                                                      // Unique identifier of the user.
	Name                                               fields.Field = "user.name"                                                    // Short name or login of the user.
	RiskCalculatedLevel                                fields.Field = "user.risk.calculated_level"                                   // A risk classification level calculated by an internal system as part of entity analytics and entity risk scoring.
	RiskCalculatedScore                                fields.Field = "user.risk.calculated_score"                                   // A risk classification score calculated by an internal system as part of entity analytics and entity risk scoring.
	RiskCalculatedScoreNorm                            fields.Field = "user.risk.calculated_score_norm"                              // A normalized risk score calculated by an internal system.
	RiskStaticLevel                                    fields.Field = "user.risk.static_level"                                       // A risk classification level obtained from outside the system, such as from some external Threat Intelligence Platform.
	RiskStaticScore                                    fields.Field = "user.risk.static_score"                                       // A risk classification score obtained from outside the system, such as from some external Threat Intelligence Platform.
	RiskStaticScoreNorm                                fields.Field = "user.risk.static_score_norm"                                  // A normalized risk score calculated by an external system.
	Roles                                              fields.Field = "user.roles"                                                   // Array of user roles at the time of the event.
	TargetDomain                                       fields.Field = "user.target.domain"                                           // Name of the directory the user is a member of.
	TargetEmail                                        fields.Field = "user.target.email"                                            // User email address.
	TargetEntityAttributesKnownRedirects               fields.Field = "user.target.entity.attributes.known_redirects"                // Known redirect URIs or URLs associated with this entity.
	TargetEntityAttributesManaged                      fields.Field = "user.target.entity.attributes.managed"                        // Indicates whether the entity is managed by an external system.
	TargetEntityAttributesMfaEnabled                   fields.Field = "user.target.entity.attributes.mfa_enabled"                    // Indicates whether multi-factor authentication is enabled for this entity.
	TargetEntityAttributesOauthConsentRestriction      fields.Field = "user.target.entity.attributes.oauth_consent_restriction"      // Restriction applied to OAuth consent for this entity.
	TargetEntityAttributesPermissions                  fields.Field = "user.target.entity.attributes.permissions"                    // Action-level permissions associated with this entity.
	TargetEntityAttributesStorageClass                 fields.Field = "user.target.entity.attributes.storage_class"                  // Storage tier or class assigned to an object storage resource.
	TargetEntityBehavior                               fields.Field = "user.target.entity.behavior"                                  // A set of ephemeral characteristics of the entity, derived from observed behaviors during a specific time period.
	TargetEntityDisplayName                            fields.Field = "user.target.entity.display_name"                              // An optional field used when a pretty name is desired for entity-centric operations.
	TargetEntityID                                     fields.Field = "user.target.entity.id"                                        // Unique identifier for the entity.
	TargetEntityLastSeenTimestamp                      fields.Field = "user.target.entity.last_seen_timestamp"                       // Indicates the date/time when this entity was last "seen."
	TargetEntityLifecycleLastActivity                  fields.Field = "user.target.entity.lifecycle.last_activity"                   // Timestamp of the most recent action performed by or attributed to this entity.
	TargetEntityMetrics                                fields.Field = "user.target.entity.metrics"                                   // Field set for any fields containing numeric entity metrics.
	TargetEntityName                                   fields.Field = "user.target.entity.name"                                      // The name of the entity.
	TargetEntityRaw                                    fields.Field = "user.target.entity.raw"                                       // Original, unmodified fields from the source system.
	TargetEntityReference                              fields.Field = "user.target.entity.reference"                                 // A URI, URL, or other direct reference to access or locate the entity.
	TargetEntityRelationshipsAdministersDomain         fields.Field = "user.target.entity.relationships.administers.user.domain"     // Referenced user directory or AD/LDAP domain names.
	TargetEntityRelationshipsAdministersEmail          fields.Field = "user.target.entity.relationships.administers.user.email"      // Referenced user email addresses.
	TargetEntityRelationshipsAdministersEntityID       fields.Field = "user.target.entity.relationships.administers.entity.id"       // Identifiers of referenced entities.
	TargetEntityRelationshipsAdministersHostID         fields.Field = "user.target.entity.relationships.administers.host.id"         // Referenced host ids.
	TargetEntityRelationshipsAdministersHostName       fields.Field = "user.target.entity.relationships.administers.host.name"       // Referenced host names.
	TargetEntityRelationshipsAdministersID             fields.Field = "user.target.entity.relationships.administers.user.id"         // Referenced user ids.
	TargetEntityRelationshipsAdministersName           fields.Field = "user.target.entity.relationships.administers.user.name"       // Referenced user short names or logins.
	TargetEntityRelationshipsAdministersServiceID      fields.Field = "user.target.entity.relationships.administers.service.id"      // Referenced service ids.
	TargetEntityRelationshipsAdministersServiceName    fields.Field = "user.target.entity.relationships.administers.service.name"    // Referenced service names.
	TargetEntityRelationshipsDependsOnDomain           fields.Field = "user.target.entity.relationships.depends_on.user.domain"      // Referenced user directory or AD/LDAP domain names.
	TargetEntityRelationshipsDependsOnEmail            fields.Field = "user.target.entity.relationships.depends_on.user.email"       // Referenced user email addresses.
	TargetEntityRelationshipsDependsOnEntityID         fields.Field = "user.target.entity.relationships.depends_on.entity.id"        // Identifiers of referenced entities.
	TargetEntityRelationshipsDependsOnHostID           fields.Field = "user.target.entity.relationships.depends_on.host.id"          // Referenced host ids.
	TargetEntityRelationshipsDependsOnHostName         fields.Field = "user.target.entity.relationships.depends_on.host.name"        // Referenced host names.
	TargetEntityRelationshipsDependsOnID               fields.Field = "user.target.entity.relationships.depends_on.user.id"          // Referenced user ids.
	TargetEntityRelationshipsDependsOnName             fields.Field = "user.target.entity.relationships.depends_on.user.name"        // Referenced user short names or logins.
	TargetEntityRelationshipsDependsOnServiceID        fields.Field = "user.target.entity.relationships.depends_on.service.id"       // Referenced service ids.
	TargetEntityRelationshipsDependsOnServiceName      fields.Field = "user.target.entity.relationships.depends_on.service.name"     // Referenced service names.
	TargetEntityRelationshipsOwnsDomain                fields.Field = "user.target.entity.relationships.owns.user.domain"            // Referenced user directory or AD/LDAP domain names.
	TargetEntityRelationshipsOwnsEmail                 fields.Field = "user.target.entity.relationships.owns.user.email"             // Referenced user email addresses.
	TargetEntityRelationshipsOwnsEntityID              fields.Field = "user.target.entity.relationships.owns.entity.id"              // Identifiers of referenced entities.
	TargetEntityRelationshipsOwnsHostID                fields.Field = "user.target.entity.relationships.owns.host.id"                // Referenced host ids.
	TargetEntityRelationshipsOwnsHostName              fields.Field = "user.target.entity.relationships.owns.host.name"              // Referenced host names.
	TargetEntityRelationshipsOwnsID                    fields.Field = "user.target.entity.relationships.owns.user.id"                // Referenced user ids.
	TargetEntityRelationshipsOwnsName                  fields.Field = "user.target.entity.relationships.owns.user.name"              // Referenced user short names or logins.
	TargetEntityRelationshipsOwnsServiceID             fields.Field = "user.target.entity.relationships.owns.service.id"             // Referenced service ids.
	TargetEntityRelationshipsOwnsServiceName           fields.Field = "user.target.entity.relationships.owns.service.name"           // Referenced service names.
	TargetEntityRelationshipsSupervisesDomain          fields.Field = "user.target.entity.relationships.supervises.user.domain"      // Referenced user directory or AD/LDAP domain names.
	TargetEntityRelationshipsSupervisesEmail           fields.Field = "user.target.entity.relationships.supervises.user.email"       // Referenced user email addresses.
	TargetEntityRelationshipsSupervisesEntityID        fields.Field = "user.target.entity.relationships.supervises.entity.id"        // Identifiers of referenced entities.
	TargetEntityRelationshipsSupervisesHostID          fields.Field = "user.target.entity.relationships.supervises.host.id"          // Referenced host ids.
	TargetEntityRelationshipsSupervisesHostName        fields.Field = "user.target.entity.relationships.supervises.host.name"        // Referenced host names.
	TargetEntityRelationshipsSupervisesID              fields.Field = "user.target.entity.relationships.supervises.user.id"          // Referenced user ids.
	TargetEntityRelationshipsSupervisesName            fields.Field = "user.target.entity.relationships.supervises.user.name"        // Referenced user short names or logins.
	TargetEntityRelationshipsSupervisesServiceID       fields.Field = "user.target.entity.relationships.supervises.service.id"       // Referenced service ids.
	TargetEntityRelationshipsSupervisesServiceName     fields.Field = "user.target.entity.relationships.supervises.service.name"     // Referenced service names.
	TargetEntitySource                                 fields.Field = "user.target.entity.source"                                    // Source module or integration that provided the entity data.
	TargetEntitySubType                                fields.Field = "user.target.entity.sub_type"                                  // The specific type designation for the entity as defined by its provider or system.
	TargetEntityType                                   fields.Field = "user.target.entity.type"                                      // Standardized high-level classification of the entity.
	TargetFullName                                     fields.Field = "user.target.full_name"                                        // User's full name, if available.
	TargetGroupDomain                                  fields.Field = "user.target.group.domain"                                     // Name of the directory the group is a member of.
	TargetGroupID                                      fields.Field = "user.target.group.id"                                         // Unique identifier for the group on the system/platform.
	TargetGroupName                                    fields.Field = "user.target.group.name"                                       // Name of the group.
	TargetHash                                         fields.Field = "user.target.hash"                                             // Unique user hash to correlate information for a user in anonymized form.
	TargetID                                           fields.Field = "user.target.id"                                               // Unique identifier of the user.
	TargetName                                         fields.Field = "user.target.name"                                             // Short name or login of the user.
	TargetRiskCalculatedLevel                          fields.Field = "user.target.risk.calculated_level"                            // A risk classification level calculated by an internal system as part of entity analytics and entity risk scoring.
	TargetRiskCalculatedScore                          fields.Field = "user.target.risk.calculated_score"                            // A risk classification score calculated by an internal system as part of entity analytics and entity risk scoring.
	TargetRiskCalculatedScoreNorm                      fields.Field = "user.target.risk.calculated_score_norm"                       // A normalized risk score calculated by an internal system.
	TargetRiskStaticLevel                              fields.Field = "user.target.risk.static_level"                                // A risk classification level obtained from outside the system, such as from some external Threat Intelligence Platform.
	TargetRiskStaticScore                              fields.Field = "user.target.risk.static_score"                                // A risk classification score obtained from outside the system, such as from some external Threat Intelligence Platform.
	TargetRiskStaticScoreNorm                          fields.Field = "user.target.risk.static_score_norm"                           // A normalized risk score calculated by an external system.
	TargetRoles                                        fields.Field = "user.target.roles"                                            // Array of user roles at the time of the event.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	ChangesDomain,
	ChangesEmail,
	ChangesEntityAttributesKnownRedirects,
	ChangesEntityAttributesManaged,
	ChangesEntityAttributesMfaEnabled,
	ChangesEntityAttributesOauthConsentRestriction,
	ChangesEntityAttributesPermissions,
	ChangesEntityAttributesStorageClass,
	ChangesEntityBehavior,
	ChangesEntityDisplayName,
	ChangesEntityID,
	ChangesEntityLastSeenTimestamp,
	ChangesEntityLifecycleLastActivity,
	ChangesEntityMetrics,
	ChangesEntityName,
	ChangesEntityRaw,
	ChangesEntityReference,
	ChangesEntityRelationshipsAdministersDomain,
	ChangesEntityRelationshipsAdministersEmail,
	ChangesEntityRelationshipsAdministersEntityID,
	ChangesEntityRelationshipsAdministersHostID,
	ChangesEntityRelationshipsAdministersHostName,
	ChangesEntityRelationshipsAdministersID,
	ChangesEntityRelationshipsAdministersName,
	ChangesEntityRelationshipsAdministersServiceID,
	ChangesEntityRelationshipsAdministersServiceName,
	ChangesEntityRelationshipsDependsOnDomain,
	ChangesEntityRelationshipsDependsOnEmail,
	ChangesEntityRelationshipsDependsOnEntityID,
	ChangesEntityRelationshipsDependsOnHostID,
	ChangesEntityRelationshipsDependsOnHostName,
	ChangesEntityRelationshipsDependsOnID,
	ChangesEntityRelationshipsDependsOnName,
	ChangesEntityRelationshipsDependsOnServiceID,
	ChangesEntityRelationshipsDependsOnServiceName,
	ChangesEntityRelationshipsOwnsDomain,
	ChangesEntityRelationshipsOwnsEmail,
	ChangesEntityRelationshipsOwnsEntityID,
	ChangesEntityRelationshipsOwnsHostID,
	ChangesEntityRelationshipsOwnsHostName,
	ChangesEntityRelationshipsOwnsID,
	ChangesEntityRelationshipsOwnsName,
	ChangesEntityRelationshipsOwnsServiceID,
	ChangesEntityRelationshipsOwnsServiceName,
	ChangesEntityRelationshipsSupervisesDomain,
	ChangesEntityRelationshipsSupervisesEmail,
	ChangesEntityRelationshipsSupervisesEntityID,
	ChangesEntityRelationshipsSupervisesHostID,
	ChangesEntityRelationshipsSupervisesHostName,
	ChangesEntityRelationshipsSupervisesID,
	ChangesEntityRelationshipsSupervisesName,
	ChangesEntityRelationshipsSupervisesServiceID,
	ChangesEntityRelationshipsSupervisesServiceName,
	ChangesEntitySource,
	ChangesEntitySubType,
	ChangesEntityType,
	ChangesFullName,
	ChangesGroupDomain,
	ChangesGroupID,
	ChangesGroupName,
	ChangesHash,
	ChangesID,
	ChangesName,
	ChangesRiskCalculatedLevel,
	ChangesRiskCalculatedScore,
	ChangesRiskCalculatedScoreNorm,
	ChangesRiskStaticLevel,
	ChangesRiskStaticScore,
	ChangesRiskStaticScoreNorm,
	ChangesRoles,
	Domain,
	EffectiveDomain,
	EffectiveEmail,
	EffectiveEntityAttributesKnownRedirects,
	EffectiveEntityAttributesManaged,
	EffectiveEntityAttributesMfaEnabled,
	EffectiveEntityAttributesOauthConsentRestriction,
	EffectiveEntityAttributesPermissions,
	EffectiveEntityAttributesStorageClass,
	EffectiveEntityBehavior,
	EffectiveEntityDisplayName,
	EffectiveEntityID,
	EffectiveEntityLastSeenTimestamp,
	EffectiveEntityLifecycleLastActivity,
	EffectiveEntityMetrics,
	EffectiveEntityName,
	EffectiveEntityRaw,
	EffectiveEntityReference,
	EffectiveEntityRelationshipsAdministersDomain,
	EffectiveEntityRelationshipsAdministersEmail,
	EffectiveEntityRelationshipsAdministersEntityID,
	EffectiveEntityRelationshipsAdministersHostID,
	EffectiveEntityRelationshipsAdministersHostName,
	EffectiveEntityRelationshipsAdministersID,
	EffectiveEntityRelationshipsAdministersName,
	EffectiveEntityRelationshipsAdministersServiceID,
	EffectiveEntityRelationshipsAdministersServiceName,
	EffectiveEntityRelationshipsDependsOnDomain,
	EffectiveEntityRelationshipsDependsOnEmail,
	EffectiveEntityRelationshipsDependsOnEntityID,
	EffectiveEntityRelationshipsDependsOnHostID,
	EffectiveEntityRelationshipsDependsOnHostName,
	EffectiveEntityRelationshipsDependsOnID,
	EffectiveEntityRelationshipsDependsOnName,
	EffectiveEntityRelationshipsDependsOnServiceID,
	EffectiveEntityRelationshipsDependsOnServiceName,
	EffectiveEntityRelationshipsOwnsDomain,
	EffectiveEntityRelationshipsOwnsEmail,
	EffectiveEntityRelationshipsOwnsEntityID,
	EffectiveEntityRelationshipsOwnsHostID,
	EffectiveEntityRelationshipsOwnsHostName,
	EffectiveEntityRelationshipsOwnsID,
	EffectiveEntityRelationshipsOwnsName,
	EffectiveEntityRelationshipsOwnsServiceID,
	EffectiveEntityRelationshipsOwnsServiceName,
	EffectiveEntityRelationshipsSupervisesDomain,
	EffectiveEntityRelationshipsSupervisesEmail,
	EffectiveEntityRelationshipsSupervisesEntityID,
	EffectiveEntityRelationshipsSupervisesHostID,
	EffectiveEntityRelationshipsSupervisesHostName,
	EffectiveEntityRelationshipsSupervisesID,
	EffectiveEntityRelationshipsSupervisesName,
	EffectiveEntityRelationshipsSupervisesServiceID,
	EffectiveEntityRelationshipsSupervisesServiceName,
	EffectiveEntitySource,
	EffectiveEntitySubType,
	EffectiveEntityType,
	EffectiveFullName,
	EffectiveGroupDomain,
	EffectiveGroupID,
	EffectiveGroupName,
	EffectiveHash,
	EffectiveID,
	EffectiveName,
	EffectiveRiskCalculatedLevel,
	EffectiveRiskCalculatedScore,
	EffectiveRiskCalculatedScoreNorm,
	EffectiveRiskStaticLevel,
	EffectiveRiskStaticScore,
	EffectiveRiskStaticScoreNorm,
	EffectiveRoles,
	Email,
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
	EntityRelationshipsAdministersDomain,
	EntityRelationshipsAdministersEmail,
	EntityRelationshipsAdministersEntityID,
	EntityRelationshipsAdministersHostID,
	EntityRelationshipsAdministersHostName,
	EntityRelationshipsAdministersID,
	EntityRelationshipsAdministersName,
	EntityRelationshipsAdministersServiceID,
	EntityRelationshipsAdministersServiceName,
	EntityRelationshipsDependsOnDomain,
	EntityRelationshipsDependsOnEmail,
	EntityRelationshipsDependsOnEntityID,
	EntityRelationshipsDependsOnHostID,
	EntityRelationshipsDependsOnHostName,
	EntityRelationshipsDependsOnID,
	EntityRelationshipsDependsOnName,
	EntityRelationshipsDependsOnServiceID,
	EntityRelationshipsDependsOnServiceName,
	EntityRelationshipsOwnsDomain,
	EntityRelationshipsOwnsEmail,
	EntityRelationshipsOwnsEntityID,
	EntityRelationshipsOwnsHostID,
	EntityRelationshipsOwnsHostName,
	EntityRelationshipsOwnsID,
	EntityRelationshipsOwnsName,
	EntityRelationshipsOwnsServiceID,
	EntityRelationshipsOwnsServiceName,
	EntityRelationshipsSupervisesDomain,
	EntityRelationshipsSupervisesEmail,
	EntityRelationshipsSupervisesEntityID,
	EntityRelationshipsSupervisesHostID,
	EntityRelationshipsSupervisesHostName,
	EntityRelationshipsSupervisesID,
	EntityRelationshipsSupervisesName,
	EntityRelationshipsSupervisesServiceID,
	EntityRelationshipsSupervisesServiceName,
	EntitySource,
	EntitySubType,
	EntityType,
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
	TargetEntityRelationshipsAdministersDomain,
	TargetEntityRelationshipsAdministersEmail,
	TargetEntityRelationshipsAdministersEntityID,
	TargetEntityRelationshipsAdministersHostID,
	TargetEntityRelationshipsAdministersHostName,
	TargetEntityRelationshipsAdministersID,
	TargetEntityRelationshipsAdministersName,
	TargetEntityRelationshipsAdministersServiceID,
	TargetEntityRelationshipsAdministersServiceName,
	TargetEntityRelationshipsDependsOnDomain,
	TargetEntityRelationshipsDependsOnEmail,
	TargetEntityRelationshipsDependsOnEntityID,
	TargetEntityRelationshipsDependsOnHostID,
	TargetEntityRelationshipsDependsOnHostName,
	TargetEntityRelationshipsDependsOnID,
	TargetEntityRelationshipsDependsOnName,
	TargetEntityRelationshipsDependsOnServiceID,
	TargetEntityRelationshipsDependsOnServiceName,
	TargetEntityRelationshipsOwnsDomain,
	TargetEntityRelationshipsOwnsEmail,
	TargetEntityRelationshipsOwnsEntityID,
	TargetEntityRelationshipsOwnsHostID,
	TargetEntityRelationshipsOwnsHostName,
	TargetEntityRelationshipsOwnsID,
	TargetEntityRelationshipsOwnsName,
	TargetEntityRelationshipsOwnsServiceID,
	TargetEntityRelationshipsOwnsServiceName,
	TargetEntityRelationshipsSupervisesDomain,
	TargetEntityRelationshipsSupervisesEmail,
	TargetEntityRelationshipsSupervisesEntityID,
	TargetEntityRelationshipsSupervisesHostID,
	TargetEntityRelationshipsSupervisesHostName,
	TargetEntityRelationshipsSupervisesID,
	TargetEntityRelationshipsSupervisesName,
	TargetEntityRelationshipsSupervisesServiceID,
	TargetEntityRelationshipsSupervisesServiceName,
	TargetEntitySource,
	TargetEntitySubType,
	TargetEntityType,
	TargetFullName,
	TargetGroupDomain,
	TargetGroupID,
	TargetGroupName,
	TargetHash,
	TargetID,
	TargetName,
	TargetRiskCalculatedLevel,
	TargetRiskCalculatedScore,
	TargetRiskCalculatedScoreNorm,
	TargetRiskStaticLevel,
	TargetRiskStaticScore,
	TargetRiskStaticScoreNorm,
	TargetRoles,
}

type ChangesEntityTypeAllowedType struct {
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

var ChangesEntityTypeAllowedValues ChangesEntityTypeAllowedType = ChangesEntityTypeAllowedType{
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

type EffectiveEntityTypeAllowedType struct {
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

var EffectiveEntityTypeAllowedValues EffectiveEntityTypeAllowedType = EffectiveEntityTypeAllowedType{
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
	ChangesDomain                                      fields.Keyword
	ChangesEmail                                       fields.Keyword
	ChangesEntityAttributesKnownRedirects              fields.Keyword
	ChangesEntityAttributesManaged                     fields.Boolean
	ChangesEntityAttributesMfaEnabled                  fields.Boolean
	ChangesEntityAttributesOauthConsentRestriction     fields.Keyword
	ChangesEntityAttributesPermissions                 fields.Keyword
	ChangesEntityAttributesStorageClass                fields.Keyword
	ChangesEntityBehavior                              fields.Object
	ChangesEntityDisplayName                           fields.Keyword
	ChangesEntityID                                    fields.Keyword
	ChangesEntityLastSeenTimestamp                     fields.Date
	ChangesEntityLifecycleLastActivity                 fields.Date
	ChangesEntityMetrics                               fields.Object
	ChangesEntityName                                  fields.Keyword
	ChangesEntityRaw                                   fields.Object
	ChangesEntityReference                             fields.Keyword
	ChangesEntityRelationshipsAdministersDomain        fields.Keyword
	ChangesEntityRelationshipsAdministersEmail         fields.Keyword
	ChangesEntityRelationshipsAdministersEntityID      fields.Keyword
	ChangesEntityRelationshipsAdministersHostID        fields.Keyword
	ChangesEntityRelationshipsAdministersHostName      fields.Keyword
	ChangesEntityRelationshipsAdministersID            fields.Keyword
	ChangesEntityRelationshipsAdministersName          fields.Keyword
	ChangesEntityRelationshipsAdministersServiceID     fields.Keyword
	ChangesEntityRelationshipsAdministersServiceName   fields.Keyword
	ChangesEntityRelationshipsDependsOnDomain          fields.Keyword
	ChangesEntityRelationshipsDependsOnEmail           fields.Keyword
	ChangesEntityRelationshipsDependsOnEntityID        fields.Keyword
	ChangesEntityRelationshipsDependsOnHostID          fields.Keyword
	ChangesEntityRelationshipsDependsOnHostName        fields.Keyword
	ChangesEntityRelationshipsDependsOnID              fields.Keyword
	ChangesEntityRelationshipsDependsOnName            fields.Keyword
	ChangesEntityRelationshipsDependsOnServiceID       fields.Keyword
	ChangesEntityRelationshipsDependsOnServiceName     fields.Keyword
	ChangesEntityRelationshipsOwnsDomain               fields.Keyword
	ChangesEntityRelationshipsOwnsEmail                fields.Keyword
	ChangesEntityRelationshipsOwnsEntityID             fields.Keyword
	ChangesEntityRelationshipsOwnsHostID               fields.Keyword
	ChangesEntityRelationshipsOwnsHostName             fields.Keyword
	ChangesEntityRelationshipsOwnsID                   fields.Keyword
	ChangesEntityRelationshipsOwnsName                 fields.Keyword
	ChangesEntityRelationshipsOwnsServiceID            fields.Keyword
	ChangesEntityRelationshipsOwnsServiceName          fields.Keyword
	ChangesEntityRelationshipsSupervisesDomain         fields.Keyword
	ChangesEntityRelationshipsSupervisesEmail          fields.Keyword
	ChangesEntityRelationshipsSupervisesEntityID       fields.Keyword
	ChangesEntityRelationshipsSupervisesHostID         fields.Keyword
	ChangesEntityRelationshipsSupervisesHostName       fields.Keyword
	ChangesEntityRelationshipsSupervisesID             fields.Keyword
	ChangesEntityRelationshipsSupervisesName           fields.Keyword
	ChangesEntityRelationshipsSupervisesServiceID      fields.Keyword
	ChangesEntityRelationshipsSupervisesServiceName    fields.Keyword
	ChangesEntitySource                                fields.Keyword
	ChangesEntitySubType                               fields.Keyword
	ChangesEntityType                                  fields.Keyword
	ChangesFullName                                    fields.Keyword
	ChangesGroupDomain                                 fields.Keyword
	ChangesGroupID                                     fields.Keyword
	ChangesGroupName                                   fields.Keyword
	ChangesHash                                        fields.Keyword
	ChangesID                                          fields.Keyword
	ChangesName                                        fields.Keyword
	ChangesRiskCalculatedLevel                         fields.Keyword
	ChangesRiskCalculatedScore                         fields.Float
	ChangesRiskCalculatedScoreNorm                     fields.Float
	ChangesRiskStaticLevel                             fields.Keyword
	ChangesRiskStaticScore                             fields.Float
	ChangesRiskStaticScoreNorm                         fields.Float
	ChangesRoles                                       fields.Keyword
	Domain                                             fields.Keyword
	EffectiveDomain                                    fields.Keyword
	EffectiveEmail                                     fields.Keyword
	EffectiveEntityAttributesKnownRedirects            fields.Keyword
	EffectiveEntityAttributesManaged                   fields.Boolean
	EffectiveEntityAttributesMfaEnabled                fields.Boolean
	EffectiveEntityAttributesOauthConsentRestriction   fields.Keyword
	EffectiveEntityAttributesPermissions               fields.Keyword
	EffectiveEntityAttributesStorageClass              fields.Keyword
	EffectiveEntityBehavior                            fields.Object
	EffectiveEntityDisplayName                         fields.Keyword
	EffectiveEntityID                                  fields.Keyword
	EffectiveEntityLastSeenTimestamp                   fields.Date
	EffectiveEntityLifecycleLastActivity               fields.Date
	EffectiveEntityMetrics                             fields.Object
	EffectiveEntityName                                fields.Keyword
	EffectiveEntityRaw                                 fields.Object
	EffectiveEntityReference                           fields.Keyword
	EffectiveEntityRelationshipsAdministersDomain      fields.Keyword
	EffectiveEntityRelationshipsAdministersEmail       fields.Keyword
	EffectiveEntityRelationshipsAdministersEntityID    fields.Keyword
	EffectiveEntityRelationshipsAdministersHostID      fields.Keyword
	EffectiveEntityRelationshipsAdministersHostName    fields.Keyword
	EffectiveEntityRelationshipsAdministersID          fields.Keyword
	EffectiveEntityRelationshipsAdministersName        fields.Keyword
	EffectiveEntityRelationshipsAdministersServiceID   fields.Keyword
	EffectiveEntityRelationshipsAdministersServiceName fields.Keyword
	EffectiveEntityRelationshipsDependsOnDomain        fields.Keyword
	EffectiveEntityRelationshipsDependsOnEmail         fields.Keyword
	EffectiveEntityRelationshipsDependsOnEntityID      fields.Keyword
	EffectiveEntityRelationshipsDependsOnHostID        fields.Keyword
	EffectiveEntityRelationshipsDependsOnHostName      fields.Keyword
	EffectiveEntityRelationshipsDependsOnID            fields.Keyword
	EffectiveEntityRelationshipsDependsOnName          fields.Keyword
	EffectiveEntityRelationshipsDependsOnServiceID     fields.Keyword
	EffectiveEntityRelationshipsDependsOnServiceName   fields.Keyword
	EffectiveEntityRelationshipsOwnsDomain             fields.Keyword
	EffectiveEntityRelationshipsOwnsEmail              fields.Keyword
	EffectiveEntityRelationshipsOwnsEntityID           fields.Keyword
	EffectiveEntityRelationshipsOwnsHostID             fields.Keyword
	EffectiveEntityRelationshipsOwnsHostName           fields.Keyword
	EffectiveEntityRelationshipsOwnsID                 fields.Keyword
	EffectiveEntityRelationshipsOwnsName               fields.Keyword
	EffectiveEntityRelationshipsOwnsServiceID          fields.Keyword
	EffectiveEntityRelationshipsOwnsServiceName        fields.Keyword
	EffectiveEntityRelationshipsSupervisesDomain       fields.Keyword
	EffectiveEntityRelationshipsSupervisesEmail        fields.Keyword
	EffectiveEntityRelationshipsSupervisesEntityID     fields.Keyword
	EffectiveEntityRelationshipsSupervisesHostID       fields.Keyword
	EffectiveEntityRelationshipsSupervisesHostName     fields.Keyword
	EffectiveEntityRelationshipsSupervisesID           fields.Keyword
	EffectiveEntityRelationshipsSupervisesName         fields.Keyword
	EffectiveEntityRelationshipsSupervisesServiceID    fields.Keyword
	EffectiveEntityRelationshipsSupervisesServiceName  fields.Keyword
	EffectiveEntitySource                              fields.Keyword
	EffectiveEntitySubType                             fields.Keyword
	EffectiveEntityType                                fields.Keyword
	EffectiveFullName                                  fields.Keyword
	EffectiveGroupDomain                               fields.Keyword
	EffectiveGroupID                                   fields.Keyword
	EffectiveGroupName                                 fields.Keyword
	EffectiveHash                                      fields.Keyword
	EffectiveID                                        fields.Keyword
	EffectiveName                                      fields.Keyword
	EffectiveRiskCalculatedLevel                       fields.Keyword
	EffectiveRiskCalculatedScore                       fields.Float
	EffectiveRiskCalculatedScoreNorm                   fields.Float
	EffectiveRiskStaticLevel                           fields.Keyword
	EffectiveRiskStaticScore                           fields.Float
	EffectiveRiskStaticScoreNorm                       fields.Float
	EffectiveRoles                                     fields.Keyword
	Email                                              fields.Keyword
	EntityAttributesKnownRedirects                     fields.Keyword
	EntityAttributesManaged                            fields.Boolean
	EntityAttributesMfaEnabled                         fields.Boolean
	EntityAttributesOauthConsentRestriction            fields.Keyword
	EntityAttributesPermissions                        fields.Keyword
	EntityAttributesStorageClass                       fields.Keyword
	EntityBehavior                                     fields.Object
	EntityDisplayName                                  fields.Keyword
	EntityID                                           fields.Keyword
	EntityLastSeenTimestamp                            fields.Date
	EntityLifecycleLastActivity                        fields.Date
	EntityMetrics                                      fields.Object
	EntityName                                         fields.Keyword
	EntityRaw                                          fields.Object
	EntityReference                                    fields.Keyword
	EntityRelationshipsAdministersDomain               fields.Keyword
	EntityRelationshipsAdministersEmail                fields.Keyword
	EntityRelationshipsAdministersEntityID             fields.Keyword
	EntityRelationshipsAdministersHostID               fields.Keyword
	EntityRelationshipsAdministersHostName             fields.Keyword
	EntityRelationshipsAdministersID                   fields.Keyword
	EntityRelationshipsAdministersName                 fields.Keyword
	EntityRelationshipsAdministersServiceID            fields.Keyword
	EntityRelationshipsAdministersServiceName          fields.Keyword
	EntityRelationshipsDependsOnDomain                 fields.Keyword
	EntityRelationshipsDependsOnEmail                  fields.Keyword
	EntityRelationshipsDependsOnEntityID               fields.Keyword
	EntityRelationshipsDependsOnHostID                 fields.Keyword
	EntityRelationshipsDependsOnHostName               fields.Keyword
	EntityRelationshipsDependsOnID                     fields.Keyword
	EntityRelationshipsDependsOnName                   fields.Keyword
	EntityRelationshipsDependsOnServiceID              fields.Keyword
	EntityRelationshipsDependsOnServiceName            fields.Keyword
	EntityRelationshipsOwnsDomain                      fields.Keyword
	EntityRelationshipsOwnsEmail                       fields.Keyword
	EntityRelationshipsOwnsEntityID                    fields.Keyword
	EntityRelationshipsOwnsHostID                      fields.Keyword
	EntityRelationshipsOwnsHostName                    fields.Keyword
	EntityRelationshipsOwnsID                          fields.Keyword
	EntityRelationshipsOwnsName                        fields.Keyword
	EntityRelationshipsOwnsServiceID                   fields.Keyword
	EntityRelationshipsOwnsServiceName                 fields.Keyword
	EntityRelationshipsSupervisesDomain                fields.Keyword
	EntityRelationshipsSupervisesEmail                 fields.Keyword
	EntityRelationshipsSupervisesEntityID              fields.Keyword
	EntityRelationshipsSupervisesHostID                fields.Keyword
	EntityRelationshipsSupervisesHostName              fields.Keyword
	EntityRelationshipsSupervisesID                    fields.Keyword
	EntityRelationshipsSupervisesName                  fields.Keyword
	EntityRelationshipsSupervisesServiceID             fields.Keyword
	EntityRelationshipsSupervisesServiceName           fields.Keyword
	EntitySource                                       fields.Keyword
	EntitySubType                                      fields.Keyword
	EntityType                                         fields.Keyword
	FullName                                           fields.Keyword
	GroupDomain                                        fields.Keyword
	GroupID                                            fields.Keyword
	GroupName                                          fields.Keyword
	Hash                                               fields.Keyword
	ID                                                 fields.Keyword
	Name                                               fields.Keyword
	RiskCalculatedLevel                                fields.Keyword
	RiskCalculatedScore                                fields.Float
	RiskCalculatedScoreNorm                            fields.Float
	RiskStaticLevel                                    fields.Keyword
	RiskStaticScore                                    fields.Float
	RiskStaticScoreNorm                                fields.Float
	Roles                                              fields.Keyword
	TargetDomain                                       fields.Keyword
	TargetEmail                                        fields.Keyword
	TargetEntityAttributesKnownRedirects               fields.Keyword
	TargetEntityAttributesManaged                      fields.Boolean
	TargetEntityAttributesMfaEnabled                   fields.Boolean
	TargetEntityAttributesOauthConsentRestriction      fields.Keyword
	TargetEntityAttributesPermissions                  fields.Keyword
	TargetEntityAttributesStorageClass                 fields.Keyword
	TargetEntityBehavior                               fields.Object
	TargetEntityDisplayName                            fields.Keyword
	TargetEntityID                                     fields.Keyword
	TargetEntityLastSeenTimestamp                      fields.Date
	TargetEntityLifecycleLastActivity                  fields.Date
	TargetEntityMetrics                                fields.Object
	TargetEntityName                                   fields.Keyword
	TargetEntityRaw                                    fields.Object
	TargetEntityReference                              fields.Keyword
	TargetEntityRelationshipsAdministersDomain         fields.Keyword
	TargetEntityRelationshipsAdministersEmail          fields.Keyword
	TargetEntityRelationshipsAdministersEntityID       fields.Keyword
	TargetEntityRelationshipsAdministersHostID         fields.Keyword
	TargetEntityRelationshipsAdministersHostName       fields.Keyword
	TargetEntityRelationshipsAdministersID             fields.Keyword
	TargetEntityRelationshipsAdministersName           fields.Keyword
	TargetEntityRelationshipsAdministersServiceID      fields.Keyword
	TargetEntityRelationshipsAdministersServiceName    fields.Keyword
	TargetEntityRelationshipsDependsOnDomain           fields.Keyword
	TargetEntityRelationshipsDependsOnEmail            fields.Keyword
	TargetEntityRelationshipsDependsOnEntityID         fields.Keyword
	TargetEntityRelationshipsDependsOnHostID           fields.Keyword
	TargetEntityRelationshipsDependsOnHostName         fields.Keyword
	TargetEntityRelationshipsDependsOnID               fields.Keyword
	TargetEntityRelationshipsDependsOnName             fields.Keyword
	TargetEntityRelationshipsDependsOnServiceID        fields.Keyword
	TargetEntityRelationshipsDependsOnServiceName      fields.Keyword
	TargetEntityRelationshipsOwnsDomain                fields.Keyword
	TargetEntityRelationshipsOwnsEmail                 fields.Keyword
	TargetEntityRelationshipsOwnsEntityID              fields.Keyword
	TargetEntityRelationshipsOwnsHostID                fields.Keyword
	TargetEntityRelationshipsOwnsHostName              fields.Keyword
	TargetEntityRelationshipsOwnsID                    fields.Keyword
	TargetEntityRelationshipsOwnsName                  fields.Keyword
	TargetEntityRelationshipsOwnsServiceID             fields.Keyword
	TargetEntityRelationshipsOwnsServiceName           fields.Keyword
	TargetEntityRelationshipsSupervisesDomain          fields.Keyword
	TargetEntityRelationshipsSupervisesEmail           fields.Keyword
	TargetEntityRelationshipsSupervisesEntityID        fields.Keyword
	TargetEntityRelationshipsSupervisesHostID          fields.Keyword
	TargetEntityRelationshipsSupervisesHostName        fields.Keyword
	TargetEntityRelationshipsSupervisesID              fields.Keyword
	TargetEntityRelationshipsSupervisesName            fields.Keyword
	TargetEntityRelationshipsSupervisesServiceID       fields.Keyword
	TargetEntityRelationshipsSupervisesServiceName     fields.Keyword
	TargetEntitySource                                 fields.Keyword
	TargetEntitySubType                                fields.Keyword
	TargetEntityType                                   fields.Keyword
	TargetFullName                                     fields.Keyword
	TargetGroupDomain                                  fields.Keyword
	TargetGroupID                                      fields.Keyword
	TargetGroupName                                    fields.Keyword
	TargetHash                                         fields.Keyword
	TargetID                                           fields.Keyword
	TargetName                                         fields.Keyword
	TargetRiskCalculatedLevel                          fields.Keyword
	TargetRiskCalculatedScore                          fields.Float
	TargetRiskCalculatedScoreNorm                      fields.Float
	TargetRiskStaticLevel                              fields.Keyword
	TargetRiskStaticScore                              fields.Float
	TargetRiskStaticScoreNorm                          fields.Float
	TargetRoles                                        fields.Keyword
}

var Types TypesType = TypesType{}
