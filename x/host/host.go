package host

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Architecture                                    fields.Field = "host.architecture"                                         // Operating system architecture.
	BootID                                          fields.Field = "host.boot.id"                                              // Linux boot uuid taken from /proc/sys/kernel/random/boot_id
	CpuUsage                                        fields.Field = "host.cpu.usage"                                            // Percent CPU used, between 0 and 1.
	DiskReadBytes                                   fields.Field = "host.disk.read.bytes"                                      // The number of bytes read by all disks.
	DiskWriteBytes                                  fields.Field = "host.disk.write.bytes"                                     // The number of bytes written on all disks.
	Domain                                          fields.Field = "host.domain"                                               // Name of the directory the group is a member of.
	EntityAttributesKnownRedirects                  fields.Field = "host.entity.attributes.known_redirects"                    // Known redirect URIs or URLs associated with this entity.
	EntityAttributesManaged                         fields.Field = "host.entity.attributes.managed"                            // Indicates whether the entity is managed by an external system.
	EntityAttributesMfaEnabled                      fields.Field = "host.entity.attributes.mfa_enabled"                        // Indicates whether multi-factor authentication is enabled for this entity.
	EntityAttributesOauthConsentRestriction         fields.Field = "host.entity.attributes.oauth_consent_restriction"          // Restriction applied to OAuth consent for this entity.
	EntityAttributesPermissions                     fields.Field = "host.entity.attributes.permissions"                        // Action-level permissions associated with this entity.
	EntityAttributesStorageClass                    fields.Field = "host.entity.attributes.storage_class"                      // Storage tier or class assigned to an object storage resource.
	EntityBehavior                                  fields.Field = "host.entity.behavior"                                      // A set of ephemeral characteristics of the entity, derived from observed behaviors during a specific time period.
	EntityDisplayName                               fields.Field = "host.entity.display_name"                                  // An optional field used when a pretty name is desired for entity-centric operations.
	EntityID                                        fields.Field = "host.entity.id"                                            // Unique identifier for the entity.
	EntityLastSeenTimestamp                         fields.Field = "host.entity.last_seen_timestamp"                           // Indicates the date/time when this entity was last "seen."
	EntityLifecycleLastActivity                     fields.Field = "host.entity.lifecycle.last_activity"                       // Timestamp of the most recent action performed by or attributed to this entity.
	EntityMetrics                                   fields.Field = "host.entity.metrics"                                       // Field set for any fields containing numeric entity metrics.
	EntityName                                      fields.Field = "host.entity.name"                                          // The name of the entity.
	EntityRaw                                       fields.Field = "host.entity.raw"                                           // Original, unmodified fields from the source system.
	EntityReference                                 fields.Field = "host.entity.reference"                                     // A URI, URL, or other direct reference to access or locate the entity.
	EntityRelationshipsAdministersEntityID          fields.Field = "host.entity.relationships.administers.entity.id"           // Identifiers of referenced entities.
	EntityRelationshipsAdministersID                fields.Field = "host.entity.relationships.administers.host.id"             // Referenced host ids.
	EntityRelationshipsAdministersName              fields.Field = "host.entity.relationships.administers.host.name"           // Referenced host names.
	EntityRelationshipsAdministersServiceID         fields.Field = "host.entity.relationships.administers.service.id"          // Referenced service ids.
	EntityRelationshipsAdministersServiceName       fields.Field = "host.entity.relationships.administers.service.name"        // Referenced service names.
	EntityRelationshipsAdministersUserDomain        fields.Field = "host.entity.relationships.administers.user.domain"         // Referenced user directory or AD/LDAP domain names.
	EntityRelationshipsAdministersUserEmail         fields.Field = "host.entity.relationships.administers.user.email"          // Referenced user email addresses.
	EntityRelationshipsAdministersUserID            fields.Field = "host.entity.relationships.administers.user.id"             // Referenced user ids.
	EntityRelationshipsAdministersUserName          fields.Field = "host.entity.relationships.administers.user.name"           // Referenced user short names or logins.
	EntityRelationshipsDependsOnEntityID            fields.Field = "host.entity.relationships.depends_on.entity.id"            // Identifiers of referenced entities.
	EntityRelationshipsDependsOnID                  fields.Field = "host.entity.relationships.depends_on.host.id"              // Referenced host ids.
	EntityRelationshipsDependsOnName                fields.Field = "host.entity.relationships.depends_on.host.name"            // Referenced host names.
	EntityRelationshipsDependsOnServiceID           fields.Field = "host.entity.relationships.depends_on.service.id"           // Referenced service ids.
	EntityRelationshipsDependsOnServiceName         fields.Field = "host.entity.relationships.depends_on.service.name"         // Referenced service names.
	EntityRelationshipsDependsOnUserDomain          fields.Field = "host.entity.relationships.depends_on.user.domain"          // Referenced user directory or AD/LDAP domain names.
	EntityRelationshipsDependsOnUserEmail           fields.Field = "host.entity.relationships.depends_on.user.email"           // Referenced user email addresses.
	EntityRelationshipsDependsOnUserID              fields.Field = "host.entity.relationships.depends_on.user.id"              // Referenced user ids.
	EntityRelationshipsDependsOnUserName            fields.Field = "host.entity.relationships.depends_on.user.name"            // Referenced user short names or logins.
	EntityRelationshipsOwnsEntityID                 fields.Field = "host.entity.relationships.owns.entity.id"                  // Identifiers of referenced entities.
	EntityRelationshipsOwnsID                       fields.Field = "host.entity.relationships.owns.host.id"                    // Referenced host ids.
	EntityRelationshipsOwnsName                     fields.Field = "host.entity.relationships.owns.host.name"                  // Referenced host names.
	EntityRelationshipsOwnsServiceID                fields.Field = "host.entity.relationships.owns.service.id"                 // Referenced service ids.
	EntityRelationshipsOwnsServiceName              fields.Field = "host.entity.relationships.owns.service.name"               // Referenced service names.
	EntityRelationshipsOwnsUserDomain               fields.Field = "host.entity.relationships.owns.user.domain"                // Referenced user directory or AD/LDAP domain names.
	EntityRelationshipsOwnsUserEmail                fields.Field = "host.entity.relationships.owns.user.email"                 // Referenced user email addresses.
	EntityRelationshipsOwnsUserID                   fields.Field = "host.entity.relationships.owns.user.id"                    // Referenced user ids.
	EntityRelationshipsOwnsUserName                 fields.Field = "host.entity.relationships.owns.user.name"                  // Referenced user short names or logins.
	EntityRelationshipsSupervisesEntityID           fields.Field = "host.entity.relationships.supervises.entity.id"            // Identifiers of referenced entities.
	EntityRelationshipsSupervisesID                 fields.Field = "host.entity.relationships.supervises.host.id"              // Referenced host ids.
	EntityRelationshipsSupervisesName               fields.Field = "host.entity.relationships.supervises.host.name"            // Referenced host names.
	EntityRelationshipsSupervisesServiceID          fields.Field = "host.entity.relationships.supervises.service.id"           // Referenced service ids.
	EntityRelationshipsSupervisesServiceName        fields.Field = "host.entity.relationships.supervises.service.name"         // Referenced service names.
	EntityRelationshipsSupervisesUserDomain         fields.Field = "host.entity.relationships.supervises.user.domain"          // Referenced user directory or AD/LDAP domain names.
	EntityRelationshipsSupervisesUserEmail          fields.Field = "host.entity.relationships.supervises.user.email"           // Referenced user email addresses.
	EntityRelationshipsSupervisesUserID             fields.Field = "host.entity.relationships.supervises.user.id"              // Referenced user ids.
	EntityRelationshipsSupervisesUserName           fields.Field = "host.entity.relationships.supervises.user.name"            // Referenced user short names or logins.
	EntitySource                                    fields.Field = "host.entity.source"                                        // Source module or integration that provided the entity data.
	EntitySubType                                   fields.Field = "host.entity.sub_type"                                      // The specific type designation for the entity as defined by its provider or system.
	EntityType                                      fields.Field = "host.entity.type"                                          // Standardized high-level classification of the entity.
	GeoCityName                                     fields.Field = "host.geo.city_name"                                        // City name.
	GeoContinentCode                                fields.Field = "host.geo.continent_code"                                   // Continent code.
	GeoContinentName                                fields.Field = "host.geo.continent_name"                                   // Name of the continent.
	GeoCountryIsoCode                               fields.Field = "host.geo.country_iso_code"                                 // Country ISO code.
	GeoCountryName                                  fields.Field = "host.geo.country_name"                                     // Country name.
	GeoLocation                                     fields.Field = "host.geo.location"                                         // Longitude and latitude.
	GeoName                                         fields.Field = "host.geo.name"                                             // User-defined description of a location.
	GeoPostalCode                                   fields.Field = "host.geo.postal_code"                                      // Postal code.
	GeoRegionIsoCode                                fields.Field = "host.geo.region_iso_code"                                  // Region ISO code.
	GeoRegionName                                   fields.Field = "host.geo.region_name"                                      // Region name.
	GeoTimezone                                     fields.Field = "host.geo.timezone"                                         // The time zone of the location, such as IANA time zone name.
	Hostname                                        fields.Field = "host.hostname"                                             // Hostname of the host.
	ID                                              fields.Field = "host.id"                                                   // Unique host id.
	Ip                                              fields.Field = "host.ip"                                                   // Host ip addresses.
	Mac                                             fields.Field = "host.mac"                                                  // Host MAC addresses.
	Name                                            fields.Field = "host.name"                                                 // Name of the host.
	NetworkEgressBytes                              fields.Field = "host.network.egress.bytes"                                 // The number of bytes sent on all network interfaces.
	NetworkEgressPackets                            fields.Field = "host.network.egress.packets"                               // The number of packets sent on all network interfaces.
	NetworkIngressBytes                             fields.Field = "host.network.ingress.bytes"                                // The number of bytes received on all network interfaces.
	NetworkIngressPackets                           fields.Field = "host.network.ingress.packets"                              // The number of packets received on all network interfaces.
	OsFamily                                        fields.Field = "host.os.family"                                            // OS family (such as redhat, debian, freebsd, windows).
	OsFull                                          fields.Field = "host.os.full"                                              // Operating system name, including the version or code name.
	OsKernel                                        fields.Field = "host.os.kernel"                                            // Operating system kernel version as a raw string.
	OsName                                          fields.Field = "host.os.name"                                              // Operating system name, without the version.
	OsPlatform                                      fields.Field = "host.os.platform"                                          // Operating system platform (such centos, ubuntu, windows).
	OsType                                          fields.Field = "host.os.type"                                              // Which commercial OS family (one of: linux, macos, unix, windows, ios or android).
	OsVersion                                       fields.Field = "host.os.version"                                           // Operating system version as a raw string.
	PidNsIno                                        fields.Field = "host.pid_ns_ino"                                           // Pid namespace inode
	RiskCalculatedLevel                             fields.Field = "host.risk.calculated_level"                                // A risk classification level calculated by an internal system as part of entity analytics and entity risk scoring.
	RiskCalculatedScore                             fields.Field = "host.risk.calculated_score"                                // A risk classification score calculated by an internal system as part of entity analytics and entity risk scoring.
	RiskCalculatedScoreNorm                         fields.Field = "host.risk.calculated_score_norm"                           // A normalized risk score calculated by an internal system.
	RiskStaticLevel                                 fields.Field = "host.risk.static_level"                                    // A risk classification level obtained from outside the system, such as from some external Threat Intelligence Platform.
	RiskStaticScore                                 fields.Field = "host.risk.static_score"                                    // A risk classification score obtained from outside the system, such as from some external Threat Intelligence Platform.
	RiskStaticScoreNorm                             fields.Field = "host.risk.static_score_norm"                               // A normalized risk score calculated by an external system.
	TargetArchitecture                              fields.Field = "host.target.architecture"                                  // Operating system architecture.
	TargetBootID                                    fields.Field = "host.target.boot.id"                                       // Linux boot uuid taken from /proc/sys/kernel/random/boot_id
	TargetCpuUsage                                  fields.Field = "host.target.cpu.usage"                                     // Percent CPU used, between 0 and 1.
	TargetDiskReadBytes                             fields.Field = "host.target.disk.read.bytes"                               // The number of bytes read by all disks.
	TargetDiskWriteBytes                            fields.Field = "host.target.disk.write.bytes"                              // The number of bytes written on all disks.
	TargetDomain                                    fields.Field = "host.target.domain"                                        // Name of the directory the group is a member of.
	TargetEntityAttributesKnownRedirects            fields.Field = "host.target.entity.attributes.known_redirects"             // Known redirect URIs or URLs associated with this entity.
	TargetEntityAttributesManaged                   fields.Field = "host.target.entity.attributes.managed"                     // Indicates whether the entity is managed by an external system.
	TargetEntityAttributesMfaEnabled                fields.Field = "host.target.entity.attributes.mfa_enabled"                 // Indicates whether multi-factor authentication is enabled for this entity.
	TargetEntityAttributesOauthConsentRestriction   fields.Field = "host.target.entity.attributes.oauth_consent_restriction"   // Restriction applied to OAuth consent for this entity.
	TargetEntityAttributesPermissions               fields.Field = "host.target.entity.attributes.permissions"                 // Action-level permissions associated with this entity.
	TargetEntityAttributesStorageClass              fields.Field = "host.target.entity.attributes.storage_class"               // Storage tier or class assigned to an object storage resource.
	TargetEntityBehavior                            fields.Field = "host.target.entity.behavior"                               // A set of ephemeral characteristics of the entity, derived from observed behaviors during a specific time period.
	TargetEntityDisplayName                         fields.Field = "host.target.entity.display_name"                           // An optional field used when a pretty name is desired for entity-centric operations.
	TargetEntityID                                  fields.Field = "host.target.entity.id"                                     // Unique identifier for the entity.
	TargetEntityLastSeenTimestamp                   fields.Field = "host.target.entity.last_seen_timestamp"                    // Indicates the date/time when this entity was last "seen."
	TargetEntityLifecycleLastActivity               fields.Field = "host.target.entity.lifecycle.last_activity"                // Timestamp of the most recent action performed by or attributed to this entity.
	TargetEntityMetrics                             fields.Field = "host.target.entity.metrics"                                // Field set for any fields containing numeric entity metrics.
	TargetEntityName                                fields.Field = "host.target.entity.name"                                   // The name of the entity.
	TargetEntityRaw                                 fields.Field = "host.target.entity.raw"                                    // Original, unmodified fields from the source system.
	TargetEntityReference                           fields.Field = "host.target.entity.reference"                              // A URI, URL, or other direct reference to access or locate the entity.
	TargetEntityRelationshipsAdministersEntityID    fields.Field = "host.target.entity.relationships.administers.entity.id"    // Identifiers of referenced entities.
	TargetEntityRelationshipsAdministersID          fields.Field = "host.target.entity.relationships.administers.host.id"      // Referenced host ids.
	TargetEntityRelationshipsAdministersName        fields.Field = "host.target.entity.relationships.administers.host.name"    // Referenced host names.
	TargetEntityRelationshipsAdministersServiceID   fields.Field = "host.target.entity.relationships.administers.service.id"   // Referenced service ids.
	TargetEntityRelationshipsAdministersServiceName fields.Field = "host.target.entity.relationships.administers.service.name" // Referenced service names.
	TargetEntityRelationshipsAdministersUserDomain  fields.Field = "host.target.entity.relationships.administers.user.domain"  // Referenced user directory or AD/LDAP domain names.
	TargetEntityRelationshipsAdministersUserEmail   fields.Field = "host.target.entity.relationships.administers.user.email"   // Referenced user email addresses.
	TargetEntityRelationshipsAdministersUserID      fields.Field = "host.target.entity.relationships.administers.user.id"      // Referenced user ids.
	TargetEntityRelationshipsAdministersUserName    fields.Field = "host.target.entity.relationships.administers.user.name"    // Referenced user short names or logins.
	TargetEntityRelationshipsDependsOnEntityID      fields.Field = "host.target.entity.relationships.depends_on.entity.id"     // Identifiers of referenced entities.
	TargetEntityRelationshipsDependsOnID            fields.Field = "host.target.entity.relationships.depends_on.host.id"       // Referenced host ids.
	TargetEntityRelationshipsDependsOnName          fields.Field = "host.target.entity.relationships.depends_on.host.name"     // Referenced host names.
	TargetEntityRelationshipsDependsOnServiceID     fields.Field = "host.target.entity.relationships.depends_on.service.id"    // Referenced service ids.
	TargetEntityRelationshipsDependsOnServiceName   fields.Field = "host.target.entity.relationships.depends_on.service.name"  // Referenced service names.
	TargetEntityRelationshipsDependsOnUserDomain    fields.Field = "host.target.entity.relationships.depends_on.user.domain"   // Referenced user directory or AD/LDAP domain names.
	TargetEntityRelationshipsDependsOnUserEmail     fields.Field = "host.target.entity.relationships.depends_on.user.email"    // Referenced user email addresses.
	TargetEntityRelationshipsDependsOnUserID        fields.Field = "host.target.entity.relationships.depends_on.user.id"       // Referenced user ids.
	TargetEntityRelationshipsDependsOnUserName      fields.Field = "host.target.entity.relationships.depends_on.user.name"     // Referenced user short names or logins.
	TargetEntityRelationshipsOwnsEntityID           fields.Field = "host.target.entity.relationships.owns.entity.id"           // Identifiers of referenced entities.
	TargetEntityRelationshipsOwnsID                 fields.Field = "host.target.entity.relationships.owns.host.id"             // Referenced host ids.
	TargetEntityRelationshipsOwnsName               fields.Field = "host.target.entity.relationships.owns.host.name"           // Referenced host names.
	TargetEntityRelationshipsOwnsServiceID          fields.Field = "host.target.entity.relationships.owns.service.id"          // Referenced service ids.
	TargetEntityRelationshipsOwnsServiceName        fields.Field = "host.target.entity.relationships.owns.service.name"        // Referenced service names.
	TargetEntityRelationshipsOwnsUserDomain         fields.Field = "host.target.entity.relationships.owns.user.domain"         // Referenced user directory or AD/LDAP domain names.
	TargetEntityRelationshipsOwnsUserEmail          fields.Field = "host.target.entity.relationships.owns.user.email"          // Referenced user email addresses.
	TargetEntityRelationshipsOwnsUserID             fields.Field = "host.target.entity.relationships.owns.user.id"             // Referenced user ids.
	TargetEntityRelationshipsOwnsUserName           fields.Field = "host.target.entity.relationships.owns.user.name"           // Referenced user short names or logins.
	TargetEntityRelationshipsSupervisesEntityID     fields.Field = "host.target.entity.relationships.supervises.entity.id"     // Identifiers of referenced entities.
	TargetEntityRelationshipsSupervisesID           fields.Field = "host.target.entity.relationships.supervises.host.id"       // Referenced host ids.
	TargetEntityRelationshipsSupervisesName         fields.Field = "host.target.entity.relationships.supervises.host.name"     // Referenced host names.
	TargetEntityRelationshipsSupervisesServiceID    fields.Field = "host.target.entity.relationships.supervises.service.id"    // Referenced service ids.
	TargetEntityRelationshipsSupervisesServiceName  fields.Field = "host.target.entity.relationships.supervises.service.name"  // Referenced service names.
	TargetEntityRelationshipsSupervisesUserDomain   fields.Field = "host.target.entity.relationships.supervises.user.domain"   // Referenced user directory or AD/LDAP domain names.
	TargetEntityRelationshipsSupervisesUserEmail    fields.Field = "host.target.entity.relationships.supervises.user.email"    // Referenced user email addresses.
	TargetEntityRelationshipsSupervisesUserID       fields.Field = "host.target.entity.relationships.supervises.user.id"       // Referenced user ids.
	TargetEntityRelationshipsSupervisesUserName     fields.Field = "host.target.entity.relationships.supervises.user.name"     // Referenced user short names or logins.
	TargetEntitySource                              fields.Field = "host.target.entity.source"                                 // Source module or integration that provided the entity data.
	TargetEntitySubType                             fields.Field = "host.target.entity.sub_type"                               // The specific type designation for the entity as defined by its provider or system.
	TargetEntityType                                fields.Field = "host.target.entity.type"                                   // Standardized high-level classification of the entity.
	TargetGeoCityName                               fields.Field = "host.target.geo.city_name"                                 // City name.
	TargetGeoContinentCode                          fields.Field = "host.target.geo.continent_code"                            // Continent code.
	TargetGeoContinentName                          fields.Field = "host.target.geo.continent_name"                            // Name of the continent.
	TargetGeoCountryIsoCode                         fields.Field = "host.target.geo.country_iso_code"                          // Country ISO code.
	TargetGeoCountryName                            fields.Field = "host.target.geo.country_name"                              // Country name.
	TargetGeoLocation                               fields.Field = "host.target.geo.location"                                  // Longitude and latitude.
	TargetGeoName                                   fields.Field = "host.target.geo.name"                                      // User-defined description of a location.
	TargetGeoPostalCode                             fields.Field = "host.target.geo.postal_code"                               // Postal code.
	TargetGeoRegionIsoCode                          fields.Field = "host.target.geo.region_iso_code"                           // Region ISO code.
	TargetGeoRegionName                             fields.Field = "host.target.geo.region_name"                               // Region name.
	TargetGeoTimezone                               fields.Field = "host.target.geo.timezone"                                  // The time zone of the location, such as IANA time zone name.
	TargetHostname                                  fields.Field = "host.target.hostname"                                      // Hostname of the host.
	TargetID                                        fields.Field = "host.target.id"                                            // Unique host id.
	TargetIp                                        fields.Field = "host.target.ip"                                            // Host ip addresses.
	TargetMac                                       fields.Field = "host.target.mac"                                           // Host MAC addresses.
	TargetName                                      fields.Field = "host.target.name"                                          // Name of the host.
	TargetNetworkEgressBytes                        fields.Field = "host.target.network.egress.bytes"                          // The number of bytes sent on all network interfaces.
	TargetNetworkEgressPackets                      fields.Field = "host.target.network.egress.packets"                        // The number of packets sent on all network interfaces.
	TargetNetworkIngressBytes                       fields.Field = "host.target.network.ingress.bytes"                         // The number of bytes received on all network interfaces.
	TargetNetworkIngressPackets                     fields.Field = "host.target.network.ingress.packets"                       // The number of packets received on all network interfaces.
	TargetOsFamily                                  fields.Field = "host.target.os.family"                                     // OS family (such as redhat, debian, freebsd, windows).
	TargetOsFull                                    fields.Field = "host.target.os.full"                                       // Operating system name, including the version or code name.
	TargetOsKernel                                  fields.Field = "host.target.os.kernel"                                     // Operating system kernel version as a raw string.
	TargetOsName                                    fields.Field = "host.target.os.name"                                       // Operating system name, without the version.
	TargetOsPlatform                                fields.Field = "host.target.os.platform"                                   // Operating system platform (such centos, ubuntu, windows).
	TargetOsType                                    fields.Field = "host.target.os.type"                                       // Which commercial OS family (one of: linux, macos, unix, windows, ios or android).
	TargetOsVersion                                 fields.Field = "host.target.os.version"                                    // Operating system version as a raw string.
	TargetPidNsIno                                  fields.Field = "host.target.pid_ns_ino"                                    // Pid namespace inode
	TargetRiskCalculatedLevel                       fields.Field = "host.target.risk.calculated_level"                         // A risk classification level calculated by an internal system as part of entity analytics and entity risk scoring.
	TargetRiskCalculatedScore                       fields.Field = "host.target.risk.calculated_score"                         // A risk classification score calculated by an internal system as part of entity analytics and entity risk scoring.
	TargetRiskCalculatedScoreNorm                   fields.Field = "host.target.risk.calculated_score_norm"                    // A normalized risk score calculated by an internal system.
	TargetRiskStaticLevel                           fields.Field = "host.target.risk.static_level"                             // A risk classification level obtained from outside the system, such as from some external Threat Intelligence Platform.
	TargetRiskStaticScore                           fields.Field = "host.target.risk.static_score"                             // A risk classification score obtained from outside the system, such as from some external Threat Intelligence Platform.
	TargetRiskStaticScoreNorm                       fields.Field = "host.target.risk.static_score_norm"                        // A normalized risk score calculated by an external system.
	TargetType                                      fields.Field = "host.target.type"                                          // Type of host.
	TargetUptime                                    fields.Field = "host.target.uptime"                                        // Seconds the host has been up.
	Type                                            fields.Field = "host.type"                                                 // Type of host.
	Uptime                                          fields.Field = "host.uptime"                                               // Seconds the host has been up.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Architecture,
	BootID,
	CpuUsage,
	DiskReadBytes,
	DiskWriteBytes,
	Domain,
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
	EntityRelationshipsAdministersID,
	EntityRelationshipsAdministersName,
	EntityRelationshipsAdministersServiceID,
	EntityRelationshipsAdministersServiceName,
	EntityRelationshipsAdministersUserDomain,
	EntityRelationshipsAdministersUserEmail,
	EntityRelationshipsAdministersUserID,
	EntityRelationshipsAdministersUserName,
	EntityRelationshipsDependsOnEntityID,
	EntityRelationshipsDependsOnID,
	EntityRelationshipsDependsOnName,
	EntityRelationshipsDependsOnServiceID,
	EntityRelationshipsDependsOnServiceName,
	EntityRelationshipsDependsOnUserDomain,
	EntityRelationshipsDependsOnUserEmail,
	EntityRelationshipsDependsOnUserID,
	EntityRelationshipsDependsOnUserName,
	EntityRelationshipsOwnsEntityID,
	EntityRelationshipsOwnsID,
	EntityRelationshipsOwnsName,
	EntityRelationshipsOwnsServiceID,
	EntityRelationshipsOwnsServiceName,
	EntityRelationshipsOwnsUserDomain,
	EntityRelationshipsOwnsUserEmail,
	EntityRelationshipsOwnsUserID,
	EntityRelationshipsOwnsUserName,
	EntityRelationshipsSupervisesEntityID,
	EntityRelationshipsSupervisesID,
	EntityRelationshipsSupervisesName,
	EntityRelationshipsSupervisesServiceID,
	EntityRelationshipsSupervisesServiceName,
	EntityRelationshipsSupervisesUserDomain,
	EntityRelationshipsSupervisesUserEmail,
	EntityRelationshipsSupervisesUserID,
	EntityRelationshipsSupervisesUserName,
	EntitySource,
	EntitySubType,
	EntityType,
	GeoCityName,
	GeoContinentCode,
	GeoContinentName,
	GeoCountryIsoCode,
	GeoCountryName,
	GeoLocation,
	GeoName,
	GeoPostalCode,
	GeoRegionIsoCode,
	GeoRegionName,
	GeoTimezone,
	Hostname,
	ID,
	Ip,
	Mac,
	Name,
	NetworkEgressBytes,
	NetworkEgressPackets,
	NetworkIngressBytes,
	NetworkIngressPackets,
	OsFamily,
	OsFull,
	OsKernel,
	OsName,
	OsPlatform,
	OsType,
	OsVersion,
	PidNsIno,
	RiskCalculatedLevel,
	RiskCalculatedScore,
	RiskCalculatedScoreNorm,
	RiskStaticLevel,
	RiskStaticScore,
	RiskStaticScoreNorm,
	TargetArchitecture,
	TargetBootID,
	TargetCpuUsage,
	TargetDiskReadBytes,
	TargetDiskWriteBytes,
	TargetDomain,
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
	TargetEntityRelationshipsAdministersID,
	TargetEntityRelationshipsAdministersName,
	TargetEntityRelationshipsAdministersServiceID,
	TargetEntityRelationshipsAdministersServiceName,
	TargetEntityRelationshipsAdministersUserDomain,
	TargetEntityRelationshipsAdministersUserEmail,
	TargetEntityRelationshipsAdministersUserID,
	TargetEntityRelationshipsAdministersUserName,
	TargetEntityRelationshipsDependsOnEntityID,
	TargetEntityRelationshipsDependsOnID,
	TargetEntityRelationshipsDependsOnName,
	TargetEntityRelationshipsDependsOnServiceID,
	TargetEntityRelationshipsDependsOnServiceName,
	TargetEntityRelationshipsDependsOnUserDomain,
	TargetEntityRelationshipsDependsOnUserEmail,
	TargetEntityRelationshipsDependsOnUserID,
	TargetEntityRelationshipsDependsOnUserName,
	TargetEntityRelationshipsOwnsEntityID,
	TargetEntityRelationshipsOwnsID,
	TargetEntityRelationshipsOwnsName,
	TargetEntityRelationshipsOwnsServiceID,
	TargetEntityRelationshipsOwnsServiceName,
	TargetEntityRelationshipsOwnsUserDomain,
	TargetEntityRelationshipsOwnsUserEmail,
	TargetEntityRelationshipsOwnsUserID,
	TargetEntityRelationshipsOwnsUserName,
	TargetEntityRelationshipsSupervisesEntityID,
	TargetEntityRelationshipsSupervisesID,
	TargetEntityRelationshipsSupervisesName,
	TargetEntityRelationshipsSupervisesServiceID,
	TargetEntityRelationshipsSupervisesServiceName,
	TargetEntityRelationshipsSupervisesUserDomain,
	TargetEntityRelationshipsSupervisesUserEmail,
	TargetEntityRelationshipsSupervisesUserID,
	TargetEntityRelationshipsSupervisesUserName,
	TargetEntitySource,
	TargetEntitySubType,
	TargetEntityType,
	TargetGeoCityName,
	TargetGeoContinentCode,
	TargetGeoContinentName,
	TargetGeoCountryIsoCode,
	TargetGeoCountryName,
	TargetGeoLocation,
	TargetGeoName,
	TargetGeoPostalCode,
	TargetGeoRegionIsoCode,
	TargetGeoRegionName,
	TargetGeoTimezone,
	TargetHostname,
	TargetID,
	TargetIp,
	TargetMac,
	TargetName,
	TargetNetworkEgressBytes,
	TargetNetworkEgressPackets,
	TargetNetworkIngressBytes,
	TargetNetworkIngressPackets,
	TargetOsFamily,
	TargetOsFull,
	TargetOsKernel,
	TargetOsName,
	TargetOsPlatform,
	TargetOsType,
	TargetOsVersion,
	TargetPidNsIno,
	TargetRiskCalculatedLevel,
	TargetRiskCalculatedScore,
	TargetRiskCalculatedScoreNorm,
	TargetRiskStaticLevel,
	TargetRiskStaticScore,
	TargetRiskStaticScoreNorm,
	TargetType,
	TargetUptime,
	Type,
	Uptime,
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

type OsTypeExpectedType struct {
	Android string
	Ios     string
	Linux   string
	Macos   string
	Unix    string
	Windows string
}

var OsTypeExpectedValues OsTypeExpectedType = OsTypeExpectedType{
	Android: `android`,
	Ios:     `ios`,
	Linux:   `linux`,
	Macos:   `macos`,
	Unix:    `unix`,
	Windows: `windows`,
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

type TargetOsTypeExpectedType struct {
	Android string
	Ios     string
	Linux   string
	Macos   string
	Unix    string
	Windows string
}

var TargetOsTypeExpectedValues TargetOsTypeExpectedType = TargetOsTypeExpectedType{
	Android: `android`,
	Ios:     `ios`,
	Linux:   `linux`,
	Macos:   `macos`,
	Unix:    `unix`,
	Windows: `windows`,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Architecture                                    fields.Keyword
	BootID                                          fields.Keyword
	CpuUsage                                        fields.ScaledFloat
	DiskReadBytes                                   fields.Long
	DiskWriteBytes                                  fields.Long
	Domain                                          fields.Keyword
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
	EntityRelationshipsAdministersID                fields.Keyword
	EntityRelationshipsAdministersName              fields.Keyword
	EntityRelationshipsAdministersServiceID         fields.Keyword
	EntityRelationshipsAdministersServiceName       fields.Keyword
	EntityRelationshipsAdministersUserDomain        fields.Keyword
	EntityRelationshipsAdministersUserEmail         fields.Keyword
	EntityRelationshipsAdministersUserID            fields.Keyword
	EntityRelationshipsAdministersUserName          fields.Keyword
	EntityRelationshipsDependsOnEntityID            fields.Keyword
	EntityRelationshipsDependsOnID                  fields.Keyword
	EntityRelationshipsDependsOnName                fields.Keyword
	EntityRelationshipsDependsOnServiceID           fields.Keyword
	EntityRelationshipsDependsOnServiceName         fields.Keyword
	EntityRelationshipsDependsOnUserDomain          fields.Keyword
	EntityRelationshipsDependsOnUserEmail           fields.Keyword
	EntityRelationshipsDependsOnUserID              fields.Keyword
	EntityRelationshipsDependsOnUserName            fields.Keyword
	EntityRelationshipsOwnsEntityID                 fields.Keyword
	EntityRelationshipsOwnsID                       fields.Keyword
	EntityRelationshipsOwnsName                     fields.Keyword
	EntityRelationshipsOwnsServiceID                fields.Keyword
	EntityRelationshipsOwnsServiceName              fields.Keyword
	EntityRelationshipsOwnsUserDomain               fields.Keyword
	EntityRelationshipsOwnsUserEmail                fields.Keyword
	EntityRelationshipsOwnsUserID                   fields.Keyword
	EntityRelationshipsOwnsUserName                 fields.Keyword
	EntityRelationshipsSupervisesEntityID           fields.Keyword
	EntityRelationshipsSupervisesID                 fields.Keyword
	EntityRelationshipsSupervisesName               fields.Keyword
	EntityRelationshipsSupervisesServiceID          fields.Keyword
	EntityRelationshipsSupervisesServiceName        fields.Keyword
	EntityRelationshipsSupervisesUserDomain         fields.Keyword
	EntityRelationshipsSupervisesUserEmail          fields.Keyword
	EntityRelationshipsSupervisesUserID             fields.Keyword
	EntityRelationshipsSupervisesUserName           fields.Keyword
	EntitySource                                    fields.Keyword
	EntitySubType                                   fields.Keyword
	EntityType                                      fields.Keyword
	GeoCityName                                     fields.Keyword
	GeoContinentCode                                fields.Keyword
	GeoContinentName                                fields.Keyword
	GeoCountryIsoCode                               fields.Keyword
	GeoCountryName                                  fields.Keyword
	GeoLocation                                     fields.GeoPoint
	GeoName                                         fields.Keyword
	GeoPostalCode                                   fields.Keyword
	GeoRegionIsoCode                                fields.Keyword
	GeoRegionName                                   fields.Keyword
	GeoTimezone                                     fields.Keyword
	Hostname                                        fields.Keyword
	ID                                              fields.Keyword
	Ip                                              fields.IP
	Mac                                             fields.Keyword
	Name                                            fields.Keyword
	NetworkEgressBytes                              fields.Long
	NetworkEgressPackets                            fields.Long
	NetworkIngressBytes                             fields.Long
	NetworkIngressPackets                           fields.Long
	OsFamily                                        fields.Keyword
	OsFull                                          fields.Keyword
	OsKernel                                        fields.Keyword
	OsName                                          fields.Keyword
	OsPlatform                                      fields.Keyword
	OsType                                          fields.Keyword
	OsVersion                                       fields.Keyword
	PidNsIno                                        fields.Keyword
	RiskCalculatedLevel                             fields.Keyword
	RiskCalculatedScore                             fields.Float
	RiskCalculatedScoreNorm                         fields.Float
	RiskStaticLevel                                 fields.Keyword
	RiskStaticScore                                 fields.Float
	RiskStaticScoreNorm                             fields.Float
	TargetArchitecture                              fields.Keyword
	TargetBootID                                    fields.Keyword
	TargetCpuUsage                                  fields.ScaledFloat
	TargetDiskReadBytes                             fields.Long
	TargetDiskWriteBytes                            fields.Long
	TargetDomain                                    fields.Keyword
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
	TargetEntityRelationshipsAdministersID          fields.Keyword
	TargetEntityRelationshipsAdministersName        fields.Keyword
	TargetEntityRelationshipsAdministersServiceID   fields.Keyword
	TargetEntityRelationshipsAdministersServiceName fields.Keyword
	TargetEntityRelationshipsAdministersUserDomain  fields.Keyword
	TargetEntityRelationshipsAdministersUserEmail   fields.Keyword
	TargetEntityRelationshipsAdministersUserID      fields.Keyword
	TargetEntityRelationshipsAdministersUserName    fields.Keyword
	TargetEntityRelationshipsDependsOnEntityID      fields.Keyword
	TargetEntityRelationshipsDependsOnID            fields.Keyword
	TargetEntityRelationshipsDependsOnName          fields.Keyword
	TargetEntityRelationshipsDependsOnServiceID     fields.Keyword
	TargetEntityRelationshipsDependsOnServiceName   fields.Keyword
	TargetEntityRelationshipsDependsOnUserDomain    fields.Keyword
	TargetEntityRelationshipsDependsOnUserEmail     fields.Keyword
	TargetEntityRelationshipsDependsOnUserID        fields.Keyword
	TargetEntityRelationshipsDependsOnUserName      fields.Keyword
	TargetEntityRelationshipsOwnsEntityID           fields.Keyword
	TargetEntityRelationshipsOwnsID                 fields.Keyword
	TargetEntityRelationshipsOwnsName               fields.Keyword
	TargetEntityRelationshipsOwnsServiceID          fields.Keyword
	TargetEntityRelationshipsOwnsServiceName        fields.Keyword
	TargetEntityRelationshipsOwnsUserDomain         fields.Keyword
	TargetEntityRelationshipsOwnsUserEmail          fields.Keyword
	TargetEntityRelationshipsOwnsUserID             fields.Keyword
	TargetEntityRelationshipsOwnsUserName           fields.Keyword
	TargetEntityRelationshipsSupervisesEntityID     fields.Keyword
	TargetEntityRelationshipsSupervisesID           fields.Keyword
	TargetEntityRelationshipsSupervisesName         fields.Keyword
	TargetEntityRelationshipsSupervisesServiceID    fields.Keyword
	TargetEntityRelationshipsSupervisesServiceName  fields.Keyword
	TargetEntityRelationshipsSupervisesUserDomain   fields.Keyword
	TargetEntityRelationshipsSupervisesUserEmail    fields.Keyword
	TargetEntityRelationshipsSupervisesUserID       fields.Keyword
	TargetEntityRelationshipsSupervisesUserName     fields.Keyword
	TargetEntitySource                              fields.Keyword
	TargetEntitySubType                             fields.Keyword
	TargetEntityType                                fields.Keyword
	TargetGeoCityName                               fields.Keyword
	TargetGeoContinentCode                          fields.Keyword
	TargetGeoContinentName                          fields.Keyword
	TargetGeoCountryIsoCode                         fields.Keyword
	TargetGeoCountryName                            fields.Keyword
	TargetGeoLocation                               fields.GeoPoint
	TargetGeoName                                   fields.Keyword
	TargetGeoPostalCode                             fields.Keyword
	TargetGeoRegionIsoCode                          fields.Keyword
	TargetGeoRegionName                             fields.Keyword
	TargetGeoTimezone                               fields.Keyword
	TargetHostname                                  fields.Keyword
	TargetID                                        fields.Keyword
	TargetIp                                        fields.IP
	TargetMac                                       fields.Keyword
	TargetName                                      fields.Keyword
	TargetNetworkEgressBytes                        fields.Long
	TargetNetworkEgressPackets                      fields.Long
	TargetNetworkIngressBytes                       fields.Long
	TargetNetworkIngressPackets                     fields.Long
	TargetOsFamily                                  fields.Keyword
	TargetOsFull                                    fields.Keyword
	TargetOsKernel                                  fields.Keyword
	TargetOsName                                    fields.Keyword
	TargetOsPlatform                                fields.Keyword
	TargetOsType                                    fields.Keyword
	TargetOsVersion                                 fields.Keyword
	TargetPidNsIno                                  fields.Keyword
	TargetRiskCalculatedLevel                       fields.Keyword
	TargetRiskCalculatedScore                       fields.Float
	TargetRiskCalculatedScoreNorm                   fields.Float
	TargetRiskStaticLevel                           fields.Keyword
	TargetRiskStaticScore                           fields.Float
	TargetRiskStaticScoreNorm                       fields.Float
	TargetType                                      fields.Keyword
	TargetUptime                                    fields.Long
	Type                                            fields.Keyword
	Uptime                                          fields.Long
}

var Types TypesType = TypesType{}
