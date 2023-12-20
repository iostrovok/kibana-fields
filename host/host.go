package host

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Architecture            fields.Field = "host.architecture"               // Operating system architecture.
	BootID                  fields.Field = "host.boot.id"                    // Linux boot uuid taken from /proc/sys/kernel/random/boot_id
	CpuUsage                fields.Field = "host.cpu.usage"                  // Percent CPU used, between 0 and 1.
	DiskReadBytes           fields.Field = "host.disk.read.bytes"            // The number of bytes read by all disks.
	DiskWriteBytes          fields.Field = "host.disk.write.bytes"           // The number of bytes written on all disks.
	Domain                  fields.Field = "host.domain"                     // Name of the directory the group is a member of.
	GeoCityName             fields.Field = "host.geo.city_name"              // City name.
	GeoContinentCode        fields.Field = "host.geo.continent_code"         // Continent code.
	GeoContinentName        fields.Field = "host.geo.continent_name"         // Name of the continent.
	GeoCountryIsoCode       fields.Field = "host.geo.country_iso_code"       // Country ISO code.
	GeoCountryName          fields.Field = "host.geo.country_name"           // Country name.
	GeoLocation             fields.Field = "host.geo.location"               // Longitude and latitude.
	GeoName                 fields.Field = "host.geo.name"                   // User-defined description of a location.
	GeoPostalCode           fields.Field = "host.geo.postal_code"            // Postal code.
	GeoRegionIsoCode        fields.Field = "host.geo.region_iso_code"        // Region ISO code.
	GeoRegionName           fields.Field = "host.geo.region_name"            // Region name.
	GeoTimezone             fields.Field = "host.geo.timezone"               // The time zone of the location, such as IANA time zone name.
	Hostname                fields.Field = "host.hostname"                   // Hostname of the host.
	ID                      fields.Field = "host.id"                         // Unique host id.
	Ip                      fields.Field = "host.ip"                         // Host ip addresses.
	Mac                     fields.Field = "host.mac"                        // Host MAC addresses.
	Name                    fields.Field = "host.name"                       // Name of the host.
	NetworkEgressBytes      fields.Field = "host.network.egress.bytes"       // The number of bytes sent on all network interfaces.
	NetworkEgressPackets    fields.Field = "host.network.egress.packets"     // The number of packets sent on all network interfaces.
	NetworkIngressBytes     fields.Field = "host.network.ingress.bytes"      // The number of bytes received on all network interfaces.
	NetworkIngressPackets   fields.Field = "host.network.ingress.packets"    // The number of packets received on all network interfaces.
	OsFamily                fields.Field = "host.os.family"                  // OS family (such as redhat, debian, freebsd, windows).
	OsFull                  fields.Field = "host.os.full"                    // Operating system name, including the version or code name.
	OsKernel                fields.Field = "host.os.kernel"                  // Operating system kernel version as a raw string.
	OsName                  fields.Field = "host.os.name"                    // Operating system name, without the version.
	OsPlatform              fields.Field = "host.os.platform"                // Operating system platform (such centos, ubuntu, windows).
	OsType                  fields.Field = "host.os.type"                    // Which commercial OS family (one of: linux, macos, unix, windows, ios or android).
	OsVersion               fields.Field = "host.os.version"                 // Operating system version as a raw string.
	PidNsIno                fields.Field = "host.pid_ns_ino"                 // Pid namespace inode
	RiskCalculatedLevel     fields.Field = "host.risk.calculated_level"      // A risk classification level calculated by an internal system as part of entity analytics and entity risk scoring.
	RiskCalculatedScore     fields.Field = "host.risk.calculated_score"      // A risk classification score calculated by an internal system as part of entity analytics and entity risk scoring.
	RiskCalculatedScoreNorm fields.Field = "host.risk.calculated_score_norm" // A normalized risk score calculated by an internal system.
	RiskStaticLevel         fields.Field = "host.risk.static_level"          // A risk classification level obtained from outside the system, such as from some external Threat Intelligence Platform.
	RiskStaticScore         fields.Field = "host.risk.static_score"          // A risk classification score obtained from outside the system, such as from some external Threat Intelligence Platform.
	RiskStaticScoreNorm     fields.Field = "host.risk.static_score_norm"     // A normalized risk score calculated by an external system.
	Type                    fields.Field = "host.type"                       // Type of host.
	Uptime                  fields.Field = "host.uptime"                     // Seconds the host has been up.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Architecture,
	BootID,
	CpuUsage,
	DiskReadBytes,
	DiskWriteBytes,
	Domain,
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
	Type,
	Uptime,
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

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Architecture            fields.KeyWord
	BootID                  fields.KeyWord
	CpuUsage                fields.Float
	DiskReadBytes           fields.Long
	DiskWriteBytes          fields.Long
	Domain                  fields.KeyWord
	GeoCityName             fields.KeyWord
	GeoContinentCode        fields.KeyWord
	GeoContinentName        fields.KeyWord
	GeoCountryIsoCode       fields.KeyWord
	GeoCountryName          fields.KeyWord
	GeoLocation             fields.GeoPoint
	GeoName                 fields.KeyWord
	GeoPostalCode           fields.KeyWord
	GeoRegionIsoCode        fields.KeyWord
	GeoRegionName           fields.KeyWord
	GeoTimezone             fields.KeyWord
	Hostname                fields.KeyWord
	ID                      fields.KeyWord
	Ip                      fields.IP
	Mac                     fields.KeyWord
	Name                    fields.KeyWord
	NetworkEgressBytes      fields.Long
	NetworkEgressPackets    fields.Long
	NetworkIngressBytes     fields.Long
	NetworkIngressPackets   fields.Long
	OsFamily                fields.KeyWord
	OsFull                  fields.KeyWord
	OsKernel                fields.KeyWord
	OsName                  fields.KeyWord
	OsPlatform              fields.KeyWord
	OsType                  fields.KeyWord
	OsVersion               fields.KeyWord
	PidNsIno                fields.KeyWord
	RiskCalculatedLevel     fields.KeyWord
	RiskCalculatedScore     fields.Float
	RiskCalculatedScoreNorm fields.Float
	RiskStaticLevel         fields.KeyWord
	RiskStaticScore         fields.Float
	RiskStaticScoreNorm     fields.Float
	Type                    fields.KeyWord
	Uptime                  fields.Long
}

var Types TypesType = TypesType{}
