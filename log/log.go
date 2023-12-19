package log

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	FilePath             fields.Field = "log.file.path"              // Full path to the log file this event came from.
	Level                fields.Field = "log.level"                  // Log level of the log event.
	Logger               fields.Field = "log.logger"                 // Name of the logger.
	OriginFileLine       fields.Field = "log.origin.file.line"       // The line number of the file which originated the log event.
	OriginFileName       fields.Field = "log.origin.file.name"       // The code file which originated the log event.
	OriginFunction       fields.Field = "log.origin.function"        // The function which originated the log event.
	SyslogAppname        fields.Field = "log.syslog.appname"         // The device or application that originated the Syslog message.
	SyslogFacilityCode   fields.Field = "log.syslog.facility.code"   // Syslog numeric facility of the event.
	SyslogFacilityName   fields.Field = "log.syslog.facility.name"   // Syslog text-based facility of the event.
	SyslogHostname       fields.Field = "log.syslog.hostname"        // The host that originated the Syslog message.
	SyslogMsgid          fields.Field = "log.syslog.msgid"           // An identifier for the type of Syslog message.
	SyslogPriority       fields.Field = "log.syslog.priority"        // Syslog priority of the event.
	SyslogProcid         fields.Field = "log.syslog.procid"          // The process name or ID that originated the Syslog message.
	SyslogSeverityCode   fields.Field = "log.syslog.severity.code"   // Syslog numeric severity of the event.
	SyslogSeverityName   fields.Field = "log.syslog.severity.name"   // Syslog text-based severity of the event.
	SyslogStructuredData fields.Field = "log.syslog.structured_data" // Structured data expressed in RFC 5424 messages.
	SyslogVersion        fields.Field = "log.syslog.version"         // Syslog protocol version.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	FilePath,
	Level,
	Logger,
	OriginFileLine,
	OriginFileName,
	OriginFunction,
	SyslogAppname,
	SyslogFacilityCode,
	SyslogFacilityName,
	SyslogHostname,
	SyslogMsgid,
	SyslogPriority,
	SyslogProcid,
	SyslogSeverityCode,
	SyslogSeverityName,
	SyslogStructuredData,
	SyslogVersion,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	FilePath             fields.KeyWord
	Level                fields.KeyWord
	Logger               fields.KeyWord
	OriginFileLine       fields.Long
	OriginFileName       fields.KeyWord
	OriginFunction       fields.KeyWord
	SyslogAppname        fields.KeyWord
	SyslogFacilityCode   fields.Long
	SyslogFacilityName   fields.KeyWord
	SyslogHostname       fields.KeyWord
	SyslogMsgid          fields.KeyWord
	SyslogPriority       fields.Long
	SyslogProcid         fields.KeyWord
	SyslogSeverityCode   fields.Long
	SyslogSeverityName   fields.KeyWord
	SyslogStructuredData fields.Flattened
	SyslogVersion        fields.KeyWord
}

var Types TypesType = TypesType{}
