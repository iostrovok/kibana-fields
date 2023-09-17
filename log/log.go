package log

/*
	Details about the event’s logging mechanism or logging transport.

	The log.* fields are typically populated with details about the logging mechanism used to create and/or
	transport the event. For example, syslog details belong under log.syslog.*.

	The details specific to your event source are typically not logged under log.*,
	but rather in event.* or in other ECS fields.
*/

import "github.com/iostrovok/kibana-fields/face"

// All available fields as constants
const (
	FilePath       face.Field = "log.file.path"        // Original log level of the log event. type: keyword
	Level          face.Field = "log.level"            // Original log level of the log event. type: keyword
	Logger         face.Field = "log.logger"           // The name of the logger inside an application.
	OriginFileLine face.Field = "log.origin.file.line" // The line number of the file containing the source code which originated the log event. type: integer
	OriginFileName face.Field = "log.origin.file.name" // The name of the file containing the source code which originated the log event. Note that this is not the name of the log file. type: keyword
	OriginFunction face.Field = "log.origin.function"  // The name of the function or method which originated the log event. type: keyword
	Syslog         face.Field = "log.syslog"           // The Syslog metadata of the event, if the event was transmitted via Syslog. Please see RFCs 5424 or 3164.

	SyslogAppname        face.Field = "log.syslog.appname"         // The device or application that originated the Syslog message, if available.
	SyslogFacilityCode   face.Field = "log.syslog.facility.code"   // The Syslog numeric facility of the log event, if available. According to RFCs 5424 and 3164, this value should be an integer between 0 and 23.
	SyslogFacilityName   face.Field = "log.syslog.facility.name"   // The Syslog text-based facility of the log event, if available.
	SyslogHostname       face.Field = "log.syslog.hostname"        // The hostname, FQDN, or IP of the machine that originally sent the Syslog message. This is sourced from the hostname field of the syslog header. Depending on the environment, this value may be different from the host that handled the event, especially if the host handling the events is acting as a collector.
	SyslogMsgid          face.Field = "log.syslog.msgid"           // An identifier for the type of Syslog message, if available. Only applicable for RFC 5424 messages.
	SyslogPriority       face.Field = "log.syslog.priority"        // Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 * facility + severity. This number is therefore expected to contain a value between 0 and 191.
	SyslogProcid         face.Field = "log.syslog.procid"          //  The process name or ID that originated the Syslog message, if available.
	SyslogSeverityCode   face.Field = "log.syslog.severity.code"   //  The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different numeric severity value (e.g. firewall, IDS), your source’s numeric severity should go to event.severity. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to event.severity.
	SyslogSeverityName   face.Field = "log.syslog.severity.name"   // The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different severity value (e.g. firewall, IDS), your source’s text severity should go to log.level. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to log.level.
	SyslogStructuredData face.Field = "log.syslog.structured_data" // Structured data expressed in RFC 5424 messages, if available. These are key-value pairs formed from the structured data portion of the syslog message, as defined in RFC 5424 Section 6.3.
	SyslogVersion        face.Field = "log.syslog.version"         // The version of the Syslog protocol specification. Only applicable for RFC 5424 messages.
)

// All package constants as list
var Fields = []face.Field{
	FilePath,
	Level,
	Logger,
	OriginFileLine,
	OriginFileName,
	OriginFunction,
	Syslog,
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

// Types describes kibana types of fields
var Types = map[face.Field]face.Type{
	FilePath:             face.KeyWord,
	Level:                face.KeyWord,
	Logger:               face.KeyWord,
	OriginFileLine:       face.Long,
	OriginFileName:       face.KeyWord,
	OriginFunction:       face.KeyWord,
	Syslog:               face.Object,
	SyslogAppname:        face.KeyWord,
	SyslogFacilityCode:   face.Long,
	SyslogFacilityName:   face.KeyWord,
	SyslogHostname:       face.KeyWord,
	SyslogMsgid:          face.KeyWord,
	SyslogPriority:       face.Long,
	SyslogProcid:         face.KeyWord,
	SyslogSeverityCode:   face.Long,
	SyslogSeverityName:   face.KeyWord,
	SyslogStructuredData: face.Flattened,
	SyslogVersion:        face.KeyWord,
}
