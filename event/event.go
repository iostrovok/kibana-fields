package event

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Action        fields.Field = "event.action"          // The action captured by the event.
	AgentIDStatus fields.Field = "event.agent_id_status" // Validation status of the event's agent.id field.
	Category      fields.Field = "event.category"        // Event category. The second categorization field in the hierarchy.
	Code          fields.Field = "event.code"            // Identification code for this event.
	Created       fields.Field = "event.created"         // Time when the event was first read by an agent or by your pipeline.
	Dataset       fields.Field = "event.dataset"         // Name of the dataset.
	Duration      fields.Field = "event.duration"        // Duration of the event in nanoseconds.
	End           fields.Field = "event.end"             // `event.end` contains the date when the event ended or when the activity was last observed.
	Hash          fields.Field = "event.hash"            // Hash (perhaps logstash fingerprint) of raw field to be able to demonstrate log integrity.
	ID            fields.Field = "event.id"              // Unique ID to describe the event.
	Ingested      fields.Field = "event.ingested"        // Timestamp when an event arrived in the central data store.
	Kind          fields.Field = "event.kind"            // The kind of the event. The highest categorization field in the hierarchy.
	Module        fields.Field = "event.module"          // Name of the module this data is coming from.
	Original      fields.Field = "event.original"        // Raw text message of entire event.
	Outcome       fields.Field = "event.outcome"         // The outcome of the event. The lowest level categorization field in the hierarchy.
	Provider      fields.Field = "event.provider"        // Source of the event.
	Reason        fields.Field = "event.reason"          // Reason why this event happened, according to the source
	Reference     fields.Field = "event.reference"       // Event reference URL
	RiskScore     fields.Field = "event.risk_score"      // Risk score or priority of the event (e.g. security solutions). Use your system's original value here.
	RiskScoreNorm fields.Field = "event.risk_score_norm" // Normalized risk score or priority of the event (0-100).
	Sequence      fields.Field = "event.sequence"        // Sequence number of the event.
	Severity      fields.Field = "event.severity"        // Numeric severity of the event.
	Start         fields.Field = "event.start"           // `event.start` contains the date when the event started or when the activity was first observed.
	Timezone      fields.Field = "event.timezone"        // Event time zone.
	Type          fields.Field = "event.type"            // Event type. The third categorization field in the hierarchy.
	Url           fields.Field = "event.url"             // Event investigation URL

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Action,
	AgentIDStatus,
	Category,
	Code,
	Created,
	Dataset,
	Duration,
	End,
	Hash,
	ID,
	Ingested,
	Kind,
	Module,
	Original,
	Outcome,
	Provider,
	Reason,
	Reference,
	RiskScore,
	RiskScoreNorm,
	Sequence,
	Severity,
	Start,
	Timezone,
	Type,
	Url,
}

type CategoryAllowedType struct {
	Api                string // Events in this category annotate API calls that occured on a system. Typical sources for those events could be from the Operating System level through the native libraries (for example Windows Win32, Linux libc, etc.), or managed sources of events (such as ETW, syslog), but can also include network protocols (such as SOAP, RPC, Websocket, REST, etc.)
	Authentication     string // Events in this category are related to the challenge and response process in which credentials are supplied and verified to allow the creation of a session. Common sources for these logs are Windows event logs and ssh logs. Visualize and analyze events in this category to look for failed logins, and other authentication-related activity.
	Configuration      string // Events in the configuration category have to deal with creating, modifying, or deleting the settings or parameters of an application, process, or system. Example sources include security policy change logs, configuration auditing logging, and system integrity monitoring.
	Database           string // The database category denotes events and metrics relating to a data storage and retrieval system. Note that use of this category is not limited to relational database systems. Examples include event logs from MS SQL, MySQL, Elasticsearch, MongoDB, etc. Use this category to visualize and analyze database activity such as accesses and changes.
	Driver             string // Events in the driver category have to do with operating system device drivers and similar software entities such as Windows drivers, kernel extensions, kernel modules, etc. Use events and metrics in this category to visualize and analyze driver-related activity and status on hosts.
	Email              string // This category is used for events relating to email messages, email attachments, and email network or protocol activity. Emails events can be produced by email security gateways, mail transfer agents, email cloud service providers, or mail server monitoring applications.
	File               string // Relating to a set of information that has been created on, or has existed on a filesystem. Use this category of events to visualize and analyze the creation, access, and deletions of files. Events in this category can come from both host-based and network-based sources. An example source of a network-based detection of a file transfer would be the Zeek file.log.
	Host               string // Use this category to visualize and analyze information such as host inventory or host lifecycle events. Most of the events in this category can usually be observed from the outside, such as from a hypervisor or a control plane's point of view. Some can also be seen from within, such as "start" or "end". Note that this category is for information about hosts themselves; it is not meant to capture activity "happening on a host".
	Iam                string // Identity and access management (IAM) events relating to users, groups, and administration. Use this category to visualize and analyze IAM-related logs and data from active directory, LDAP, Okta, Duo, and other IAM systems.
	IntrusionDetection string // Relating to intrusion detections from IDS/IPS systems and functions, both network and host-based. Use this category to visualize and analyze intrusion detection alerts from systems such as Snort, Suricata, and Palo Alto threat detections.
	Library            string // Events in this category refer to the loading of a library, such as (dll / so / dynlib), into a process. Use this category to visualize and analyze library loading related activity on hosts.  Keep in mind that driver related activity will be captured under the "driver" category above.
	Malware            string // Malware detection events and alerts. Use this category to visualize and analyze malware detections from EDR/EPP systems such as Elastic Endpoint Security, Symantec Endpoint Protection, Crowdstrike, and network IDS/IPS systems such as Suricata, or other sources of malware-related events such as Palo Alto Networks threat logs and Wildfire logs.
	Network            string // Relating to all network activity, including network connection lifecycle, network traffic, and essentially any event that includes an IP address. Many events containing decoded network protocol transactions fit into this category. Use events in this category to visualize or analyze counts of network ports, protocols, addresses, geolocation information, etc.
	Package            string // Relating to software packages installed on hosts. Use this category to visualize and analyze inventory of software installed on various hosts, or to determine host vulnerability in the absence of vulnerability scan data.
	Process            string // Use this category of events to visualize and analyze process-specific information such as lifecycle events or process ancestry.
	Registry           string // Having to do with settings and assets stored in the Windows registry. Use this category to visualize and analyze activity such as registry access and modifications.
	Session            string // The session category is applied to events and metrics regarding logical persistent connections to hosts and services. Use this category to visualize and analyze interactive or automated persistent connections between assets. Data for this category may come from Windows Event logs, SSH logs, or stateless sessions such as HTTP cookie-based sessions, etc.
	Threat             string // Use this category to visualize and analyze events describing threat actors' targets, motives, or behaviors.
	Vulnerability      string // Relating to vulnerability scan results. Use this category to analyze vulnerabilities detected by Tenable, Qualys, internal scanners, and other vulnerability management sources.
	Web                string // Relating to web server access. Use this category to create a dashboard of web server/proxy activity from apache, IIS, nginx web servers, etc. Note: events from network observers such as Zeek http log may also be included in this category.

}

var CategoryAllowedValues CategoryAllowedType = CategoryAllowedType{
	Api:                `api`,
	Authentication:     `authentication`,
	Configuration:      `configuration`,
	Database:           `database`,
	Driver:             `driver`,
	Email:              `email`,
	File:               `file`,
	Host:               `host`,
	Iam:                `iam`,
	IntrusionDetection: `intrusion_detection`,
	Library:            `library`,
	Malware:            `malware`,
	Network:            `network`,
	Package:            `package`,
	Process:            `process`,
	Registry:           `registry`,
	Session:            `session`,
	Threat:             `threat`,
	Vulnerability:      `vulnerability`,
	Web:                `web`,
}

type KindAllowedType struct {
	Alert         string // This value indicates an event such as an alert or notable event, triggered by a detection rule executing externally to the Elastic Stack. `event.kind:alert` is often populated for events coming from firewalls, intrusion detection systems, endpoint detection and response systems, and so on. This value is not used by Elastic solutions for alert documents that are created by rules executing within the Kibana alerting framework.
	Asset         string // This value indicates events whose primary purpose is to store an inventory of assets/entities and their attributes. Assets/entities are objects (such as users and hosts) that are expected to be subjects of detailed analysis within the system. Examples include lists of user identities or accounts ingested from directory services such as Active Directory (AD), inventory of hosts pulled from configuration management databases (CMDB), and lists of cloud storage buckets pulled from cloud provider APIs. This value is used by Elastic Security for asset management solutions. `event.kind: asset` is not used for normal system events or logs that are coming from an asset/entity, nor is it used for system events or logs coming from a directory or CMDB system.
	Enrichment    string // The `enrichment` value indicates an event collected to provide additional context, often to other events. An example is collecting indicators of compromise (IOCs) from a threat intelligence provider with the intent to use those values to enrich other events. The IOC events from the intelligence provider should be categorized as `event.kind:enrichment`.
	Event         string // This value is the most general and most common value for this field. It is used to represent events that indicate that something happened.
	Metric        string // This value is used to indicate that this event describes a numeric measurement taken at given point in time. Examples include CPU utilization, memory usage, or device temperature. Metric events are often collected on a predictable frequency, such as once every few seconds, or once a minute, but can also be used to describe ad-hoc numeric metric queries.
	PipelineError string // This value indicates that an error occurred during the ingestion of this event, and that event data may be missing, inconsistent, or incorrect. `event.kind:pipeline_error` is often associated with parsing errors.
	Signal        string // This value is used by Elastic solutions (e.g., Security, Observability) for alert documents that are created by rules executing within the Kibana alerting framework. Usage of this value is reserved, and data ingestion pipelines must not populate `event.kind` with the value "signal".
	State         string // The state value is similar to metric, indicating that this event describes a measurement taken at given point in time, except that the measurement does not result in a numeric value, but rather one of a fixed set of categorical values that represent conditions or states. Examples include periodic events reporting Elasticsearch cluster state (green/yellow/red), the state of a TCP connection (open, closed, fin_wait, etc.), the state of a host with respect to a software vulnerability (vulnerable, not vulnerable), and the state of a system regarding compliance with a regulatory standard (compliant, not compliant). Note that an event that describes a change of state would not use `event.kind:state`, but instead would use 'event.kind:event' since a state change fits the more general event definition of something that happened. State events are often collected on a predictable frequency, such as once every few seconds, once a minute, once an hour, or once a day, but can also be used to describe ad-hoc state queries.

}

var KindAllowedValues KindAllowedType = KindAllowedType{
	Alert:         `alert`,
	Asset:         `asset`,
	Enrichment:    `enrichment`,
	Event:         `event`,
	Metric:        `metric`,
	PipelineError: `pipeline_error`,
	Signal:        `signal`,
	State:         `state`,
}

type OutcomeAllowedType struct {
	Failure string // Indicates that this event describes a failed result. A common example is `event.category:file AND event.type:access AND event.outcome:failure` to indicate that a file access was attempted, but was not successful.
	Success string // Indicates that this event describes a successful result. A common example is `event.category:file AND event.type:create AND event.outcome:success` to indicate that a file was successfully created.
	Unknown string // Indicates that this event describes only an attempt for which the result is unknown from the perspective of the event producer. For example, if the event contains information only about the request side of a transaction that results in a response, populating `event.outcome:unknown` in the request event is appropriate. The unknown value should not be used when an outcome doesn't make logical sense for the event. In such cases `event.outcome` should not be populated.

}

var OutcomeAllowedValues OutcomeAllowedType = OutcomeAllowedType{
	Failure: `failure`,
	Success: `success`,
	Unknown: `unknown`,
}

type TypeAllowedType struct {
	Access       string // The access event type is used for the subset of events within a category that indicate that something was accessed. Common examples include `event.category:database AND event.type:access`, or `event.category:file AND event.type:access`. Note for file access, both directory listings and file opens should be included in this subcategory. You can further distinguish access operations using the ECS `event.action` field.
	Admin        string // The admin event type is used for the subset of events within a category that are related to admin objects. For example, administrative changes within an IAM framework that do not specifically affect a user or group (e.g., adding new applications to a federation solution or connecting discrete forests in Active Directory) would fall into this subcategory. Common example: `event.category:iam AND event.type:change AND event.type:admin`. You can further distinguish admin operations using the ECS `event.action` field.
	Allowed      string // The allowed event type is used for the subset of events within a category that indicate that something was allowed. Common examples include `event.category:network AND event.type:connection AND event.type:allowed` (to indicate a network firewall event for which the firewall disposition was to allow the connection to complete) and `event.category:intrusion_detection AND event.type:allowed` (to indicate a network intrusion prevention system event for which the IPS disposition was to allow the connection to complete). You can further distinguish allowed operations using the ECS `event.action` field, populating with values of your choosing, such as "allow", "detect", or "pass".
	Change       string // The change event type is used for the subset of events within a category that indicate that something has changed. If semantics best describe an event as modified, then include them in this subcategory. Common examples include `event.category:process AND event.type:change`, and `event.category:file AND event.type:change`. You can further distinguish change operations using the ECS `event.action` field.
	Connection   string // Used primarily with `event.category:network` this value is used for the subset of network traffic that includes sufficient information for the event to be included in flow or connection analysis. Events in this subcategory will contain at least source and destination IP addresses, source and destination TCP/UDP ports, and will usually contain counts of bytes and/or packets transferred. Events in this subcategory may contain unidirectional or bidirectional information, including summary information. Use this subcategory to visualize and analyze network connections. Flow analysis, including Netflow, IPFIX, and other flow-related events fit in this subcategory. Note that firewall events from many Next-Generation Firewall (NGFW) devices will also fit into this subcategory.  A common filter for flow/connection information would be `event.category:network AND event.type:connection AND event.type:end` (to view or analyze all completed network connections, ignoring mid-flow reports). You can further distinguish connection events using the ECS `event.action` field, populating with values of your choosing, such as "timeout", or "reset".
	Creation     string // The "creation" event type is used for the subset of events within a category that indicate that something was created. A common example is `event.category:file AND event.type:creation`.
	Deletion     string // The deletion event type is used for the subset of events within a category that indicate that something was deleted. A common example is `event.category:file AND event.type:deletion` to indicate that a file has been deleted.
	Denied       string // The denied event type is used for the subset of events within a category that indicate that something was denied. Common examples include `event.category:network AND event.type:denied` (to indicate a network firewall event for which the firewall disposition was to deny the connection) and `event.category:intrusion_detection AND event.type:denied` (to indicate a network intrusion prevention system event for which the IPS disposition was to deny the connection to complete). You can further distinguish denied operations using the ECS `event.action` field, populating with values of your choosing, such as "blocked", "dropped", or "quarantined".
	End          string // The end event type is used for the subset of events within a category that indicate something has ended. A common example is `event.category:process AND event.type:end`.
	Error        string // The error event type is used for the subset of events within a category that indicate or describe an error. A common example is `event.category:database AND event.type:error`. Note that pipeline errors that occur during the event ingestion process should not use this `event.type` value. Instead, they should use `event.kind:pipeline_error`.
	Group        string // The group event type is used for the subset of events within a category that are related to group objects. Common example: `event.category:iam AND event.type:creation AND event.type:group`. You can further distinguish group operations using the ECS `event.action` field.
	Indicator    string // The indicator event type is used for the subset of events within a category that contain details about indicators of compromise (IOCs). A common example is `event.category:threat AND event.type:indicator`.
	Info         string // The info event type is used for the subset of events within a category that indicate that they are purely informational, and don't report a state change, or any type of action. For example, an initial run of a file integrity monitoring system (FIM), where an agent reports all files under management, would fall into the "info" subcategory. Similarly, an event containing a dump of all currently running processes (as opposed to reporting that a process started/ended) would fall into the "info" subcategory. An additional common examples is `event.category:intrusion_detection AND event.type:info`.
	Installation string // The installation event type is used for the subset of events within a category that indicate that something was installed. A common example is `event.category:package` AND `event.type:installation`.
	Protocol     string // The protocol event type is used for the subset of events within a category that indicate that they contain protocol details or analysis, beyond simply identifying the protocol. Generally, network events that contain specific protocol details will fall into this subcategory. A common example is `event.category:network AND event.type:protocol AND event.type:connection AND event.type:end` (to indicate that the event is a network connection event sent at the end of a connection that also includes a protocol detail breakdown). Note that events that only indicate the name or id of the protocol should not use the protocol value. Further note that when the protocol subcategory is used, the identified protocol is populated in the ECS `network.protocol` field.
	Start        string // The start event type is used for the subset of events within a category that indicate something has started. A common example is `event.category:process AND event.type:start`.
	User         string // The user event type is used for the subset of events within a category that are related to user objects. Common example: `event.category:iam AND event.type:deletion AND event.type:user`. You can further distinguish user operations using the ECS `event.action` field.

}

var TypeAllowedValues TypeAllowedType = TypeAllowedType{
	Access:       `access`,
	Admin:        `admin`,
	Allowed:      `allowed`,
	Change:       `change`,
	Connection:   `connection`,
	Creation:     `creation`,
	Deletion:     `deletion`,
	Denied:       `denied`,
	End:          `end`,
	Error:        `error`,
	Group:        `group`,
	Indicator:    `indicator`,
	Info:         `info`,
	Installation: `installation`,
	Protocol:     `protocol`,
	Start:        `start`,
	User:         `user`,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Action        fields.KeyWord
	AgentIDStatus fields.KeyWord
	Category      fields.KeyWord
	Code          fields.KeyWord
	Created       fields.Date
	Dataset       fields.KeyWord
	Duration      fields.Long
	End           fields.Date
	Hash          fields.KeyWord
	ID            fields.KeyWord
	Ingested      fields.Date
	Kind          fields.KeyWord
	Module        fields.KeyWord
	Original      fields.KeyWord
	Outcome       fields.KeyWord
	Provider      fields.KeyWord
	Reason        fields.KeyWord
	Reference     fields.KeyWord
	RiskScore     fields.Float
	RiskScoreNorm fields.Float
	Sequence      fields.Long
	Severity      fields.Long
	Start         fields.Date
	Timezone      fields.KeyWord
	Type          fields.KeyWord
	Url           fields.KeyWord
}

var Types TypesType = TypesType{}
