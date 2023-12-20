package dns

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	AnswersClass             fields.Field = "dns.answers.class"              // The class of DNS data contained in this resource record.
	AnswersData              fields.Field = "dns.answers.data"               // The data describing the resource.
	AnswersName              fields.Field = "dns.answers.name"               // The domain name to which this resource record pertains.
	AnswersTtl               fields.Field = "dns.answers.ttl"                // The time interval in seconds that this resource record may be cached before it should be discarded.
	AnswersType              fields.Field = "dns.answers.type"               // The type of data contained in this resource record.
	HeaderFlags              fields.Field = "dns.header_flags"               // Array of DNS header flags.
	ID                       fields.Field = "dns.id"                         // The DNS packet identifier assigned by the program that generated the query. The identifier is copied to the response.
	OpCode                   fields.Field = "dns.op_code"                    // The DNS operation code that specifies the kind of query in the message.
	QuestionClass            fields.Field = "dns.question.class"             // The class of records being queried.
	QuestionName             fields.Field = "dns.question.name"              // The name being queried.
	QuestionRegisteredDomain fields.Field = "dns.question.registered_domain" // The highest registered domain, stripped of the subdomain.
	QuestionSubdomain        fields.Field = "dns.question.subdomain"         // The subdomain of the domain.
	QuestionTopLevelDomain   fields.Field = "dns.question.top_level_domain"  // The effective top level domain (com, org, net, co.uk).
	QuestionType             fields.Field = "dns.question.type"              // The type of record being queried.
	ResolvedIp               fields.Field = "dns.resolved_ip"                // Array containing all IPs seen in answers.data
	ResponseCode             fields.Field = "dns.response_code"              // The DNS response code.
	Type                     fields.Field = "dns.type"                       // The type of DNS event captured, query or answer.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	AnswersClass,
	AnswersData,
	AnswersName,
	AnswersTtl,
	AnswersType,
	HeaderFlags,
	ID,
	OpCode,
	QuestionClass,
	QuestionName,
	QuestionRegisteredDomain,
	QuestionSubdomain,
	QuestionTopLevelDomain,
	QuestionType,
	ResolvedIp,
	ResponseCode,
	Type,
}

type HeaderFlagsExpectedType struct {
	AA string
	AD string
	CD string
	DO string
	RA string
	RD string
	TC string
}

var HeaderFlagsExpectedValues HeaderFlagsExpectedType = HeaderFlagsExpectedType{
	AA: `AA`,
	AD: `AD`,
	CD: `CD`,
	DO: `DO`,
	RA: `RA`,
	RD: `RD`,
	TC: `TC`,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	AnswersClass             fields.KeyWord
	AnswersData              fields.KeyWord
	AnswersName              fields.KeyWord
	AnswersTtl               fields.Long
	AnswersType              fields.KeyWord
	HeaderFlags              fields.KeyWord
	ID                       fields.KeyWord
	OpCode                   fields.KeyWord
	QuestionClass            fields.KeyWord
	QuestionName             fields.KeyWord
	QuestionRegisteredDomain fields.KeyWord
	QuestionSubdomain        fields.KeyWord
	QuestionTopLevelDomain   fields.KeyWord
	QuestionType             fields.KeyWord
	ResolvedIp               fields.IP
	ResponseCode             fields.KeyWord
	Type                     fields.KeyWord
}

var Types TypesType = TypesType{}
