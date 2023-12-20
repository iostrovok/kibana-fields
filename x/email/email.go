package email

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	AttachmentsFileExtension  fields.Field = "email.attachments.file.extension"   // Attachment file extension.
	AttachmentsFileHashMd5    fields.Field = "email.attachments.file.hash.md5"    // MD5 hash.
	AttachmentsFileHashSha1   fields.Field = "email.attachments.file.hash.sha1"   // SHA1 hash.
	AttachmentsFileHashSha256 fields.Field = "email.attachments.file.hash.sha256" // SHA256 hash.
	AttachmentsFileHashSha384 fields.Field = "email.attachments.file.hash.sha384" // SHA384 hash.
	AttachmentsFileHashSha512 fields.Field = "email.attachments.file.hash.sha512" // SHA512 hash.
	AttachmentsFileHashSsdeep fields.Field = "email.attachments.file.hash.ssdeep" // SSDEEP hash.
	AttachmentsFileHashTlsh   fields.Field = "email.attachments.file.hash.tlsh"   // TLSH hash.
	AttachmentsFileMimeType   fields.Field = "email.attachments.file.mime_type"   // MIME type of the attachment file.
	AttachmentsFileName       fields.Field = "email.attachments.file.name"        // Name of the attachment file.
	AttachmentsFileSize       fields.Field = "email.attachments.file.size"        // Attachment file size.
	BccAddress                fields.Field = "email.bcc.address"                  // Email address of BCC recipient
	CcAddress                 fields.Field = "email.cc.address"                   // Email address of CC recipient
	ContentType               fields.Field = "email.content_type"                 // MIME type of the email message.
	DeliveryTimestamp         fields.Field = "email.delivery_timestamp"           // Date and time when message was delivered.
	Direction                 fields.Field = "email.direction"                    // Direction of the message.
	FromAddress               fields.Field = "email.from.address"                 // The sender's email address.
	LocalID                   fields.Field = "email.local_id"                     // Unique identifier given by the source.
	MessageID                 fields.Field = "email.message_id"                   // Value from the Message-ID header.
	OriginationTimestamp      fields.Field = "email.origination_timestamp"        // Date and time the email was composed.
	ReplyToAddress            fields.Field = "email.reply_to.address"             // Address replies should be delivered to.
	SenderAddress             fields.Field = "email.sender.address"               // Address of the message sender.
	Subject                   fields.Field = "email.subject"                      // The subject of the email message.
	ToAddress                 fields.Field = "email.to.address"                   // Email address of recipient
	XMailer                   fields.Field = "email.x_mailer"                     // Application that drafted email.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	AttachmentsFileExtension,
	AttachmentsFileHashMd5,
	AttachmentsFileHashSha1,
	AttachmentsFileHashSha256,
	AttachmentsFileHashSha384,
	AttachmentsFileHashSha512,
	AttachmentsFileHashSsdeep,
	AttachmentsFileHashTlsh,
	AttachmentsFileMimeType,
	AttachmentsFileName,
	AttachmentsFileSize,
	BccAddress,
	CcAddress,
	ContentType,
	DeliveryTimestamp,
	Direction,
	FromAddress,
	LocalID,
	MessageID,
	OriginationTimestamp,
	ReplyToAddress,
	SenderAddress,
	Subject,
	ToAddress,
	XMailer,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	AttachmentsFileExtension  fields.KeyWord
	AttachmentsFileHashMd5    fields.KeyWord
	AttachmentsFileHashSha1   fields.KeyWord
	AttachmentsFileHashSha256 fields.KeyWord
	AttachmentsFileHashSha384 fields.KeyWord
	AttachmentsFileHashSha512 fields.KeyWord
	AttachmentsFileHashSsdeep fields.KeyWord
	AttachmentsFileHashTlsh   fields.KeyWord
	AttachmentsFileMimeType   fields.KeyWord
	AttachmentsFileName       fields.KeyWord
	AttachmentsFileSize       fields.Long
	BccAddress                fields.KeyWord
	CcAddress                 fields.KeyWord
	ContentType               fields.KeyWord
	DeliveryTimestamp         fields.Date
	Direction                 fields.KeyWord
	FromAddress               fields.KeyWord
	LocalID                   fields.KeyWord
	MessageID                 fields.Wildcard
	OriginationTimestamp      fields.Date
	ReplyToAddress            fields.KeyWord
	SenderAddress             fields.KeyWord
	Subject                   fields.KeyWord
	ToAddress                 fields.KeyWord
	XMailer                   fields.KeyWord
}

var Types TypesType = TypesType{}
