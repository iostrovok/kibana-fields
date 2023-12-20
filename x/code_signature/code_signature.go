package code_signature

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	CodeSignatureDigestAlgorithm fields.Field = "code_signature.digest_algorithm" // Hashing algorithm used to sign the process.
	CodeSignatureExists          fields.Field = "code_signature.exists"           // Boolean to capture if a signature is present.
	CodeSignatureSigningID       fields.Field = "code_signature.signing_id"       // The identifier used to sign the process.
	CodeSignatureStatus          fields.Field = "code_signature.status"           // Additional information about the certificate status.
	CodeSignatureSubjectName     fields.Field = "code_signature.subject_name"     // Subject name of the code signer
	CodeSignatureTeamID          fields.Field = "code_signature.team_id"          // The team identifier used to sign the process.
	CodeSignatureTimestamp       fields.Field = "code_signature.timestamp"        // When the signature was generated and signed.
	CodeSignatureTrusted         fields.Field = "code_signature.trusted"          // Stores the trust status of the certificate chain.
	CodeSignatureValid           fields.Field = "code_signature.valid"            // Boolean to capture if the digital signature is verified against the binary content.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	CodeSignatureDigestAlgorithm,
	CodeSignatureExists,
	CodeSignatureSigningID,
	CodeSignatureStatus,
	CodeSignatureSubjectName,
	CodeSignatureTeamID,
	CodeSignatureTimestamp,
	CodeSignatureTrusted,
	CodeSignatureValid,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	CodeSignatureDigestAlgorithm fields.KeyWord
	CodeSignatureExists          fields.Boolean
	CodeSignatureSigningID       fields.KeyWord
	CodeSignatureStatus          fields.KeyWord
	CodeSignatureSubjectName     fields.KeyWord
	CodeSignatureTeamID          fields.KeyWord
	CodeSignatureTimestamp       fields.Date
	CodeSignatureTrusted         fields.Boolean
	CodeSignatureValid           fields.Boolean
}

var Types TypesType = TypesType{}
