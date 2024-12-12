package dll

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	CodeSignatureDigestAlgorithm fields.Field = "dll.code_signature.digest_algorithm" // Hashing algorithm used to sign the process.
	CodeSignatureExists          fields.Field = "dll.code_signature.exists"           // Boolean to capture if a signature is present.
	CodeSignatureFlags           fields.Field = "dll.code_signature.flags"            // Code signing flags of the process
	CodeSignatureSigningID       fields.Field = "dll.code_signature.signing_id"       // The identifier used to sign the process.
	CodeSignatureStatus          fields.Field = "dll.code_signature.status"           // Additional information about the certificate status.
	CodeSignatureSubjectName     fields.Field = "dll.code_signature.subject_name"     // Subject name of the code signer
	CodeSignatureTeamID          fields.Field = "dll.code_signature.team_id"          // The team identifier used to sign the process.
	CodeSignatureTimestamp       fields.Field = "dll.code_signature.timestamp"        // When the signature was generated and signed.
	CodeSignatureTrusted         fields.Field = "dll.code_signature.trusted"          // Stores the trust status of the certificate chain.
	CodeSignatureValid           fields.Field = "dll.code_signature.valid"            // Boolean to capture if the digital signature is verified against the binary content.
	HashCdhash                   fields.Field = "dll.hash.cdhash"                     // The Code Directory (CD) hash of an executable.
	HashMd5                      fields.Field = "dll.hash.md5"                        // MD5 hash.
	HashSha1                     fields.Field = "dll.hash.sha1"                       // SHA1 hash.
	HashSha256                   fields.Field = "dll.hash.sha256"                     // SHA256 hash.
	HashSha384                   fields.Field = "dll.hash.sha384"                     // SHA384 hash.
	HashSha512                   fields.Field = "dll.hash.sha512"                     // SHA512 hash.
	HashSsdeep                   fields.Field = "dll.hash.ssdeep"                     // SSDEEP hash.
	HashTlsh                     fields.Field = "dll.hash.tlsh"                       // TLSH hash.
	Name                         fields.Field = "dll.name"                            // Name of the library.
	Path                         fields.Field = "dll.path"                            // Full file path of the library.
	PeArchitecture               fields.Field = "dll.pe.architecture"                 // CPU architecture target for the file.
	PeCompany                    fields.Field = "dll.pe.company"                      // Internal company name of the file, provided at compile-time.
	PeDescription                fields.Field = "dll.pe.description"                  // Internal description of the file, provided at compile-time.
	PeFileVersion                fields.Field = "dll.pe.file_version"                 // Process name.
	PeGoImportHash               fields.Field = "dll.pe.go_import_hash"               // A hash of the Go language imports in a PE file.
	PeGoImports                  fields.Field = "dll.pe.go_imports"                   // List of imported Go language element names and types.
	PeGoImportsNamesEntropy      fields.Field = "dll.pe.go_imports_names_entropy"     // Shannon entropy calculation from the list of Go imports.
	PeGoImportsNamesVarEntropy   fields.Field = "dll.pe.go_imports_names_var_entropy" // Variance for Shannon entropy calculation from the list of Go imports.
	PeGoStripped                 fields.Field = "dll.pe.go_stripped"                  // Whether the file is a stripped or obfuscated Go executable.
	PeImphash                    fields.Field = "dll.pe.imphash"                      // A hash of the imports in a PE file.
	PeImportHash                 fields.Field = "dll.pe.import_hash"                  // A hash of the imports in a PE file.
	PeImports                    fields.Field = "dll.pe.imports"                      // List of imported element names and types.
	PeImportsNamesEntropy        fields.Field = "dll.pe.imports_names_entropy"        // Shannon entropy calculation from the list of imported element names and types.
	PeImportsNamesVarEntropy     fields.Field = "dll.pe.imports_names_var_entropy"    // Variance for Shannon entropy calculation from the list of imported element names and types.
	PeOriginalFileName           fields.Field = "dll.pe.original_file_name"           // Internal name of the file, provided at compile-time.
	PePehash                     fields.Field = "dll.pe.pehash"                       // A hash of the PE header and data from one or more PE sections.
	PeProduct                    fields.Field = "dll.pe.product"                      // Internal product name of the file, provided at compile-time.
	PeSections                   fields.Field = "dll.pe.sections"                     // Section information of the PE file.
	PeSectionsEntropy            fields.Field = "dll.pe.sections.entropy"             // Shannon entropy calculation from the section.
	PeSectionsName               fields.Field = "dll.pe.sections.name"                // PE Section List name.
	PeSectionsPhysicalSize       fields.Field = "dll.pe.sections.physical_size"       // PE Section List physical size.
	PeSectionsVarEntropy         fields.Field = "dll.pe.sections.var_entropy"         // Variance for Shannon entropy calculation from the section.
	PeSectionsVirtualSize        fields.Field = "dll.pe.sections.virtual_size"        // PE Section List virtual size. This is always the same as `physical_size`.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	CodeSignatureDigestAlgorithm,
	CodeSignatureExists,
	CodeSignatureFlags,
	CodeSignatureSigningID,
	CodeSignatureStatus,
	CodeSignatureSubjectName,
	CodeSignatureTeamID,
	CodeSignatureTimestamp,
	CodeSignatureTrusted,
	CodeSignatureValid,
	HashCdhash,
	HashMd5,
	HashSha1,
	HashSha256,
	HashSha384,
	HashSha512,
	HashSsdeep,
	HashTlsh,
	Name,
	Path,
	PeArchitecture,
	PeCompany,
	PeDescription,
	PeFileVersion,
	PeGoImportHash,
	PeGoImports,
	PeGoImportsNamesEntropy,
	PeGoImportsNamesVarEntropy,
	PeGoStripped,
	PeImphash,
	PeImportHash,
	PeImports,
	PeImportsNamesEntropy,
	PeImportsNamesVarEntropy,
	PeOriginalFileName,
	PePehash,
	PeProduct,
	PeSections,
	PeSectionsEntropy,
	PeSectionsName,
	PeSectionsPhysicalSize,
	PeSectionsVarEntropy,
	PeSectionsVirtualSize,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	CodeSignatureDigestAlgorithm fields.KeyWord
	CodeSignatureExists          fields.Boolean
	CodeSignatureFlags           fields.KeyWord
	CodeSignatureSigningID       fields.KeyWord
	CodeSignatureStatus          fields.KeyWord
	CodeSignatureSubjectName     fields.KeyWord
	CodeSignatureTeamID          fields.KeyWord
	CodeSignatureTimestamp       fields.Date
	CodeSignatureTrusted         fields.Boolean
	CodeSignatureValid           fields.Boolean
	HashCdhash                   fields.KeyWord
	HashMd5                      fields.KeyWord
	HashSha1                     fields.KeyWord
	HashSha256                   fields.KeyWord
	HashSha384                   fields.KeyWord
	HashSha512                   fields.KeyWord
	HashSsdeep                   fields.KeyWord
	HashTlsh                     fields.KeyWord
	Name                         fields.KeyWord
	Path                         fields.KeyWord
	PeArchitecture               fields.KeyWord
	PeCompany                    fields.KeyWord
	PeDescription                fields.KeyWord
	PeFileVersion                fields.KeyWord
	PeGoImportHash               fields.KeyWord
	PeGoImports                  fields.Flattened
	PeGoImportsNamesEntropy      fields.Long
	PeGoImportsNamesVarEntropy   fields.Long
	PeGoStripped                 fields.Boolean
	PeImphash                    fields.KeyWord
	PeImportHash                 fields.KeyWord
	PeImports                    fields.Flattened
	PeImportsNamesEntropy        fields.Long
	PeImportsNamesVarEntropy     fields.Long
	PeOriginalFileName           fields.KeyWord
	PePehash                     fields.KeyWord
	PeProduct                    fields.KeyWord
	PeSections                   fields.Nested
	PeSectionsEntropy            fields.Long
	PeSectionsName               fields.KeyWord
	PeSectionsPhysicalSize       fields.Long
	PeSectionsVarEntropy         fields.Long
	PeSectionsVirtualSize        fields.Long
}

var Types TypesType = TypesType{}
