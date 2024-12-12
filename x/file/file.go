package file

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Accessed                      fields.Field = "file.accessed"                           // Last time the file was accessed.
	Attributes                    fields.Field = "file.attributes"                         // Array of file attributes.
	CodeSignatureDigestAlgorithm  fields.Field = "file.code_signature.digest_algorithm"    // Hashing algorithm used to sign the process.
	CodeSignatureExists           fields.Field = "file.code_signature.exists"              // Boolean to capture if a signature is present.
	CodeSignatureFlags            fields.Field = "file.code_signature.flags"               // Code signing flags of the process
	CodeSignatureSigningID        fields.Field = "file.code_signature.signing_id"          // The identifier used to sign the process.
	CodeSignatureStatus           fields.Field = "file.code_signature.status"              // Additional information about the certificate status.
	CodeSignatureSubjectName      fields.Field = "file.code_signature.subject_name"        // Subject name of the code signer
	CodeSignatureTeamID           fields.Field = "file.code_signature.team_id"             // The team identifier used to sign the process.
	CodeSignatureTimestamp        fields.Field = "file.code_signature.timestamp"           // When the signature was generated and signed.
	CodeSignatureTrusted          fields.Field = "file.code_signature.trusted"             // Stores the trust status of the certificate chain.
	CodeSignatureValid            fields.Field = "file.code_signature.valid"               // Boolean to capture if the digital signature is verified against the binary content.
	Created                       fields.Field = "file.created"                            // File creation time.
	Ctime                         fields.Field = "file.ctime"                              // Last time the file attributes or metadata changed.
	Device                        fields.Field = "file.device"                             // Device that is the source of the file.
	Directory                     fields.Field = "file.directory"                          // Directory where the file is located.
	DriveLetter                   fields.Field = "file.drive_letter"                       // Drive letter where the file is located.
	ElfArchitecture               fields.Field = "file.elf.architecture"                   // Machine architecture of the ELF file.
	ElfByteOrder                  fields.Field = "file.elf.byte_order"                     // Byte sequence of ELF file.
	ElfCpuType                    fields.Field = "file.elf.cpu_type"                       // CPU type of the ELF file.
	ElfCreationDate               fields.Field = "file.elf.creation_date"                  // Build or compile date.
	ElfExports                    fields.Field = "file.elf.exports"                        // List of exported element names and types.
	ElfGoImportHash               fields.Field = "file.elf.go_import_hash"                 // A hash of the Go language imports in an ELF file.
	ElfGoImports                  fields.Field = "file.elf.go_imports"                     // List of imported Go language element names and types.
	ElfGoImportsNamesEntropy      fields.Field = "file.elf.go_imports_names_entropy"       // Shannon entropy calculation from the list of Go imports.
	ElfGoImportsNamesVarEntropy   fields.Field = "file.elf.go_imports_names_var_entropy"   // Variance for Shannon entropy calculation from the list of Go imports.
	ElfGoStripped                 fields.Field = "file.elf.go_stripped"                    // Whether the file is a stripped or obfuscated Go executable.
	ElfHeaderAbiVersion           fields.Field = "file.elf.header.abi_version"             // Version of the ELF Application Binary Interface (ABI).
	ElfHeaderClass                fields.Field = "file.elf.header.class"                   // Header class of the ELF file.
	ElfHeaderData                 fields.Field = "file.elf.header.data"                    // Data table of the ELF header.
	ElfHeaderEntrypoint           fields.Field = "file.elf.header.entrypoint"              // Header entrypoint of the ELF file.
	ElfHeaderObjectVersion        fields.Field = "file.elf.header.object_version"          // "0x1" for original ELF files.
	ElfHeaderOsAbi                fields.Field = "file.elf.header.os_abi"                  // Application Binary Interface (ABI) of the Linux OS.
	ElfHeaderType                 fields.Field = "file.elf.header.type"                    // Header type of the ELF file.
	ElfHeaderVersion              fields.Field = "file.elf.header.version"                 // Version of the ELF header.
	ElfImportHash                 fields.Field = "file.elf.import_hash"                    // A hash of the imports in an ELF file.
	ElfImports                    fields.Field = "file.elf.imports"                        // List of imported element names and types.
	ElfImportsNamesEntropy        fields.Field = "file.elf.imports_names_entropy"          // Shannon entropy calculation from the list of imported element names and types.
	ElfImportsNamesVarEntropy     fields.Field = "file.elf.imports_names_var_entropy"      // Variance for Shannon entropy calculation from the list of imported element names and types.
	ElfSections                   fields.Field = "file.elf.sections"                       // Section information of the ELF file.
	ElfSectionsChi2               fields.Field = "file.elf.sections.chi2"                  // Chi-square probability distribution of the section.
	ElfSectionsEntropy            fields.Field = "file.elf.sections.entropy"               // Shannon entropy calculation from the section.
	ElfSectionsFlags              fields.Field = "file.elf.sections.flags"                 // ELF Section List flags.
	ElfSectionsName               fields.Field = "file.elf.sections.name"                  // ELF Section List name.
	ElfSectionsPhysicalOffset     fields.Field = "file.elf.sections.physical_offset"       // ELF Section List offset.
	ElfSectionsPhysicalSize       fields.Field = "file.elf.sections.physical_size"         // ELF Section List physical size.
	ElfSectionsType               fields.Field = "file.elf.sections.type"                  // ELF Section List type.
	ElfSectionsVarEntropy         fields.Field = "file.elf.sections.var_entropy"           // Variance for Shannon entropy calculation from the section.
	ElfSectionsVirtualAddress     fields.Field = "file.elf.sections.virtual_address"       // ELF Section List virtual address.
	ElfSectionsVirtualSize        fields.Field = "file.elf.sections.virtual_size"          // ELF Section List virtual size.
	ElfSegments                   fields.Field = "file.elf.segments"                       // ELF object segment list.
	ElfSegmentsSections           fields.Field = "file.elf.segments.sections"              // ELF object segment sections.
	ElfSegmentsType               fields.Field = "file.elf.segments.type"                  // ELF object segment type.
	ElfSharedLibraries            fields.Field = "file.elf.shared_libraries"               // List of shared libraries used by this ELF object.
	ElfTelfhash                   fields.Field = "file.elf.telfhash"                       // telfhash hash for ELF file.
	Extension                     fields.Field = "file.extension"                          // File extension, excluding the leading dot.
	ForkName                      fields.Field = "file.fork_name"                          // A fork is additional data associated with a filesystem object.
	Gid                           fields.Field = "file.gid"                                // Primary group ID (GID) of the file.
	Group                         fields.Field = "file.group"                              // Primary group name of the file.
	HashCdhash                    fields.Field = "file.hash.cdhash"                        // The Code Directory (CD) hash of an executable.
	HashMd5                       fields.Field = "file.hash.md5"                           // MD5 hash.
	HashSha1                      fields.Field = "file.hash.sha1"                          // SHA1 hash.
	HashSha256                    fields.Field = "file.hash.sha256"                        // SHA256 hash.
	HashSha384                    fields.Field = "file.hash.sha384"                        // SHA384 hash.
	HashSha512                    fields.Field = "file.hash.sha512"                        // SHA512 hash.
	HashSsdeep                    fields.Field = "file.hash.ssdeep"                        // SSDEEP hash.
	HashTlsh                      fields.Field = "file.hash.tlsh"                          // TLSH hash.
	Inode                         fields.Field = "file.inode"                              // Inode representing the file in the filesystem.
	MachoGoImportHash             fields.Field = "file.macho.go_import_hash"               // A hash of the Go language imports in a Mach-O file.
	MachoGoImports                fields.Field = "file.macho.go_imports"                   // List of imported Go language element names and types.
	MachoGoImportsNamesEntropy    fields.Field = "file.macho.go_imports_names_entropy"     // Shannon entropy calculation from the list of Go imports.
	MachoGoImportsNamesVarEntropy fields.Field = "file.macho.go_imports_names_var_entropy" // Variance for Shannon entropy calculation from the list of Go imports.
	MachoGoStripped               fields.Field = "file.macho.go_stripped"                  // Whether the file is a stripped or obfuscated Go executable.
	MachoImportHash               fields.Field = "file.macho.import_hash"                  // A hash of the imports in a Mach-O file.
	MachoImports                  fields.Field = "file.macho.imports"                      // List of imported element names and types.
	MachoImportsNamesEntropy      fields.Field = "file.macho.imports_names_entropy"        // Shannon entropy calculation from the list of imported element names and types.
	MachoImportsNamesVarEntropy   fields.Field = "file.macho.imports_names_var_entropy"    // Variance for Shannon entropy calculation from the list of imported element names and types.
	MachoSections                 fields.Field = "file.macho.sections"                     // Section information of the Mach-O file.
	MachoSectionsEntropy          fields.Field = "file.macho.sections.entropy"             // Shannon entropy calculation from the section.
	MachoSectionsName             fields.Field = "file.macho.sections.name"                // Mach-O Section List name.
	MachoSectionsPhysicalSize     fields.Field = "file.macho.sections.physical_size"       // Mach-O Section List physical size.
	MachoSectionsVarEntropy       fields.Field = "file.macho.sections.var_entropy"         // Variance for Shannon entropy calculation from the section.
	MachoSectionsVirtualSize      fields.Field = "file.macho.sections.virtual_size"        // Mach-O Section List virtual size. This is always the same as `physical_size`.
	MachoSymhash                  fields.Field = "file.macho.symhash"                      // A hash of the imports in a Mach-O file.
	MimeType                      fields.Field = "file.mime_type"                          // Media type of file, document, or arrangement of bytes.
	Mode                          fields.Field = "file.mode"                               // Mode of the file in octal representation.
	Mtime                         fields.Field = "file.mtime"                              // Last time the file content was modified.
	Name                          fields.Field = "file.name"                               // Name of the file including the extension, without the directory.
	Owner                         fields.Field = "file.owner"                              // File owner's username.
	Path                          fields.Field = "file.path"                               // Full path to the file, including the file name.
	PeArchitecture                fields.Field = "file.pe.architecture"                    // CPU architecture target for the file.
	PeCompany                     fields.Field = "file.pe.company"                         // Internal company name of the file, provided at compile-time.
	PeDescription                 fields.Field = "file.pe.description"                     // Internal description of the file, provided at compile-time.
	PeGoImportHash                fields.Field = "file.pe.go_import_hash"                  // A hash of the Go language imports in a PE file.
	PeGoImports                   fields.Field = "file.pe.go_imports"                      // List of imported Go language element names and types.
	PeGoImportsNamesEntropy       fields.Field = "file.pe.go_imports_names_entropy"        // Shannon entropy calculation from the list of Go imports.
	PeGoImportsNamesVarEntropy    fields.Field = "file.pe.go_imports_names_var_entropy"    // Variance for Shannon entropy calculation from the list of Go imports.
	PeGoStripped                  fields.Field = "file.pe.go_stripped"                     // Whether the file is a stripped or obfuscated Go executable.
	PeImphash                     fields.Field = "file.pe.imphash"                         // A hash of the imports in a PE file.
	PeImportHash                  fields.Field = "file.pe.import_hash"                     // A hash of the imports in a PE file.
	PeImports                     fields.Field = "file.pe.imports"                         // List of imported element names and types.
	PeImportsNamesEntropy         fields.Field = "file.pe.imports_names_entropy"           // Shannon entropy calculation from the list of imported element names and types.
	PeImportsNamesVarEntropy      fields.Field = "file.pe.imports_names_var_entropy"       // Variance for Shannon entropy calculation from the list of imported element names and types.
	PeOriginalName                fields.Field = "file.pe.original_file_name"              // Internal name of the file, provided at compile-time.
	PePehash                      fields.Field = "file.pe.pehash"                          // A hash of the PE header and data from one or more PE sections.
	PeProduct                     fields.Field = "file.pe.product"                         // Internal product name of the file, provided at compile-time.
	PeSections                    fields.Field = "file.pe.sections"                        // Section information of the PE file.
	PeSectionsEntropy             fields.Field = "file.pe.sections.entropy"                // Shannon entropy calculation from the section.
	PeSectionsName                fields.Field = "file.pe.sections.name"                   // PE Section List name.
	PeSectionsPhysicalSize        fields.Field = "file.pe.sections.physical_size"          // PE Section List physical size.
	PeSectionsVarEntropy          fields.Field = "file.pe.sections.var_entropy"            // Variance for Shannon entropy calculation from the section.
	PeSectionsVirtualSize         fields.Field = "file.pe.sections.virtual_size"           // PE Section List virtual size. This is always the same as `physical_size`.
	PeVersion                     fields.Field = "file.pe.file_version"                    // Process name.
	Size                          fields.Field = "file.size"                               // File size in bytes.
	TargetPath                    fields.Field = "file.target_path"                        // Target path for symlinks.
	Type                          fields.Field = "file.type"                               // File type (file, dir, or symlink).
	Uid                           fields.Field = "file.uid"                                // The user ID (UID) or security identifier (SID) of the file owner.
	X509AlternativeNames          fields.Field = "file.x509.alternative_names"             // List of subject alternative names (SAN).
	X509IssuerCommonName          fields.Field = "file.x509.issuer.common_name"            // List of common name (CN) of issuing certificate authority.
	X509IssuerCountry             fields.Field = "file.x509.issuer.country"                // List of country \(C) codes
	X509IssuerDistinguishedName   fields.Field = "file.x509.issuer.distinguished_name"     // Distinguished name (DN) of issuing certificate authority.
	X509IssuerLocality            fields.Field = "file.x509.issuer.locality"               // List of locality names (L)
	X509IssuerOrganization        fields.Field = "file.x509.issuer.organization"           // List of organizations (O) of issuing certificate authority.
	X509IssuerOrganizationalUnit  fields.Field = "file.x509.issuer.organizational_unit"    // List of organizational units (OU) of issuing certificate authority.
	X509IssuerStateOrProvince     fields.Field = "file.x509.issuer.state_or_province"      // List of state or province names (ST, S, or P)
	X509NotAfter                  fields.Field = "file.x509.not_after"                     // Time at which the certificate is no longer considered valid.
	X509NotBefore                 fields.Field = "file.x509.not_before"                    // Time at which the certificate is first considered valid.
	X509PublicKeyAlgorithm        fields.Field = "file.x509.public_key_algorithm"          // Algorithm used to generate the public key.
	X509PublicKeyCurve            fields.Field = "file.x509.public_key_curve"              // The curve used by the elliptic curve public key algorithm. This is algorithm specific.
	X509PublicKeyExponent         fields.Field = "file.x509.public_key_exponent"           // Exponent used to derive the public key. This is algorithm specific.
	X509PublicKeySize             fields.Field = "file.x509.public_key_size"               // The size of the public key space in bits.
	X509SerialNumber              fields.Field = "file.x509.serial_number"                 // Unique serial number issued by the certificate authority.
	X509SignatureAlgorithm        fields.Field = "file.x509.signature_algorithm"           // Identifier for certificate signature algorithm.
	X509SubjectCommonName         fields.Field = "file.x509.subject.common_name"           // List of common names (CN) of subject.
	X509SubjectCountry            fields.Field = "file.x509.subject.country"               // List of country \(C) code
	X509SubjectDistinguishedName  fields.Field = "file.x509.subject.distinguished_name"    // Distinguished name (DN) of the certificate subject entity.
	X509SubjectLocality           fields.Field = "file.x509.subject.locality"              // List of locality names (L)
	X509SubjectOrganization       fields.Field = "file.x509.subject.organization"          // List of organizations (O) of subject.
	X509SubjectOrganizationalUnit fields.Field = "file.x509.subject.organizational_unit"   // List of organizational units (OU) of subject.
	X509SubjectStateOrProvince    fields.Field = "file.x509.subject.state_or_province"     // List of state or province names (ST, S, or P)
	X509VersionNumber             fields.Field = "file.x509.version_number"                // Version of x509 format.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Accessed,
	Attributes,
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
	Created,
	Ctime,
	Device,
	Directory,
	DriveLetter,
	ElfArchitecture,
	ElfByteOrder,
	ElfCpuType,
	ElfCreationDate,
	ElfExports,
	ElfGoImportHash,
	ElfGoImports,
	ElfGoImportsNamesEntropy,
	ElfGoImportsNamesVarEntropy,
	ElfGoStripped,
	ElfHeaderAbiVersion,
	ElfHeaderClass,
	ElfHeaderData,
	ElfHeaderEntrypoint,
	ElfHeaderObjectVersion,
	ElfHeaderOsAbi,
	ElfHeaderType,
	ElfHeaderVersion,
	ElfImportHash,
	ElfImports,
	ElfImportsNamesEntropy,
	ElfImportsNamesVarEntropy,
	ElfSections,
	ElfSectionsChi2,
	ElfSectionsEntropy,
	ElfSectionsFlags,
	ElfSectionsName,
	ElfSectionsPhysicalOffset,
	ElfSectionsPhysicalSize,
	ElfSectionsType,
	ElfSectionsVarEntropy,
	ElfSectionsVirtualAddress,
	ElfSectionsVirtualSize,
	ElfSegments,
	ElfSegmentsSections,
	ElfSegmentsType,
	ElfSharedLibraries,
	ElfTelfhash,
	Extension,
	ForkName,
	Gid,
	Group,
	HashCdhash,
	HashMd5,
	HashSha1,
	HashSha256,
	HashSha384,
	HashSha512,
	HashSsdeep,
	HashTlsh,
	Inode,
	MachoGoImportHash,
	MachoGoImports,
	MachoGoImportsNamesEntropy,
	MachoGoImportsNamesVarEntropy,
	MachoGoStripped,
	MachoImportHash,
	MachoImports,
	MachoImportsNamesEntropy,
	MachoImportsNamesVarEntropy,
	MachoSections,
	MachoSectionsEntropy,
	MachoSectionsName,
	MachoSectionsPhysicalSize,
	MachoSectionsVarEntropy,
	MachoSectionsVirtualSize,
	MachoSymhash,
	MimeType,
	Mode,
	Mtime,
	Name,
	Owner,
	Path,
	PeArchitecture,
	PeCompany,
	PeDescription,
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
	PeOriginalName,
	PePehash,
	PeProduct,
	PeSections,
	PeSectionsEntropy,
	PeSectionsName,
	PeSectionsPhysicalSize,
	PeSectionsVarEntropy,
	PeSectionsVirtualSize,
	PeVersion,
	Size,
	TargetPath,
	Type,
	Uid,
	X509AlternativeNames,
	X509IssuerCommonName,
	X509IssuerCountry,
	X509IssuerDistinguishedName,
	X509IssuerLocality,
	X509IssuerOrganization,
	X509IssuerOrganizationalUnit,
	X509IssuerStateOrProvince,
	X509NotAfter,
	X509NotBefore,
	X509PublicKeyAlgorithm,
	X509PublicKeyCurve,
	X509PublicKeyExponent,
	X509PublicKeySize,
	X509SerialNumber,
	X509SignatureAlgorithm,
	X509SubjectCommonName,
	X509SubjectCountry,
	X509SubjectDistinguishedName,
	X509SubjectLocality,
	X509SubjectOrganization,
	X509SubjectOrganizationalUnit,
	X509SubjectStateOrProvince,
	X509VersionNumber,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Accessed                      fields.Date
	Attributes                    fields.KeyWord
	CodeSignatureDigestAlgorithm  fields.KeyWord
	CodeSignatureExists           fields.Boolean
	CodeSignatureFlags            fields.KeyWord
	CodeSignatureSigningID        fields.KeyWord
	CodeSignatureStatus           fields.KeyWord
	CodeSignatureSubjectName      fields.KeyWord
	CodeSignatureTeamID           fields.KeyWord
	CodeSignatureTimestamp        fields.Date
	CodeSignatureTrusted          fields.Boolean
	CodeSignatureValid            fields.Boolean
	Created                       fields.Date
	Ctime                         fields.Date
	Device                        fields.KeyWord
	Directory                     fields.KeyWord
	DriveLetter                   fields.KeyWord
	ElfArchitecture               fields.KeyWord
	ElfByteOrder                  fields.KeyWord
	ElfCpuType                    fields.KeyWord
	ElfCreationDate               fields.Date
	ElfExports                    fields.Flattened
	ElfGoImportHash               fields.KeyWord
	ElfGoImports                  fields.Flattened
	ElfGoImportsNamesEntropy      fields.Long
	ElfGoImportsNamesVarEntropy   fields.Long
	ElfGoStripped                 fields.Boolean
	ElfHeaderAbiVersion           fields.KeyWord
	ElfHeaderClass                fields.KeyWord
	ElfHeaderData                 fields.KeyWord
	ElfHeaderEntrypoint           fields.Long
	ElfHeaderObjectVersion        fields.KeyWord
	ElfHeaderOsAbi                fields.KeyWord
	ElfHeaderType                 fields.KeyWord
	ElfHeaderVersion              fields.KeyWord
	ElfImportHash                 fields.KeyWord
	ElfImports                    fields.Flattened
	ElfImportsNamesEntropy        fields.Long
	ElfImportsNamesVarEntropy     fields.Long
	ElfSections                   fields.Nested
	ElfSectionsChi2               fields.Long
	ElfSectionsEntropy            fields.Long
	ElfSectionsFlags              fields.KeyWord
	ElfSectionsName               fields.KeyWord
	ElfSectionsPhysicalOffset     fields.KeyWord
	ElfSectionsPhysicalSize       fields.Long
	ElfSectionsType               fields.KeyWord
	ElfSectionsVarEntropy         fields.Long
	ElfSectionsVirtualAddress     fields.Long
	ElfSectionsVirtualSize        fields.Long
	ElfSegments                   fields.Nested
	ElfSegmentsSections           fields.KeyWord
	ElfSegmentsType               fields.KeyWord
	ElfSharedLibraries            fields.KeyWord
	ElfTelfhash                   fields.KeyWord
	Extension                     fields.KeyWord
	ForkName                      fields.KeyWord
	Gid                           fields.KeyWord
	Group                         fields.KeyWord
	HashCdhash                    fields.KeyWord
	HashMd5                       fields.KeyWord
	HashSha1                      fields.KeyWord
	HashSha256                    fields.KeyWord
	HashSha384                    fields.KeyWord
	HashSha512                    fields.KeyWord
	HashSsdeep                    fields.KeyWord
	HashTlsh                      fields.KeyWord
	Inode                         fields.KeyWord
	MachoGoImportHash             fields.KeyWord
	MachoGoImports                fields.Flattened
	MachoGoImportsNamesEntropy    fields.Long
	MachoGoImportsNamesVarEntropy fields.Long
	MachoGoStripped               fields.Boolean
	MachoImportHash               fields.KeyWord
	MachoImports                  fields.Flattened
	MachoImportsNamesEntropy      fields.Long
	MachoImportsNamesVarEntropy   fields.Long
	MachoSections                 fields.Nested
	MachoSectionsEntropy          fields.Long
	MachoSectionsName             fields.KeyWord
	MachoSectionsPhysicalSize     fields.Long
	MachoSectionsVarEntropy       fields.Long
	MachoSectionsVirtualSize      fields.Long
	MachoSymhash                  fields.KeyWord
	MimeType                      fields.KeyWord
	Mode                          fields.KeyWord
	Mtime                         fields.Date
	Name                          fields.KeyWord
	Owner                         fields.KeyWord
	Path                          fields.KeyWord
	PeArchitecture                fields.KeyWord
	PeCompany                     fields.KeyWord
	PeDescription                 fields.KeyWord
	PeGoImportHash                fields.KeyWord
	PeGoImports                   fields.Flattened
	PeGoImportsNamesEntropy       fields.Long
	PeGoImportsNamesVarEntropy    fields.Long
	PeGoStripped                  fields.Boolean
	PeImphash                     fields.KeyWord
	PeImportHash                  fields.KeyWord
	PeImports                     fields.Flattened
	PeImportsNamesEntropy         fields.Long
	PeImportsNamesVarEntropy      fields.Long
	PeOriginalName                fields.KeyWord
	PePehash                      fields.KeyWord
	PeProduct                     fields.KeyWord
	PeSections                    fields.Nested
	PeSectionsEntropy             fields.Long
	PeSectionsName                fields.KeyWord
	PeSectionsPhysicalSize        fields.Long
	PeSectionsVarEntropy          fields.Long
	PeSectionsVirtualSize         fields.Long
	PeVersion                     fields.KeyWord
	Size                          fields.Long
	TargetPath                    fields.KeyWord
	Type                          fields.KeyWord
	Uid                           fields.KeyWord
	X509AlternativeNames          fields.KeyWord
	X509IssuerCommonName          fields.KeyWord
	X509IssuerCountry             fields.KeyWord
	X509IssuerDistinguishedName   fields.KeyWord
	X509IssuerLocality            fields.KeyWord
	X509IssuerOrganization        fields.KeyWord
	X509IssuerOrganizationalUnit  fields.KeyWord
	X509IssuerStateOrProvince     fields.KeyWord
	X509NotAfter                  fields.Date
	X509NotBefore                 fields.Date
	X509PublicKeyAlgorithm        fields.KeyWord
	X509PublicKeyCurve            fields.KeyWord
	X509PublicKeyExponent         fields.Long
	X509PublicKeySize             fields.Long
	X509SerialNumber              fields.KeyWord
	X509SignatureAlgorithm        fields.KeyWord
	X509SubjectCommonName         fields.KeyWord
	X509SubjectCountry            fields.KeyWord
	X509SubjectDistinguishedName  fields.KeyWord
	X509SubjectLocality           fields.KeyWord
	X509SubjectOrganization       fields.KeyWord
	X509SubjectOrganizationalUnit fields.KeyWord
	X509SubjectStateOrProvince    fields.KeyWord
	X509VersionNumber             fields.KeyWord
}

var Types TypesType = TypesType{}
