package threat

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	EnrichmentsIndicatorAsNumber                          fields.Field = "threat.enrichments.indicator.as.number"                             // Unique number allocated to the autonomous system.
	EnrichmentsIndicatorAsOrganizationName                fields.Field = "threat.enrichments.indicator.as.organization.name"                  // Organization name.
	EnrichmentsIndicatorConfidence                        fields.Field = "threat.enrichments.indicator.confidence"                            // Indicator confidence rating
	EnrichmentsIndicatorDescription                       fields.Field = "threat.enrichments.indicator.description"                           // Indicator description
	EnrichmentsIndicatorEmailAddress                      fields.Field = "threat.enrichments.indicator.email.address"                         // Indicator email address
	EnrichmentsIndicatorFileAccessed                      fields.Field = "threat.enrichments.indicator.file.accessed"                         // Last time the file was accessed.
	EnrichmentsIndicatorFileAttributes                    fields.Field = "threat.enrichments.indicator.file.attributes"                       // Array of file attributes.
	EnrichmentsIndicatorFileCodeSignatureDigestAlgorithm  fields.Field = "threat.enrichments.indicator.file.code_signature.digest_algorithm"  // Hashing algorithm used to sign the process.
	EnrichmentsIndicatorFileCodeSignatureExists           fields.Field = "threat.enrichments.indicator.file.code_signature.exists"            // Boolean to capture if a signature is present.
	EnrichmentsIndicatorFileCodeSignatureSigningID        fields.Field = "threat.enrichments.indicator.file.code_signature.signing_id"        // The identifier used to sign the process.
	EnrichmentsIndicatorFileCodeSignatureStatus           fields.Field = "threat.enrichments.indicator.file.code_signature.status"            // Additional information about the certificate status.
	EnrichmentsIndicatorFileCodeSignatureSubjectName      fields.Field = "threat.enrichments.indicator.file.code_signature.subject_name"      // Subject name of the code signer
	EnrichmentsIndicatorFileCodeSignatureTeamID           fields.Field = "threat.enrichments.indicator.file.code_signature.team_id"           // The team identifier used to sign the process.
	EnrichmentsIndicatorFileCodeSignatureTimestamp        fields.Field = "threat.enrichments.indicator.file.code_signature.timestamp"         // When the signature was generated and signed.
	EnrichmentsIndicatorFileCodeSignatureTrusted          fields.Field = "threat.enrichments.indicator.file.code_signature.trusted"           // Stores the trust status of the certificate chain.
	EnrichmentsIndicatorFileCodeSignatureValid            fields.Field = "threat.enrichments.indicator.file.code_signature.valid"             // Boolean to capture if the digital signature is verified against the binary content.
	EnrichmentsIndicatorFileCreated                       fields.Field = "threat.enrichments.indicator.file.created"                          // File creation time.
	EnrichmentsIndicatorFileCtime                         fields.Field = "threat.enrichments.indicator.file.ctime"                            // Last time the file attributes or metadata changed.
	EnrichmentsIndicatorFileDevice                        fields.Field = "threat.enrichments.indicator.file.device"                           // Device that is the source of the file.
	EnrichmentsIndicatorFileDirectory                     fields.Field = "threat.enrichments.indicator.file.directory"                        // Directory where the file is located.
	EnrichmentsIndicatorFileDriveLetter                   fields.Field = "threat.enrichments.indicator.file.drive_letter"                     // Drive letter where the file is located.
	EnrichmentsIndicatorFileElfArchitecture               fields.Field = "threat.enrichments.indicator.file.elf.architecture"                 // Machine architecture of the ELF file.
	EnrichmentsIndicatorFileElfByteOrder                  fields.Field = "threat.enrichments.indicator.file.elf.byte_order"                   // Byte sequence of ELF file.
	EnrichmentsIndicatorFileElfCpuType                    fields.Field = "threat.enrichments.indicator.file.elf.cpu_type"                     // CPU type of the ELF file.
	EnrichmentsIndicatorFileElfCreationDate               fields.Field = "threat.enrichments.indicator.file.elf.creation_date"                // Build or compile date.
	EnrichmentsIndicatorFileElfExports                    fields.Field = "threat.enrichments.indicator.file.elf.exports"                      // List of exported element names and types.
	EnrichmentsIndicatorFileElfGoImportHash               fields.Field = "threat.enrichments.indicator.file.elf.go_import_hash"               // A hash of the Go language imports in an ELF file.
	EnrichmentsIndicatorFileElfGoImports                  fields.Field = "threat.enrichments.indicator.file.elf.go_imports"                   // List of imported Go language element names and types.
	EnrichmentsIndicatorFileElfGoImportsNamesEntropy      fields.Field = "threat.enrichments.indicator.file.elf.go_imports_names_entropy"     // Shannon entropy calculation from the list of Go imports.
	EnrichmentsIndicatorFileElfGoImportsNamesVarEntropy   fields.Field = "threat.enrichments.indicator.file.elf.go_imports_names_var_entropy" // Variance for Shannon entropy calculation from the list of Go imports.
	EnrichmentsIndicatorFileElfGoStripped                 fields.Field = "threat.enrichments.indicator.file.elf.go_stripped"                  // Whether the file is a stripped or obfuscated Go executable.
	EnrichmentsIndicatorFileElfHeaderAbiVersion           fields.Field = "threat.enrichments.indicator.file.elf.header.abi_version"           // Version of the ELF Application Binary Interface (ABI).
	EnrichmentsIndicatorFileElfHeaderClass                fields.Field = "threat.enrichments.indicator.file.elf.header.class"                 // Header class of the ELF file.
	EnrichmentsIndicatorFileElfHeaderData                 fields.Field = "threat.enrichments.indicator.file.elf.header.data"                  // Data table of the ELF header.
	EnrichmentsIndicatorFileElfHeaderEntrypoint           fields.Field = "threat.enrichments.indicator.file.elf.header.entrypoint"            // Header entrypoint of the ELF file.
	EnrichmentsIndicatorFileElfHeaderObjectVersion        fields.Field = "threat.enrichments.indicator.file.elf.header.object_version"        // "0x1" for original ELF files.
	EnrichmentsIndicatorFileElfHeaderOsAbi                fields.Field = "threat.enrichments.indicator.file.elf.header.os_abi"                // Application Binary Interface (ABI) of the Linux OS.
	EnrichmentsIndicatorFileElfHeaderType                 fields.Field = "threat.enrichments.indicator.file.elf.header.type"                  // Header type of the ELF file.
	EnrichmentsIndicatorFileElfHeaderVersion              fields.Field = "threat.enrichments.indicator.file.elf.header.version"               // Version of the ELF header.
	EnrichmentsIndicatorFileElfImportHash                 fields.Field = "threat.enrichments.indicator.file.elf.import_hash"                  // A hash of the imports in an ELF file.
	EnrichmentsIndicatorFileElfImports                    fields.Field = "threat.enrichments.indicator.file.elf.imports"                      // List of imported element names and types.
	EnrichmentsIndicatorFileElfImportsNamesEntropy        fields.Field = "threat.enrichments.indicator.file.elf.imports_names_entropy"        // Shannon entropy calculation from the list of imported element names and types.
	EnrichmentsIndicatorFileElfImportsNamesVarEntropy     fields.Field = "threat.enrichments.indicator.file.elf.imports_names_var_entropy"    // Variance for Shannon entropy calculation from the list of imported element names and types.
	EnrichmentsIndicatorFileElfSectionsChi2               fields.Field = "threat.enrichments.indicator.file.elf.sections.chi2"                // Chi-square probability distribution of the section.
	EnrichmentsIndicatorFileElfSectionsEntropy            fields.Field = "threat.enrichments.indicator.file.elf.sections.entropy"             // Shannon entropy calculation from the section.
	EnrichmentsIndicatorFileElfSectionsFlags              fields.Field = "threat.enrichments.indicator.file.elf.sections.flags"               // ELF Section List flags.
	EnrichmentsIndicatorFileElfSectionsName               fields.Field = "threat.enrichments.indicator.file.elf.sections.name"                // ELF Section List name.
	EnrichmentsIndicatorFileElfSectionsPhysicalOffset     fields.Field = "threat.enrichments.indicator.file.elf.sections.physical_offset"     // ELF Section List offset.
	EnrichmentsIndicatorFileElfSectionsPhysicalSize       fields.Field = "threat.enrichments.indicator.file.elf.sections.physical_size"       // ELF Section List physical size.
	EnrichmentsIndicatorFileElfSectionsType               fields.Field = "threat.enrichments.indicator.file.elf.sections.type"                // ELF Section List type.
	EnrichmentsIndicatorFileElfSectionsVarEntropy         fields.Field = "threat.enrichments.indicator.file.elf.sections.var_entropy"         // Variance for Shannon entropy calculation from the section.
	EnrichmentsIndicatorFileElfSectionsVirtualAddress     fields.Field = "threat.enrichments.indicator.file.elf.sections.virtual_address"     // ELF Section List virtual address.
	EnrichmentsIndicatorFileElfSectionsVirtualSize        fields.Field = "threat.enrichments.indicator.file.elf.sections.virtual_size"        // ELF Section List virtual size.
	EnrichmentsIndicatorFileElfSegmentsSections           fields.Field = "threat.enrichments.indicator.file.elf.segments.sections"            // ELF object segment sections.
	EnrichmentsIndicatorFileElfSegmentsType               fields.Field = "threat.enrichments.indicator.file.elf.segments.type"                // ELF object segment type.
	EnrichmentsIndicatorFileElfSharedLibraries            fields.Field = "threat.enrichments.indicator.file.elf.shared_libraries"             // List of shared libraries used by this ELF object.
	EnrichmentsIndicatorFileElfTelfhash                   fields.Field = "threat.enrichments.indicator.file.elf.telfhash"                     // telfhash hash for ELF file.
	EnrichmentsIndicatorFileExtension                     fields.Field = "threat.enrichments.indicator.file.extension"                        // File extension, excluding the leading dot.
	EnrichmentsIndicatorFileForkName                      fields.Field = "threat.enrichments.indicator.file.fork_name"                        // A fork is additional data associated with a filesystem object.
	EnrichmentsIndicatorFileGid                           fields.Field = "threat.enrichments.indicator.file.gid"                              // Primary group ID (GID) of the file.
	EnrichmentsIndicatorFileGroup                         fields.Field = "threat.enrichments.indicator.file.group"                            // Primary group name of the file.
	EnrichmentsIndicatorFileHashMd5                       fields.Field = "threat.enrichments.indicator.file.hash.md5"                         // MD5 hash.
	EnrichmentsIndicatorFileHashSha1                      fields.Field = "threat.enrichments.indicator.file.hash.sha1"                        // SHA1 hash.
	EnrichmentsIndicatorFileHashSha256                    fields.Field = "threat.enrichments.indicator.file.hash.sha256"                      // SHA256 hash.
	EnrichmentsIndicatorFileHashSha384                    fields.Field = "threat.enrichments.indicator.file.hash.sha384"                      // SHA384 hash.
	EnrichmentsIndicatorFileHashSha512                    fields.Field = "threat.enrichments.indicator.file.hash.sha512"                      // SHA512 hash.
	EnrichmentsIndicatorFileHashSsdeep                    fields.Field = "threat.enrichments.indicator.file.hash.ssdeep"                      // SSDEEP hash.
	EnrichmentsIndicatorFileHashTlsh                      fields.Field = "threat.enrichments.indicator.file.hash.tlsh"                        // TLSH hash.
	EnrichmentsIndicatorFileInode                         fields.Field = "threat.enrichments.indicator.file.inode"                            // Inode representing the file in the filesystem.
	EnrichmentsIndicatorFileMimeType                      fields.Field = "threat.enrichments.indicator.file.mime_type"                        // Media type of file, document, or arrangement of bytes.
	EnrichmentsIndicatorFileMode                          fields.Field = "threat.enrichments.indicator.file.mode"                             // Mode of the file in octal representation.
	EnrichmentsIndicatorFileMtime                         fields.Field = "threat.enrichments.indicator.file.mtime"                            // Last time the file content was modified.
	EnrichmentsIndicatorFileName                          fields.Field = "threat.enrichments.indicator.file.name"                             // Name of the file including the extension, without the directory.
	EnrichmentsIndicatorFileOwner                         fields.Field = "threat.enrichments.indicator.file.owner"                            // File owner's username.
	EnrichmentsIndicatorFilePath                          fields.Field = "threat.enrichments.indicator.file.path"                             // Full path to the file, including the file name.
	EnrichmentsIndicatorFilePeArchitecture                fields.Field = "threat.enrichments.indicator.file.pe.architecture"                  // CPU architecture target for the file.
	EnrichmentsIndicatorFilePeCompany                     fields.Field = "threat.enrichments.indicator.file.pe.company"                       // Internal company name of the file, provided at compile-time.
	EnrichmentsIndicatorFilePeDescription                 fields.Field = "threat.enrichments.indicator.file.pe.description"                   // Internal description of the file, provided at compile-time.
	EnrichmentsIndicatorFilePeFileVersion                 fields.Field = "threat.enrichments.indicator.file.pe.file_version"                  // Process name.
	EnrichmentsIndicatorFilePeGoImportHash                fields.Field = "threat.enrichments.indicator.file.pe.go_import_hash"                // A hash of the Go language imports in a PE file.
	EnrichmentsIndicatorFilePeGoImports                   fields.Field = "threat.enrichments.indicator.file.pe.go_imports"                    // List of imported Go language element names and types.
	EnrichmentsIndicatorFilePeGoImportsNamesEntropy       fields.Field = "threat.enrichments.indicator.file.pe.go_imports_names_entropy"      // Shannon entropy calculation from the list of Go imports.
	EnrichmentsIndicatorFilePeGoImportsNamesVarEntropy    fields.Field = "threat.enrichments.indicator.file.pe.go_imports_names_var_entropy"  // Variance for Shannon entropy calculation from the list of Go imports.
	EnrichmentsIndicatorFilePeGoStripped                  fields.Field = "threat.enrichments.indicator.file.pe.go_stripped"                   // Whether the file is a stripped or obfuscated Go executable.
	EnrichmentsIndicatorFilePeImphash                     fields.Field = "threat.enrichments.indicator.file.pe.imphash"                       // A hash of the imports in a PE file.
	EnrichmentsIndicatorFilePeImportHash                  fields.Field = "threat.enrichments.indicator.file.pe.import_hash"                   // A hash of the imports in a PE file.
	EnrichmentsIndicatorFilePeImports                     fields.Field = "threat.enrichments.indicator.file.pe.imports"                       // List of imported element names and types.
	EnrichmentsIndicatorFilePeImportsNamesEntropy         fields.Field = "threat.enrichments.indicator.file.pe.imports_names_entropy"         // Shannon entropy calculation from the list of imported element names and types.
	EnrichmentsIndicatorFilePeImportsNamesVarEntropy      fields.Field = "threat.enrichments.indicator.file.pe.imports_names_var_entropy"     // Variance for Shannon entropy calculation from the list of imported element names and types.
	EnrichmentsIndicatorFilePeOriginalFileName            fields.Field = "threat.enrichments.indicator.file.pe.original_file_name"            // Internal name of the file, provided at compile-time.
	EnrichmentsIndicatorFilePePehash                      fields.Field = "threat.enrichments.indicator.file.pe.pehash"                        // A hash of the PE header and data from one or more PE sections.
	EnrichmentsIndicatorFilePeProduct                     fields.Field = "threat.enrichments.indicator.file.pe.product"                       // Internal product name of the file, provided at compile-time.
	EnrichmentsIndicatorFilePeSectionsEntropy             fields.Field = "threat.enrichments.indicator.file.pe.sections.entropy"              // Shannon entropy calculation from the section.
	EnrichmentsIndicatorFilePeSectionsName                fields.Field = "threat.enrichments.indicator.file.pe.sections.name"                 // PE Section List name.
	EnrichmentsIndicatorFilePeSectionsPhysicalSize        fields.Field = "threat.enrichments.indicator.file.pe.sections.physical_size"        // PE Section List physical size.
	EnrichmentsIndicatorFilePeSectionsVarEntropy          fields.Field = "threat.enrichments.indicator.file.pe.sections.var_entropy"          // Variance for Shannon entropy calculation from the section.
	EnrichmentsIndicatorFilePeSectionsVirtualSize         fields.Field = "threat.enrichments.indicator.file.pe.sections.virtual_size"         // PE Section List virtual size. This is always the same as `physical_size`.
	EnrichmentsIndicatorFileSize                          fields.Field = "threat.enrichments.indicator.file.size"                             // File size in bytes.
	EnrichmentsIndicatorFileTargetPath                    fields.Field = "threat.enrichments.indicator.file.target_path"                      // Target path for symlinks.
	EnrichmentsIndicatorFileType                          fields.Field = "threat.enrichments.indicator.file.type"                             // File type (file, dir, or symlink).
	EnrichmentsIndicatorFileUid                           fields.Field = "threat.enrichments.indicator.file.uid"                              // The user ID (UID) or security identifier (SID) of the file owner.
	EnrichmentsIndicatorFileX509AlternativeNames          fields.Field = "threat.enrichments.indicator.file.x509.alternative_names"           // List of subject alternative names (SAN).
	EnrichmentsIndicatorFileX509IssuerCommonName          fields.Field = "threat.enrichments.indicator.file.x509.issuer.common_name"          // List of common name (CN) of issuing certificate authority.
	EnrichmentsIndicatorFileX509IssuerCountry             fields.Field = "threat.enrichments.indicator.file.x509.issuer.country"              // List of country \(C) codes
	EnrichmentsIndicatorFileX509IssuerDistinguishedName   fields.Field = "threat.enrichments.indicator.file.x509.issuer.distinguished_name"   // Distinguished name (DN) of issuing certificate authority.
	EnrichmentsIndicatorFileX509IssuerLocality            fields.Field = "threat.enrichments.indicator.file.x509.issuer.locality"             // List of locality names (L)
	EnrichmentsIndicatorFileX509IssuerOrganization        fields.Field = "threat.enrichments.indicator.file.x509.issuer.organization"         // List of organizations (O) of issuing certificate authority.
	EnrichmentsIndicatorFileX509IssuerOrganizationalUnit  fields.Field = "threat.enrichments.indicator.file.x509.issuer.organizational_unit"  // List of organizational units (OU) of issuing certificate authority.
	EnrichmentsIndicatorFileX509IssuerStateOrProvince     fields.Field = "threat.enrichments.indicator.file.x509.issuer.state_or_province"    // List of state or province names (ST, S, or P)
	EnrichmentsIndicatorFileX509NotAfter                  fields.Field = "threat.enrichments.indicator.file.x509.not_after"                   // Time at which the certificate is no longer considered valid.
	EnrichmentsIndicatorFileX509NotBefore                 fields.Field = "threat.enrichments.indicator.file.x509.not_before"                  // Time at which the certificate is first considered valid.
	EnrichmentsIndicatorFileX509PublicKeyAlgorithm        fields.Field = "threat.enrichments.indicator.file.x509.public_key_algorithm"        // Algorithm used to generate the public key.
	EnrichmentsIndicatorFileX509PublicKeyCurve            fields.Field = "threat.enrichments.indicator.file.x509.public_key_curve"            // The curve used by the elliptic curve public key algorithm. This is algorithm specific.
	EnrichmentsIndicatorFileX509PublicKeyExponent         fields.Field = "threat.enrichments.indicator.file.x509.public_key_exponent"         // Exponent used to derive the public key. This is algorithm specific.
	EnrichmentsIndicatorFileX509PublicKeySize             fields.Field = "threat.enrichments.indicator.file.x509.public_key_size"             // The size of the public key space in bits.
	EnrichmentsIndicatorFileX509SerialNumber              fields.Field = "threat.enrichments.indicator.file.x509.serial_number"               // Unique serial number issued by the certificate authority.
	EnrichmentsIndicatorFileX509SignatureAlgorithm        fields.Field = "threat.enrichments.indicator.file.x509.signature_algorithm"         // Identifier for certificate signature algorithm.
	EnrichmentsIndicatorFileX509SubjectCommonName         fields.Field = "threat.enrichments.indicator.file.x509.subject.common_name"         // List of common names (CN) of subject.
	EnrichmentsIndicatorFileX509SubjectCountry            fields.Field = "threat.enrichments.indicator.file.x509.subject.country"             // List of country \(C) code
	EnrichmentsIndicatorFileX509SubjectDistinguishedName  fields.Field = "threat.enrichments.indicator.file.x509.subject.distinguished_name"  // Distinguished name (DN) of the certificate subject entity.
	EnrichmentsIndicatorFileX509SubjectLocality           fields.Field = "threat.enrichments.indicator.file.x509.subject.locality"            // List of locality names (L)
	EnrichmentsIndicatorFileX509SubjectOrganization       fields.Field = "threat.enrichments.indicator.file.x509.subject.organization"        // List of organizations (O) of subject.
	EnrichmentsIndicatorFileX509SubjectOrganizationalUnit fields.Field = "threat.enrichments.indicator.file.x509.subject.organizational_unit" // List of organizational units (OU) of subject.
	EnrichmentsIndicatorFileX509SubjectStateOrProvince    fields.Field = "threat.enrichments.indicator.file.x509.subject.state_or_province"   // List of state or province names (ST, S, or P)
	EnrichmentsIndicatorFileX509VersionNumber             fields.Field = "threat.enrichments.indicator.file.x509.version_number"              // Version of x509 format.
	EnrichmentsIndicatorFirstSeen                         fields.Field = "threat.enrichments.indicator.first_seen"                            // Date/time indicator was first reported.
	EnrichmentsIndicatorGeoCityName                       fields.Field = "threat.enrichments.indicator.geo.city_name"                         // City name.
	EnrichmentsIndicatorGeoContinentCode                  fields.Field = "threat.enrichments.indicator.geo.continent_code"                    // Continent code.
	EnrichmentsIndicatorGeoContinentName                  fields.Field = "threat.enrichments.indicator.geo.continent_name"                    // Name of the continent.
	EnrichmentsIndicatorGeoCountryIsoCode                 fields.Field = "threat.enrichments.indicator.geo.country_iso_code"                  // Country ISO code.
	EnrichmentsIndicatorGeoCountryName                    fields.Field = "threat.enrichments.indicator.geo.country_name"                      // Country name.
	EnrichmentsIndicatorGeoLocation                       fields.Field = "threat.enrichments.indicator.geo.location"                          // Longitude and latitude.
	EnrichmentsIndicatorGeoName                           fields.Field = "threat.enrichments.indicator.geo.name"                              // User-defined description of a location.
	EnrichmentsIndicatorGeoPostalCode                     fields.Field = "threat.enrichments.indicator.geo.postal_code"                       // Postal code.
	EnrichmentsIndicatorGeoRegionIsoCode                  fields.Field = "threat.enrichments.indicator.geo.region_iso_code"                   // Region ISO code.
	EnrichmentsIndicatorGeoRegionName                     fields.Field = "threat.enrichments.indicator.geo.region_name"                       // Region name.
	EnrichmentsIndicatorGeoTimezone                       fields.Field = "threat.enrichments.indicator.geo.timezone"                          // The time zone of the location, such as IANA time zone name.
	EnrichmentsIndicatorIp                                fields.Field = "threat.enrichments.indicator.ip"                                    // Indicator IP address
	EnrichmentsIndicatorLastSeen                          fields.Field = "threat.enrichments.indicator.last_seen"                             // Date/time indicator was last reported.
	EnrichmentsIndicatorMarkingTlp                        fields.Field = "threat.enrichments.indicator.marking.tlp"                           // Indicator TLP marking
	EnrichmentsIndicatorMarkingTlpVersion                 fields.Field = "threat.enrichments.indicator.marking.tlp_version"                   // Indicator TLP version
	EnrichmentsIndicatorModifiedAt                        fields.Field = "threat.enrichments.indicator.modified_at"                           // Date/time indicator was last updated.
	EnrichmentsIndicatorName                              fields.Field = "threat.enrichments.indicator.name"                                  // Indicator display name
	EnrichmentsIndicatorPort                              fields.Field = "threat.enrichments.indicator.port"                                  // Indicator port
	EnrichmentsIndicatorProvider                          fields.Field = "threat.enrichments.indicator.provider"                              // Indicator provider
	EnrichmentsIndicatorReference                         fields.Field = "threat.enrichments.indicator.reference"                             // Indicator reference URL
	EnrichmentsIndicatorRegistryDataBytes                 fields.Field = "threat.enrichments.indicator.registry.data.bytes"                   // Original bytes written with base64 encoding.
	EnrichmentsIndicatorRegistryDataStrings               fields.Field = "threat.enrichments.indicator.registry.data.strings"                 // List of strings representing what was written to the registry.
	EnrichmentsIndicatorRegistryDataType                  fields.Field = "threat.enrichments.indicator.registry.data.type"                    // Standard registry type for encoding contents
	EnrichmentsIndicatorRegistryHive                      fields.Field = "threat.enrichments.indicator.registry.hive"                         // Abbreviated name for the hive.
	EnrichmentsIndicatorRegistryKey                       fields.Field = "threat.enrichments.indicator.registry.key"                          // Hive-relative path of keys.
	EnrichmentsIndicatorRegistryPath                      fields.Field = "threat.enrichments.indicator.registry.path"                         // Full path, including hive, key and value
	EnrichmentsIndicatorRegistryValue                     fields.Field = "threat.enrichments.indicator.registry.value"                        // Name of the value written.
	EnrichmentsIndicatorScannerStats                      fields.Field = "threat.enrichments.indicator.scanner_stats"                         // Scanner statistics
	EnrichmentsIndicatorSightings                         fields.Field = "threat.enrichments.indicator.sightings"                             // Number of times indicator observed
	EnrichmentsIndicatorType                              fields.Field = "threat.enrichments.indicator.type"                                  // Type of indicator
	EnrichmentsIndicatorUrlDomain                         fields.Field = "threat.enrichments.indicator.url.domain"                            // Domain of the url.
	EnrichmentsIndicatorUrlExtension                      fields.Field = "threat.enrichments.indicator.url.extension"                         // File extension from the request url, excluding the leading dot.
	EnrichmentsIndicatorUrlFragment                       fields.Field = "threat.enrichments.indicator.url.fragment"                          // Portion of the url after the `#`.
	EnrichmentsIndicatorUrlFull                           fields.Field = "threat.enrichments.indicator.url.full"                              // Full unparsed URL.
	EnrichmentsIndicatorUrlOriginal                       fields.Field = "threat.enrichments.indicator.url.original"                          // Unmodified original url as seen in the event source.
	EnrichmentsIndicatorUrlPassword                       fields.Field = "threat.enrichments.indicator.url.password"                          // Password of the request.
	EnrichmentsIndicatorUrlPath                           fields.Field = "threat.enrichments.indicator.url.path"                              // Path of the request, such as "/search".
	EnrichmentsIndicatorUrlPort                           fields.Field = "threat.enrichments.indicator.url.port"                              // Port of the request, such as 443.
	EnrichmentsIndicatorUrlQuery                          fields.Field = "threat.enrichments.indicator.url.query"                             // Query string of the request.
	EnrichmentsIndicatorUrlRegisteredDomain               fields.Field = "threat.enrichments.indicator.url.registered_domain"                 // The highest registered url domain, stripped of the subdomain.
	EnrichmentsIndicatorUrlScheme                         fields.Field = "threat.enrichments.indicator.url.scheme"                            // Scheme of the url.
	EnrichmentsIndicatorUrlSubdomain                      fields.Field = "threat.enrichments.indicator.url.subdomain"                         // The subdomain of the domain.
	EnrichmentsIndicatorUrlTopLevelDomain                 fields.Field = "threat.enrichments.indicator.url.top_level_domain"                  // The effective top level domain (com, org, net, co.uk).
	EnrichmentsIndicatorUrlUsername                       fields.Field = "threat.enrichments.indicator.url.username"                          // Username of the request.
	EnrichmentsIndicatorX509AlternativeNames              fields.Field = "threat.enrichments.indicator.x509.alternative_names"                // List of subject alternative names (SAN).
	EnrichmentsIndicatorX509IssuerCommonName              fields.Field = "threat.enrichments.indicator.x509.issuer.common_name"               // List of common name (CN) of issuing certificate authority.
	EnrichmentsIndicatorX509IssuerCountry                 fields.Field = "threat.enrichments.indicator.x509.issuer.country"                   // List of country \(C) codes
	EnrichmentsIndicatorX509IssuerDistinguishedName       fields.Field = "threat.enrichments.indicator.x509.issuer.distinguished_name"        // Distinguished name (DN) of issuing certificate authority.
	EnrichmentsIndicatorX509IssuerLocality                fields.Field = "threat.enrichments.indicator.x509.issuer.locality"                  // List of locality names (L)
	EnrichmentsIndicatorX509IssuerOrganization            fields.Field = "threat.enrichments.indicator.x509.issuer.organization"              // List of organizations (O) of issuing certificate authority.
	EnrichmentsIndicatorX509IssuerOrganizationalUnit      fields.Field = "threat.enrichments.indicator.x509.issuer.organizational_unit"       // List of organizational units (OU) of issuing certificate authority.
	EnrichmentsIndicatorX509IssuerStateOrProvince         fields.Field = "threat.enrichments.indicator.x509.issuer.state_or_province"         // List of state or province names (ST, S, or P)
	EnrichmentsIndicatorX509NotAfter                      fields.Field = "threat.enrichments.indicator.x509.not_after"                        // Time at which the certificate is no longer considered valid.
	EnrichmentsIndicatorX509NotBefore                     fields.Field = "threat.enrichments.indicator.x509.not_before"                       // Time at which the certificate is first considered valid.
	EnrichmentsIndicatorX509PublicKeyAlgorithm            fields.Field = "threat.enrichments.indicator.x509.public_key_algorithm"             // Algorithm used to generate the public key.
	EnrichmentsIndicatorX509PublicKeyCurve                fields.Field = "threat.enrichments.indicator.x509.public_key_curve"                 // The curve used by the elliptic curve public key algorithm. This is algorithm specific.
	EnrichmentsIndicatorX509PublicKeyExponent             fields.Field = "threat.enrichments.indicator.x509.public_key_exponent"              // Exponent used to derive the public key. This is algorithm specific.
	EnrichmentsIndicatorX509PublicKeySize                 fields.Field = "threat.enrichments.indicator.x509.public_key_size"                  // The size of the public key space in bits.
	EnrichmentsIndicatorX509SerialNumber                  fields.Field = "threat.enrichments.indicator.x509.serial_number"                    // Unique serial number issued by the certificate authority.
	EnrichmentsIndicatorX509SignatureAlgorithm            fields.Field = "threat.enrichments.indicator.x509.signature_algorithm"              // Identifier for certificate signature algorithm.
	EnrichmentsIndicatorX509SubjectCommonName             fields.Field = "threat.enrichments.indicator.x509.subject.common_name"              // List of common names (CN) of subject.
	EnrichmentsIndicatorX509SubjectCountry                fields.Field = "threat.enrichments.indicator.x509.subject.country"                  // List of country \(C) code
	EnrichmentsIndicatorX509SubjectDistinguishedName      fields.Field = "threat.enrichments.indicator.x509.subject.distinguished_name"       // Distinguished name (DN) of the certificate subject entity.
	EnrichmentsIndicatorX509SubjectLocality               fields.Field = "threat.enrichments.indicator.x509.subject.locality"                 // List of locality names (L)
	EnrichmentsIndicatorX509SubjectOrganization           fields.Field = "threat.enrichments.indicator.x509.subject.organization"             // List of organizations (O) of subject.
	EnrichmentsIndicatorX509SubjectOrganizationalUnit     fields.Field = "threat.enrichments.indicator.x509.subject.organizational_unit"      // List of organizational units (OU) of subject.
	EnrichmentsIndicatorX509SubjectStateOrProvince        fields.Field = "threat.enrichments.indicator.x509.subject.state_or_province"        // List of state or province names (ST, S, or P)
	EnrichmentsIndicatorX509VersionNumber                 fields.Field = "threat.enrichments.indicator.x509.version_number"                   // Version of x509 format.
	EnrichmentsMatchedAtomic                              fields.Field = "threat.enrichments.matched.atomic"                                  // Matched indicator value
	EnrichmentsMatchedField                               fields.Field = "threat.enrichments.matched.field"                                   // Matched indicator field
	EnrichmentsMatchedID                                  fields.Field = "threat.enrichments.matched.id"                                      // Matched indicator identifier
	EnrichmentsMatchedIndex                               fields.Field = "threat.enrichments.matched.index"                                   // Matched indicator index
	EnrichmentsMatchedOccurred                            fields.Field = "threat.enrichments.matched.occurred"                                // Date of match
	EnrichmentsMatchedType                                fields.Field = "threat.enrichments.matched.type"                                    // Type of indicator match
	FeedDashboardID                                       fields.Field = "threat.feed.dashboard_id"                                           // Feed dashboard ID.
	FeedDescription                                       fields.Field = "threat.feed.description"                                            // Description of the threat feed.
	FeedName                                              fields.Field = "threat.feed.name"                                                   // Name of the threat feed.
	FeedReference                                         fields.Field = "threat.feed.reference"                                              // Reference for the threat feed.
	Framework                                             fields.Field = "threat.framework"                                                   // Threat classification framework.
	GroupAlias                                            fields.Field = "threat.group.alias"                                                 // Alias of the group.
	GroupID                                               fields.Field = "threat.group.id"                                                    // ID of the group.
	GroupName                                             fields.Field = "threat.group.name"                                                  // Name of the group.
	GroupReference                                        fields.Field = "threat.group.reference"                                             // Reference URL of the group.
	IndicatorAsNumber                                     fields.Field = "threat.indicator.as.number"                                         // Unique number allocated to the autonomous system.
	IndicatorAsOrganizationName                           fields.Field = "threat.indicator.as.organization.name"                              // Organization name.
	IndicatorConfidence                                   fields.Field = "threat.indicator.confidence"                                        // Indicator confidence rating
	IndicatorDescription                                  fields.Field = "threat.indicator.description"                                       // Indicator description
	IndicatorEmailAddress                                 fields.Field = "threat.indicator.email.address"                                     // Indicator email address
	IndicatorFileAccessed                                 fields.Field = "threat.indicator.file.accessed"                                     // Last time the file was accessed.
	IndicatorFileAttributes                               fields.Field = "threat.indicator.file.attributes"                                   // Array of file attributes.
	IndicatorFileCodeSignatureDigestAlgorithm             fields.Field = "threat.indicator.file.code_signature.digest_algorithm"              // Hashing algorithm used to sign the process.
	IndicatorFileCodeSignatureExists                      fields.Field = "threat.indicator.file.code_signature.exists"                        // Boolean to capture if a signature is present.
	IndicatorFileCodeSignatureSigningID                   fields.Field = "threat.indicator.file.code_signature.signing_id"                    // The identifier used to sign the process.
	IndicatorFileCodeSignatureStatus                      fields.Field = "threat.indicator.file.code_signature.status"                        // Additional information about the certificate status.
	IndicatorFileCodeSignatureSubjectName                 fields.Field = "threat.indicator.file.code_signature.subject_name"                  // Subject name of the code signer
	IndicatorFileCodeSignatureTeamID                      fields.Field = "threat.indicator.file.code_signature.team_id"                       // The team identifier used to sign the process.
	IndicatorFileCodeSignatureTimestamp                   fields.Field = "threat.indicator.file.code_signature.timestamp"                     // When the signature was generated and signed.
	IndicatorFileCodeSignatureTrusted                     fields.Field = "threat.indicator.file.code_signature.trusted"                       // Stores the trust status of the certificate chain.
	IndicatorFileCodeSignatureValid                       fields.Field = "threat.indicator.file.code_signature.valid"                         // Boolean to capture if the digital signature is verified against the binary content.
	IndicatorFileCreated                                  fields.Field = "threat.indicator.file.created"                                      // File creation time.
	IndicatorFileCtime                                    fields.Field = "threat.indicator.file.ctime"                                        // Last time the file attributes or metadata changed.
	IndicatorFileDevice                                   fields.Field = "threat.indicator.file.device"                                       // Device that is the source of the file.
	IndicatorFileDirectory                                fields.Field = "threat.indicator.file.directory"                                    // Directory where the file is located.
	IndicatorFileDriveLetter                              fields.Field = "threat.indicator.file.drive_letter"                                 // Drive letter where the file is located.
	IndicatorFileElfArchitecture                          fields.Field = "threat.indicator.file.elf.architecture"                             // Machine architecture of the ELF file.
	IndicatorFileElfByteOrder                             fields.Field = "threat.indicator.file.elf.byte_order"                               // Byte sequence of ELF file.
	IndicatorFileElfCpuType                               fields.Field = "threat.indicator.file.elf.cpu_type"                                 // CPU type of the ELF file.
	IndicatorFileElfCreationDate                          fields.Field = "threat.indicator.file.elf.creation_date"                            // Build or compile date.
	IndicatorFileElfExports                               fields.Field = "threat.indicator.file.elf.exports"                                  // List of exported element names and types.
	IndicatorFileElfGoImportHash                          fields.Field = "threat.indicator.file.elf.go_import_hash"                           // A hash of the Go language imports in an ELF file.
	IndicatorFileElfGoImports                             fields.Field = "threat.indicator.file.elf.go_imports"                               // List of imported Go language element names and types.
	IndicatorFileElfGoImportsNamesEntropy                 fields.Field = "threat.indicator.file.elf.go_imports_names_entropy"                 // Shannon entropy calculation from the list of Go imports.
	IndicatorFileElfGoImportsNamesVarEntropy              fields.Field = "threat.indicator.file.elf.go_imports_names_var_entropy"             // Variance for Shannon entropy calculation from the list of Go imports.
	IndicatorFileElfGoStripped                            fields.Field = "threat.indicator.file.elf.go_stripped"                              // Whether the file is a stripped or obfuscated Go executable.
	IndicatorFileElfHeaderAbiVersion                      fields.Field = "threat.indicator.file.elf.header.abi_version"                       // Version of the ELF Application Binary Interface (ABI).
	IndicatorFileElfHeaderClass                           fields.Field = "threat.indicator.file.elf.header.class"                             // Header class of the ELF file.
	IndicatorFileElfHeaderData                            fields.Field = "threat.indicator.file.elf.header.data"                              // Data table of the ELF header.
	IndicatorFileElfHeaderEntrypoint                      fields.Field = "threat.indicator.file.elf.header.entrypoint"                        // Header entrypoint of the ELF file.
	IndicatorFileElfHeaderObjectVersion                   fields.Field = "threat.indicator.file.elf.header.object_version"                    // "0x1" for original ELF files.
	IndicatorFileElfHeaderOsAbi                           fields.Field = "threat.indicator.file.elf.header.os_abi"                            // Application Binary Interface (ABI) of the Linux OS.
	IndicatorFileElfHeaderType                            fields.Field = "threat.indicator.file.elf.header.type"                              // Header type of the ELF file.
	IndicatorFileElfHeaderVersion                         fields.Field = "threat.indicator.file.elf.header.version"                           // Version of the ELF header.
	IndicatorFileElfImportHash                            fields.Field = "threat.indicator.file.elf.import_hash"                              // A hash of the imports in an ELF file.
	IndicatorFileElfImports                               fields.Field = "threat.indicator.file.elf.imports"                                  // List of imported element names and types.
	IndicatorFileElfImportsNamesEntropy                   fields.Field = "threat.indicator.file.elf.imports_names_entropy"                    // Shannon entropy calculation from the list of imported element names and types.
	IndicatorFileElfImportsNamesVarEntropy                fields.Field = "threat.indicator.file.elf.imports_names_var_entropy"                // Variance for Shannon entropy calculation from the list of imported element names and types.
	IndicatorFileElfSectionsChi2                          fields.Field = "threat.indicator.file.elf.sections.chi2"                            // Chi-square probability distribution of the section.
	IndicatorFileElfSectionsEntropy                       fields.Field = "threat.indicator.file.elf.sections.entropy"                         // Shannon entropy calculation from the section.
	IndicatorFileElfSectionsFlags                         fields.Field = "threat.indicator.file.elf.sections.flags"                           // ELF Section List flags.
	IndicatorFileElfSectionsName                          fields.Field = "threat.indicator.file.elf.sections.name"                            // ELF Section List name.
	IndicatorFileElfSectionsPhysicalOffset                fields.Field = "threat.indicator.file.elf.sections.physical_offset"                 // ELF Section List offset.
	IndicatorFileElfSectionsPhysicalSize                  fields.Field = "threat.indicator.file.elf.sections.physical_size"                   // ELF Section List physical size.
	IndicatorFileElfSectionsType                          fields.Field = "threat.indicator.file.elf.sections.type"                            // ELF Section List type.
	IndicatorFileElfSectionsVarEntropy                    fields.Field = "threat.indicator.file.elf.sections.var_entropy"                     // Variance for Shannon entropy calculation from the section.
	IndicatorFileElfSectionsVirtualAddress                fields.Field = "threat.indicator.file.elf.sections.virtual_address"                 // ELF Section List virtual address.
	IndicatorFileElfSectionsVirtualSize                   fields.Field = "threat.indicator.file.elf.sections.virtual_size"                    // ELF Section List virtual size.
	IndicatorFileElfSegmentsSections                      fields.Field = "threat.indicator.file.elf.segments.sections"                        // ELF object segment sections.
	IndicatorFileElfSegmentsType                          fields.Field = "threat.indicator.file.elf.segments.type"                            // ELF object segment type.
	IndicatorFileElfSharedLibraries                       fields.Field = "threat.indicator.file.elf.shared_libraries"                         // List of shared libraries used by this ELF object.
	IndicatorFileElfTelfhash                              fields.Field = "threat.indicator.file.elf.telfhash"                                 // telfhash hash for ELF file.
	IndicatorFileExtension                                fields.Field = "threat.indicator.file.extension"                                    // File extension, excluding the leading dot.
	IndicatorFileForkName                                 fields.Field = "threat.indicator.file.fork_name"                                    // A fork is additional data associated with a filesystem object.
	IndicatorFileGid                                      fields.Field = "threat.indicator.file.gid"                                          // Primary group ID (GID) of the file.
	IndicatorFileGroup                                    fields.Field = "threat.indicator.file.group"                                        // Primary group name of the file.
	IndicatorFileHashMd5                                  fields.Field = "threat.indicator.file.hash.md5"                                     // MD5 hash.
	IndicatorFileHashSha1                                 fields.Field = "threat.indicator.file.hash.sha1"                                    // SHA1 hash.
	IndicatorFileHashSha256                               fields.Field = "threat.indicator.file.hash.sha256"                                  // SHA256 hash.
	IndicatorFileHashSha384                               fields.Field = "threat.indicator.file.hash.sha384"                                  // SHA384 hash.
	IndicatorFileHashSha512                               fields.Field = "threat.indicator.file.hash.sha512"                                  // SHA512 hash.
	IndicatorFileHashSsdeep                               fields.Field = "threat.indicator.file.hash.ssdeep"                                  // SSDEEP hash.
	IndicatorFileHashTlsh                                 fields.Field = "threat.indicator.file.hash.tlsh"                                    // TLSH hash.
	IndicatorFileInode                                    fields.Field = "threat.indicator.file.inode"                                        // Inode representing the file in the filesystem.
	IndicatorFileMimeType                                 fields.Field = "threat.indicator.file.mime_type"                                    // Media type of file, document, or arrangement of bytes.
	IndicatorFileMode                                     fields.Field = "threat.indicator.file.mode"                                         // Mode of the file in octal representation.
	IndicatorFileMtime                                    fields.Field = "threat.indicator.file.mtime"                                        // Last time the file content was modified.
	IndicatorFileName                                     fields.Field = "threat.indicator.file.name"                                         // Name of the file including the extension, without the directory.
	IndicatorFileOwner                                    fields.Field = "threat.indicator.file.owner"                                        // File owner's username.
	IndicatorFilePath                                     fields.Field = "threat.indicator.file.path"                                         // Full path to the file, including the file name.
	IndicatorFilePeArchitecture                           fields.Field = "threat.indicator.file.pe.architecture"                              // CPU architecture target for the file.
	IndicatorFilePeCompany                                fields.Field = "threat.indicator.file.pe.company"                                   // Internal company name of the file, provided at compile-time.
	IndicatorFilePeDescription                            fields.Field = "threat.indicator.file.pe.description"                               // Internal description of the file, provided at compile-time.
	IndicatorFilePeFileVersion                            fields.Field = "threat.indicator.file.pe.file_version"                              // Process name.
	IndicatorFilePeGoImportHash                           fields.Field = "threat.indicator.file.pe.go_import_hash"                            // A hash of the Go language imports in a PE file.
	IndicatorFilePeGoImports                              fields.Field = "threat.indicator.file.pe.go_imports"                                // List of imported Go language element names and types.
	IndicatorFilePeGoImportsNamesEntropy                  fields.Field = "threat.indicator.file.pe.go_imports_names_entropy"                  // Shannon entropy calculation from the list of Go imports.
	IndicatorFilePeGoImportsNamesVarEntropy               fields.Field = "threat.indicator.file.pe.go_imports_names_var_entropy"              // Variance for Shannon entropy calculation from the list of Go imports.
	IndicatorFilePeGoStripped                             fields.Field = "threat.indicator.file.pe.go_stripped"                               // Whether the file is a stripped or obfuscated Go executable.
	IndicatorFilePeImphash                                fields.Field = "threat.indicator.file.pe.imphash"                                   // A hash of the imports in a PE file.
	IndicatorFilePeImportHash                             fields.Field = "threat.indicator.file.pe.import_hash"                               // A hash of the imports in a PE file.
	IndicatorFilePeImports                                fields.Field = "threat.indicator.file.pe.imports"                                   // List of imported element names and types.
	IndicatorFilePeImportsNamesEntropy                    fields.Field = "threat.indicator.file.pe.imports_names_entropy"                     // Shannon entropy calculation from the list of imported element names and types.
	IndicatorFilePeImportsNamesVarEntropy                 fields.Field = "threat.indicator.file.pe.imports_names_var_entropy"                 // Variance for Shannon entropy calculation from the list of imported element names and types.
	IndicatorFilePeOriginalFileName                       fields.Field = "threat.indicator.file.pe.original_file_name"                        // Internal name of the file, provided at compile-time.
	IndicatorFilePePehash                                 fields.Field = "threat.indicator.file.pe.pehash"                                    // A hash of the PE header and data from one or more PE sections.
	IndicatorFilePeProduct                                fields.Field = "threat.indicator.file.pe.product"                                   // Internal product name of the file, provided at compile-time.
	IndicatorFilePeSectionsEntropy                        fields.Field = "threat.indicator.file.pe.sections.entropy"                          // Shannon entropy calculation from the section.
	IndicatorFilePeSectionsName                           fields.Field = "threat.indicator.file.pe.sections.name"                             // PE Section List name.
	IndicatorFilePeSectionsPhysicalSize                   fields.Field = "threat.indicator.file.pe.sections.physical_size"                    // PE Section List physical size.
	IndicatorFilePeSectionsVarEntropy                     fields.Field = "threat.indicator.file.pe.sections.var_entropy"                      // Variance for Shannon entropy calculation from the section.
	IndicatorFilePeSectionsVirtualSize                    fields.Field = "threat.indicator.file.pe.sections.virtual_size"                     // PE Section List virtual size. This is always the same as `physical_size`.
	IndicatorFileSize                                     fields.Field = "threat.indicator.file.size"                                         // File size in bytes.
	IndicatorFileTargetPath                               fields.Field = "threat.indicator.file.target_path"                                  // Target path for symlinks.
	IndicatorFileType                                     fields.Field = "threat.indicator.file.type"                                         // File type (file, dir, or symlink).
	IndicatorFileUid                                      fields.Field = "threat.indicator.file.uid"                                          // The user ID (UID) or security identifier (SID) of the file owner.
	IndicatorFileX509AlternativeNames                     fields.Field = "threat.indicator.file.x509.alternative_names"                       // List of subject alternative names (SAN).
	IndicatorFileX509IssuerCommonName                     fields.Field = "threat.indicator.file.x509.issuer.common_name"                      // List of common name (CN) of issuing certificate authority.
	IndicatorFileX509IssuerCountry                        fields.Field = "threat.indicator.file.x509.issuer.country"                          // List of country \(C) codes
	IndicatorFileX509IssuerDistinguishedName              fields.Field = "threat.indicator.file.x509.issuer.distinguished_name"               // Distinguished name (DN) of issuing certificate authority.
	IndicatorFileX509IssuerLocality                       fields.Field = "threat.indicator.file.x509.issuer.locality"                         // List of locality names (L)
	IndicatorFileX509IssuerOrganization                   fields.Field = "threat.indicator.file.x509.issuer.organization"                     // List of organizations (O) of issuing certificate authority.
	IndicatorFileX509IssuerOrganizationalUnit             fields.Field = "threat.indicator.file.x509.issuer.organizational_unit"              // List of organizational units (OU) of issuing certificate authority.
	IndicatorFileX509IssuerStateOrProvince                fields.Field = "threat.indicator.file.x509.issuer.state_or_province"                // List of state or province names (ST, S, or P)
	IndicatorFileX509NotAfter                             fields.Field = "threat.indicator.file.x509.not_after"                               // Time at which the certificate is no longer considered valid.
	IndicatorFileX509NotBefore                            fields.Field = "threat.indicator.file.x509.not_before"                              // Time at which the certificate is first considered valid.
	IndicatorFileX509PublicKeyAlgorithm                   fields.Field = "threat.indicator.file.x509.public_key_algorithm"                    // Algorithm used to generate the public key.
	IndicatorFileX509PublicKeyCurve                       fields.Field = "threat.indicator.file.x509.public_key_curve"                        // The curve used by the elliptic curve public key algorithm. This is algorithm specific.
	IndicatorFileX509PublicKeyExponent                    fields.Field = "threat.indicator.file.x509.public_key_exponent"                     // Exponent used to derive the public key. This is algorithm specific.
	IndicatorFileX509PublicKeySize                        fields.Field = "threat.indicator.file.x509.public_key_size"                         // The size of the public key space in bits.
	IndicatorFileX509SerialNumber                         fields.Field = "threat.indicator.file.x509.serial_number"                           // Unique serial number issued by the certificate authority.
	IndicatorFileX509SignatureAlgorithm                   fields.Field = "threat.indicator.file.x509.signature_algorithm"                     // Identifier for certificate signature algorithm.
	IndicatorFileX509SubjectCommonName                    fields.Field = "threat.indicator.file.x509.subject.common_name"                     // List of common names (CN) of subject.
	IndicatorFileX509SubjectCountry                       fields.Field = "threat.indicator.file.x509.subject.country"                         // List of country \(C) code
	IndicatorFileX509SubjectDistinguishedName             fields.Field = "threat.indicator.file.x509.subject.distinguished_name"              // Distinguished name (DN) of the certificate subject entity.
	IndicatorFileX509SubjectLocality                      fields.Field = "threat.indicator.file.x509.subject.locality"                        // List of locality names (L)
	IndicatorFileX509SubjectOrganization                  fields.Field = "threat.indicator.file.x509.subject.organization"                    // List of organizations (O) of subject.
	IndicatorFileX509SubjectOrganizationalUnit            fields.Field = "threat.indicator.file.x509.subject.organizational_unit"             // List of organizational units (OU) of subject.
	IndicatorFileX509SubjectStateOrProvince               fields.Field = "threat.indicator.file.x509.subject.state_or_province"               // List of state or province names (ST, S, or P)
	IndicatorFileX509VersionNumber                        fields.Field = "threat.indicator.file.x509.version_number"                          // Version of x509 format.
	IndicatorFirstSeen                                    fields.Field = "threat.indicator.first_seen"                                        // Date/time indicator was first reported.
	IndicatorGeoCityName                                  fields.Field = "threat.indicator.geo.city_name"                                     // City name.
	IndicatorGeoContinentCode                             fields.Field = "threat.indicator.geo.continent_code"                                // Continent code.
	IndicatorGeoContinentName                             fields.Field = "threat.indicator.geo.continent_name"                                // Name of the continent.
	IndicatorGeoCountryIsoCode                            fields.Field = "threat.indicator.geo.country_iso_code"                              // Country ISO code.
	IndicatorGeoCountryName                               fields.Field = "threat.indicator.geo.country_name"                                  // Country name.
	IndicatorGeoLocation                                  fields.Field = "threat.indicator.geo.location"                                      // Longitude and latitude.
	IndicatorGeoName                                      fields.Field = "threat.indicator.geo.name"                                          // User-defined description of a location.
	IndicatorGeoPostalCode                                fields.Field = "threat.indicator.geo.postal_code"                                   // Postal code.
	IndicatorGeoRegionIsoCode                             fields.Field = "threat.indicator.geo.region_iso_code"                               // Region ISO code.
	IndicatorGeoRegionName                                fields.Field = "threat.indicator.geo.region_name"                                   // Region name.
	IndicatorGeoTimezone                                  fields.Field = "threat.indicator.geo.timezone"                                      // The time zone of the location, such as IANA time zone name.
	IndicatorIp                                           fields.Field = "threat.indicator.ip"                                                // Indicator IP address
	IndicatorLastSeen                                     fields.Field = "threat.indicator.last_seen"                                         // Date/time indicator was last reported.
	IndicatorMarkingTlp                                   fields.Field = "threat.indicator.marking.tlp"                                       // Indicator TLP marking
	IndicatorMarkingTlpVersion                            fields.Field = "threat.indicator.marking.tlp_version"                               // Indicator TLP version
	IndicatorModifiedAt                                   fields.Field = "threat.indicator.modified_at"                                       // Date/time indicator was last updated.
	IndicatorName                                         fields.Field = "threat.indicator.name"                                              // Indicator display name
	IndicatorPort                                         fields.Field = "threat.indicator.port"                                              // Indicator port
	IndicatorProvider                                     fields.Field = "threat.indicator.provider"                                          // Indicator provider
	IndicatorReference                                    fields.Field = "threat.indicator.reference"                                         // Indicator reference URL
	IndicatorRegistryDataBytes                            fields.Field = "threat.indicator.registry.data.bytes"                               // Original bytes written with base64 encoding.
	IndicatorRegistryDataStrings                          fields.Field = "threat.indicator.registry.data.strings"                             // List of strings representing what was written to the registry.
	IndicatorRegistryDataType                             fields.Field = "threat.indicator.registry.data.type"                                // Standard registry type for encoding contents
	IndicatorRegistryHive                                 fields.Field = "threat.indicator.registry.hive"                                     // Abbreviated name for the hive.
	IndicatorRegistryKey                                  fields.Field = "threat.indicator.registry.key"                                      // Hive-relative path of keys.
	IndicatorRegistryPath                                 fields.Field = "threat.indicator.registry.path"                                     // Full path, including hive, key and value
	IndicatorRegistryValue                                fields.Field = "threat.indicator.registry.value"                                    // Name of the value written.
	IndicatorScannerStats                                 fields.Field = "threat.indicator.scanner_stats"                                     // Scanner statistics
	IndicatorSightings                                    fields.Field = "threat.indicator.sightings"                                         // Number of times indicator observed
	IndicatorType                                         fields.Field = "threat.indicator.type"                                              // Type of indicator
	IndicatorUrlDomain                                    fields.Field = "threat.indicator.url.domain"                                        // Domain of the url.
	IndicatorUrlExtension                                 fields.Field = "threat.indicator.url.extension"                                     // File extension from the request url, excluding the leading dot.
	IndicatorUrlFragment                                  fields.Field = "threat.indicator.url.fragment"                                      // Portion of the url after the `#`.
	IndicatorUrlFull                                      fields.Field = "threat.indicator.url.full"                                          // Full unparsed URL.
	IndicatorUrlOriginal                                  fields.Field = "threat.indicator.url.original"                                      // Unmodified original url as seen in the event source.
	IndicatorUrlPassword                                  fields.Field = "threat.indicator.url.password"                                      // Password of the request.
	IndicatorUrlPath                                      fields.Field = "threat.indicator.url.path"                                          // Path of the request, such as "/search".
	IndicatorUrlPort                                      fields.Field = "threat.indicator.url.port"                                          // Port of the request, such as 443.
	IndicatorUrlQuery                                     fields.Field = "threat.indicator.url.query"                                         // Query string of the request.
	IndicatorUrlRegisteredDomain                          fields.Field = "threat.indicator.url.registered_domain"                             // The highest registered url domain, stripped of the subdomain.
	IndicatorUrlScheme                                    fields.Field = "threat.indicator.url.scheme"                                        // Scheme of the url.
	IndicatorUrlSubdomain                                 fields.Field = "threat.indicator.url.subdomain"                                     // The subdomain of the domain.
	IndicatorUrlTopLevelDomain                            fields.Field = "threat.indicator.url.top_level_domain"                              // The effective top level domain (com, org, net, co.uk).
	IndicatorUrlUsername                                  fields.Field = "threat.indicator.url.username"                                      // Username of the request.
	IndicatorX509AlternativeNames                         fields.Field = "threat.indicator.x509.alternative_names"                            // List of subject alternative names (SAN).
	IndicatorX509IssuerCommonName                         fields.Field = "threat.indicator.x509.issuer.common_name"                           // List of common name (CN) of issuing certificate authority.
	IndicatorX509IssuerCountry                            fields.Field = "threat.indicator.x509.issuer.country"                               // List of country \(C) codes
	IndicatorX509IssuerDistinguishedName                  fields.Field = "threat.indicator.x509.issuer.distinguished_name"                    // Distinguished name (DN) of issuing certificate authority.
	IndicatorX509IssuerLocality                           fields.Field = "threat.indicator.x509.issuer.locality"                              // List of locality names (L)
	IndicatorX509IssuerOrganization                       fields.Field = "threat.indicator.x509.issuer.organization"                          // List of organizations (O) of issuing certificate authority.
	IndicatorX509IssuerOrganizationalUnit                 fields.Field = "threat.indicator.x509.issuer.organizational_unit"                   // List of organizational units (OU) of issuing certificate authority.
	IndicatorX509IssuerStateOrProvince                    fields.Field = "threat.indicator.x509.issuer.state_or_province"                     // List of state or province names (ST, S, or P)
	IndicatorX509NotAfter                                 fields.Field = "threat.indicator.x509.not_after"                                    // Time at which the certificate is no longer considered valid.
	IndicatorX509NotBefore                                fields.Field = "threat.indicator.x509.not_before"                                   // Time at which the certificate is first considered valid.
	IndicatorX509PublicKeyAlgorithm                       fields.Field = "threat.indicator.x509.public_key_algorithm"                         // Algorithm used to generate the public key.
	IndicatorX509PublicKeyCurve                           fields.Field = "threat.indicator.x509.public_key_curve"                             // The curve used by the elliptic curve public key algorithm. This is algorithm specific.
	IndicatorX509PublicKeyExponent                        fields.Field = "threat.indicator.x509.public_key_exponent"                          // Exponent used to derive the public key. This is algorithm specific.
	IndicatorX509PublicKeySize                            fields.Field = "threat.indicator.x509.public_key_size"                              // The size of the public key space in bits.
	IndicatorX509SerialNumber                             fields.Field = "threat.indicator.x509.serial_number"                                // Unique serial number issued by the certificate authority.
	IndicatorX509SignatureAlgorithm                       fields.Field = "threat.indicator.x509.signature_algorithm"                          // Identifier for certificate signature algorithm.
	IndicatorX509SubjectCommonName                        fields.Field = "threat.indicator.x509.subject.common_name"                          // List of common names (CN) of subject.
	IndicatorX509SubjectCountry                           fields.Field = "threat.indicator.x509.subject.country"                              // List of country \(C) code
	IndicatorX509SubjectDistinguishedName                 fields.Field = "threat.indicator.x509.subject.distinguished_name"                   // Distinguished name (DN) of the certificate subject entity.
	IndicatorX509SubjectLocality                          fields.Field = "threat.indicator.x509.subject.locality"                             // List of locality names (L)
	IndicatorX509SubjectOrganization                      fields.Field = "threat.indicator.x509.subject.organization"                         // List of organizations (O) of subject.
	IndicatorX509SubjectOrganizationalUnit                fields.Field = "threat.indicator.x509.subject.organizational_unit"                  // List of organizational units (OU) of subject.
	IndicatorX509SubjectStateOrProvince                   fields.Field = "threat.indicator.x509.subject.state_or_province"                    // List of state or province names (ST, S, or P)
	IndicatorX509VersionNumber                            fields.Field = "threat.indicator.x509.version_number"                               // Version of x509 format.
	SoftwareAlias                                         fields.Field = "threat.software.alias"                                              // Alias of the software
	SoftwareID                                            fields.Field = "threat.software.id"                                                 // ID of the software
	SoftwareName                                          fields.Field = "threat.software.name"                                               // Name of the software.
	SoftwarePlatforms                                     fields.Field = "threat.software.platforms"                                          // Platforms of the software.
	SoftwareReference                                     fields.Field = "threat.software.reference"                                          // Software reference URL.
	SoftwareType                                          fields.Field = "threat.software.type"                                               // Software type.
	TacticID                                              fields.Field = "threat.tactic.id"                                                   // Threat tactic id.
	TacticName                                            fields.Field = "threat.tactic.name"                                                 // Threat tactic.
	TacticReference                                       fields.Field = "threat.tactic.reference"                                            // Threat tactic URL reference.
	TechniqueID                                           fields.Field = "threat.technique.id"                                                // Threat technique id.
	TechniqueName                                         fields.Field = "threat.technique.name"                                              // Threat technique name.
	TechniqueReference                                    fields.Field = "threat.technique.reference"                                         // Threat technique URL reference.
	TechniqueSubtechniqueID                               fields.Field = "threat.technique.subtechnique.id"                                   // Threat subtechnique id.
	TechniqueSubtechniqueName                             fields.Field = "threat.technique.subtechnique.name"                                 // Threat subtechnique name.
	TechniqueSubtechniqueReference                        fields.Field = "threat.technique.subtechnique.reference"                            // Threat subtechnique URL reference.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	EnrichmentsIndicatorAsNumber,
	EnrichmentsIndicatorAsOrganizationName,
	EnrichmentsIndicatorConfidence,
	EnrichmentsIndicatorDescription,
	EnrichmentsIndicatorEmailAddress,
	EnrichmentsIndicatorFileAccessed,
	EnrichmentsIndicatorFileAttributes,
	EnrichmentsIndicatorFileCodeSignatureDigestAlgorithm,
	EnrichmentsIndicatorFileCodeSignatureExists,
	EnrichmentsIndicatorFileCodeSignatureSigningID,
	EnrichmentsIndicatorFileCodeSignatureStatus,
	EnrichmentsIndicatorFileCodeSignatureSubjectName,
	EnrichmentsIndicatorFileCodeSignatureTeamID,
	EnrichmentsIndicatorFileCodeSignatureTimestamp,
	EnrichmentsIndicatorFileCodeSignatureTrusted,
	EnrichmentsIndicatorFileCodeSignatureValid,
	EnrichmentsIndicatorFileCreated,
	EnrichmentsIndicatorFileCtime,
	EnrichmentsIndicatorFileDevice,
	EnrichmentsIndicatorFileDirectory,
	EnrichmentsIndicatorFileDriveLetter,
	EnrichmentsIndicatorFileElfArchitecture,
	EnrichmentsIndicatorFileElfByteOrder,
	EnrichmentsIndicatorFileElfCpuType,
	EnrichmentsIndicatorFileElfCreationDate,
	EnrichmentsIndicatorFileElfExports,
	EnrichmentsIndicatorFileElfGoImportHash,
	EnrichmentsIndicatorFileElfGoImports,
	EnrichmentsIndicatorFileElfGoImportsNamesEntropy,
	EnrichmentsIndicatorFileElfGoImportsNamesVarEntropy,
	EnrichmentsIndicatorFileElfGoStripped,
	EnrichmentsIndicatorFileElfHeaderAbiVersion,
	EnrichmentsIndicatorFileElfHeaderClass,
	EnrichmentsIndicatorFileElfHeaderData,
	EnrichmentsIndicatorFileElfHeaderEntrypoint,
	EnrichmentsIndicatorFileElfHeaderObjectVersion,
	EnrichmentsIndicatorFileElfHeaderOsAbi,
	EnrichmentsIndicatorFileElfHeaderType,
	EnrichmentsIndicatorFileElfHeaderVersion,
	EnrichmentsIndicatorFileElfImportHash,
	EnrichmentsIndicatorFileElfImports,
	EnrichmentsIndicatorFileElfImportsNamesEntropy,
	EnrichmentsIndicatorFileElfImportsNamesVarEntropy,
	EnrichmentsIndicatorFileElfSectionsChi2,
	EnrichmentsIndicatorFileElfSectionsEntropy,
	EnrichmentsIndicatorFileElfSectionsFlags,
	EnrichmentsIndicatorFileElfSectionsName,
	EnrichmentsIndicatorFileElfSectionsPhysicalOffset,
	EnrichmentsIndicatorFileElfSectionsPhysicalSize,
	EnrichmentsIndicatorFileElfSectionsType,
	EnrichmentsIndicatorFileElfSectionsVarEntropy,
	EnrichmentsIndicatorFileElfSectionsVirtualAddress,
	EnrichmentsIndicatorFileElfSectionsVirtualSize,
	EnrichmentsIndicatorFileElfSegmentsSections,
	EnrichmentsIndicatorFileElfSegmentsType,
	EnrichmentsIndicatorFileElfSharedLibraries,
	EnrichmentsIndicatorFileElfTelfhash,
	EnrichmentsIndicatorFileExtension,
	EnrichmentsIndicatorFileForkName,
	EnrichmentsIndicatorFileGid,
	EnrichmentsIndicatorFileGroup,
	EnrichmentsIndicatorFileHashMd5,
	EnrichmentsIndicatorFileHashSha1,
	EnrichmentsIndicatorFileHashSha256,
	EnrichmentsIndicatorFileHashSha384,
	EnrichmentsIndicatorFileHashSha512,
	EnrichmentsIndicatorFileHashSsdeep,
	EnrichmentsIndicatorFileHashTlsh,
	EnrichmentsIndicatorFileInode,
	EnrichmentsIndicatorFileMimeType,
	EnrichmentsIndicatorFileMode,
	EnrichmentsIndicatorFileMtime,
	EnrichmentsIndicatorFileName,
	EnrichmentsIndicatorFileOwner,
	EnrichmentsIndicatorFilePath,
	EnrichmentsIndicatorFilePeArchitecture,
	EnrichmentsIndicatorFilePeCompany,
	EnrichmentsIndicatorFilePeDescription,
	EnrichmentsIndicatorFilePeFileVersion,
	EnrichmentsIndicatorFilePeGoImportHash,
	EnrichmentsIndicatorFilePeGoImports,
	EnrichmentsIndicatorFilePeGoImportsNamesEntropy,
	EnrichmentsIndicatorFilePeGoImportsNamesVarEntropy,
	EnrichmentsIndicatorFilePeGoStripped,
	EnrichmentsIndicatorFilePeImphash,
	EnrichmentsIndicatorFilePeImportHash,
	EnrichmentsIndicatorFilePeImports,
	EnrichmentsIndicatorFilePeImportsNamesEntropy,
	EnrichmentsIndicatorFilePeImportsNamesVarEntropy,
	EnrichmentsIndicatorFilePeOriginalFileName,
	EnrichmentsIndicatorFilePePehash,
	EnrichmentsIndicatorFilePeProduct,
	EnrichmentsIndicatorFilePeSectionsEntropy,
	EnrichmentsIndicatorFilePeSectionsName,
	EnrichmentsIndicatorFilePeSectionsPhysicalSize,
	EnrichmentsIndicatorFilePeSectionsVarEntropy,
	EnrichmentsIndicatorFilePeSectionsVirtualSize,
	EnrichmentsIndicatorFileSize,
	EnrichmentsIndicatorFileTargetPath,
	EnrichmentsIndicatorFileType,
	EnrichmentsIndicatorFileUid,
	EnrichmentsIndicatorFileX509AlternativeNames,
	EnrichmentsIndicatorFileX509IssuerCommonName,
	EnrichmentsIndicatorFileX509IssuerCountry,
	EnrichmentsIndicatorFileX509IssuerDistinguishedName,
	EnrichmentsIndicatorFileX509IssuerLocality,
	EnrichmentsIndicatorFileX509IssuerOrganization,
	EnrichmentsIndicatorFileX509IssuerOrganizationalUnit,
	EnrichmentsIndicatorFileX509IssuerStateOrProvince,
	EnrichmentsIndicatorFileX509NotAfter,
	EnrichmentsIndicatorFileX509NotBefore,
	EnrichmentsIndicatorFileX509PublicKeyAlgorithm,
	EnrichmentsIndicatorFileX509PublicKeyCurve,
	EnrichmentsIndicatorFileX509PublicKeyExponent,
	EnrichmentsIndicatorFileX509PublicKeySize,
	EnrichmentsIndicatorFileX509SerialNumber,
	EnrichmentsIndicatorFileX509SignatureAlgorithm,
	EnrichmentsIndicatorFileX509SubjectCommonName,
	EnrichmentsIndicatorFileX509SubjectCountry,
	EnrichmentsIndicatorFileX509SubjectDistinguishedName,
	EnrichmentsIndicatorFileX509SubjectLocality,
	EnrichmentsIndicatorFileX509SubjectOrganization,
	EnrichmentsIndicatorFileX509SubjectOrganizationalUnit,
	EnrichmentsIndicatorFileX509SubjectStateOrProvince,
	EnrichmentsIndicatorFileX509VersionNumber,
	EnrichmentsIndicatorFirstSeen,
	EnrichmentsIndicatorGeoCityName,
	EnrichmentsIndicatorGeoContinentCode,
	EnrichmentsIndicatorGeoContinentName,
	EnrichmentsIndicatorGeoCountryIsoCode,
	EnrichmentsIndicatorGeoCountryName,
	EnrichmentsIndicatorGeoLocation,
	EnrichmentsIndicatorGeoName,
	EnrichmentsIndicatorGeoPostalCode,
	EnrichmentsIndicatorGeoRegionIsoCode,
	EnrichmentsIndicatorGeoRegionName,
	EnrichmentsIndicatorGeoTimezone,
	EnrichmentsIndicatorIp,
	EnrichmentsIndicatorLastSeen,
	EnrichmentsIndicatorMarkingTlp,
	EnrichmentsIndicatorMarkingTlpVersion,
	EnrichmentsIndicatorModifiedAt,
	EnrichmentsIndicatorName,
	EnrichmentsIndicatorPort,
	EnrichmentsIndicatorProvider,
	EnrichmentsIndicatorReference,
	EnrichmentsIndicatorRegistryDataBytes,
	EnrichmentsIndicatorRegistryDataStrings,
	EnrichmentsIndicatorRegistryDataType,
	EnrichmentsIndicatorRegistryHive,
	EnrichmentsIndicatorRegistryKey,
	EnrichmentsIndicatorRegistryPath,
	EnrichmentsIndicatorRegistryValue,
	EnrichmentsIndicatorScannerStats,
	EnrichmentsIndicatorSightings,
	EnrichmentsIndicatorType,
	EnrichmentsIndicatorUrlDomain,
	EnrichmentsIndicatorUrlExtension,
	EnrichmentsIndicatorUrlFragment,
	EnrichmentsIndicatorUrlFull,
	EnrichmentsIndicatorUrlOriginal,
	EnrichmentsIndicatorUrlPassword,
	EnrichmentsIndicatorUrlPath,
	EnrichmentsIndicatorUrlPort,
	EnrichmentsIndicatorUrlQuery,
	EnrichmentsIndicatorUrlRegisteredDomain,
	EnrichmentsIndicatorUrlScheme,
	EnrichmentsIndicatorUrlSubdomain,
	EnrichmentsIndicatorUrlTopLevelDomain,
	EnrichmentsIndicatorUrlUsername,
	EnrichmentsIndicatorX509AlternativeNames,
	EnrichmentsIndicatorX509IssuerCommonName,
	EnrichmentsIndicatorX509IssuerCountry,
	EnrichmentsIndicatorX509IssuerDistinguishedName,
	EnrichmentsIndicatorX509IssuerLocality,
	EnrichmentsIndicatorX509IssuerOrganization,
	EnrichmentsIndicatorX509IssuerOrganizationalUnit,
	EnrichmentsIndicatorX509IssuerStateOrProvince,
	EnrichmentsIndicatorX509NotAfter,
	EnrichmentsIndicatorX509NotBefore,
	EnrichmentsIndicatorX509PublicKeyAlgorithm,
	EnrichmentsIndicatorX509PublicKeyCurve,
	EnrichmentsIndicatorX509PublicKeyExponent,
	EnrichmentsIndicatorX509PublicKeySize,
	EnrichmentsIndicatorX509SerialNumber,
	EnrichmentsIndicatorX509SignatureAlgorithm,
	EnrichmentsIndicatorX509SubjectCommonName,
	EnrichmentsIndicatorX509SubjectCountry,
	EnrichmentsIndicatorX509SubjectDistinguishedName,
	EnrichmentsIndicatorX509SubjectLocality,
	EnrichmentsIndicatorX509SubjectOrganization,
	EnrichmentsIndicatorX509SubjectOrganizationalUnit,
	EnrichmentsIndicatorX509SubjectStateOrProvince,
	EnrichmentsIndicatorX509VersionNumber,
	EnrichmentsMatchedAtomic,
	EnrichmentsMatchedField,
	EnrichmentsMatchedID,
	EnrichmentsMatchedIndex,
	EnrichmentsMatchedOccurred,
	EnrichmentsMatchedType,
	FeedDashboardID,
	FeedDescription,
	FeedName,
	FeedReference,
	Framework,
	GroupAlias,
	GroupID,
	GroupName,
	GroupReference,
	IndicatorAsNumber,
	IndicatorAsOrganizationName,
	IndicatorConfidence,
	IndicatorDescription,
	IndicatorEmailAddress,
	IndicatorFileAccessed,
	IndicatorFileAttributes,
	IndicatorFileCodeSignatureDigestAlgorithm,
	IndicatorFileCodeSignatureExists,
	IndicatorFileCodeSignatureSigningID,
	IndicatorFileCodeSignatureStatus,
	IndicatorFileCodeSignatureSubjectName,
	IndicatorFileCodeSignatureTeamID,
	IndicatorFileCodeSignatureTimestamp,
	IndicatorFileCodeSignatureTrusted,
	IndicatorFileCodeSignatureValid,
	IndicatorFileCreated,
	IndicatorFileCtime,
	IndicatorFileDevice,
	IndicatorFileDirectory,
	IndicatorFileDriveLetter,
	IndicatorFileElfArchitecture,
	IndicatorFileElfByteOrder,
	IndicatorFileElfCpuType,
	IndicatorFileElfCreationDate,
	IndicatorFileElfExports,
	IndicatorFileElfGoImportHash,
	IndicatorFileElfGoImports,
	IndicatorFileElfGoImportsNamesEntropy,
	IndicatorFileElfGoImportsNamesVarEntropy,
	IndicatorFileElfGoStripped,
	IndicatorFileElfHeaderAbiVersion,
	IndicatorFileElfHeaderClass,
	IndicatorFileElfHeaderData,
	IndicatorFileElfHeaderEntrypoint,
	IndicatorFileElfHeaderObjectVersion,
	IndicatorFileElfHeaderOsAbi,
	IndicatorFileElfHeaderType,
	IndicatorFileElfHeaderVersion,
	IndicatorFileElfImportHash,
	IndicatorFileElfImports,
	IndicatorFileElfImportsNamesEntropy,
	IndicatorFileElfImportsNamesVarEntropy,
	IndicatorFileElfSectionsChi2,
	IndicatorFileElfSectionsEntropy,
	IndicatorFileElfSectionsFlags,
	IndicatorFileElfSectionsName,
	IndicatorFileElfSectionsPhysicalOffset,
	IndicatorFileElfSectionsPhysicalSize,
	IndicatorFileElfSectionsType,
	IndicatorFileElfSectionsVarEntropy,
	IndicatorFileElfSectionsVirtualAddress,
	IndicatorFileElfSectionsVirtualSize,
	IndicatorFileElfSegmentsSections,
	IndicatorFileElfSegmentsType,
	IndicatorFileElfSharedLibraries,
	IndicatorFileElfTelfhash,
	IndicatorFileExtension,
	IndicatorFileForkName,
	IndicatorFileGid,
	IndicatorFileGroup,
	IndicatorFileHashMd5,
	IndicatorFileHashSha1,
	IndicatorFileHashSha256,
	IndicatorFileHashSha384,
	IndicatorFileHashSha512,
	IndicatorFileHashSsdeep,
	IndicatorFileHashTlsh,
	IndicatorFileInode,
	IndicatorFileMimeType,
	IndicatorFileMode,
	IndicatorFileMtime,
	IndicatorFileName,
	IndicatorFileOwner,
	IndicatorFilePath,
	IndicatorFilePeArchitecture,
	IndicatorFilePeCompany,
	IndicatorFilePeDescription,
	IndicatorFilePeFileVersion,
	IndicatorFilePeGoImportHash,
	IndicatorFilePeGoImports,
	IndicatorFilePeGoImportsNamesEntropy,
	IndicatorFilePeGoImportsNamesVarEntropy,
	IndicatorFilePeGoStripped,
	IndicatorFilePeImphash,
	IndicatorFilePeImportHash,
	IndicatorFilePeImports,
	IndicatorFilePeImportsNamesEntropy,
	IndicatorFilePeImportsNamesVarEntropy,
	IndicatorFilePeOriginalFileName,
	IndicatorFilePePehash,
	IndicatorFilePeProduct,
	IndicatorFilePeSectionsEntropy,
	IndicatorFilePeSectionsName,
	IndicatorFilePeSectionsPhysicalSize,
	IndicatorFilePeSectionsVarEntropy,
	IndicatorFilePeSectionsVirtualSize,
	IndicatorFileSize,
	IndicatorFileTargetPath,
	IndicatorFileType,
	IndicatorFileUid,
	IndicatorFileX509AlternativeNames,
	IndicatorFileX509IssuerCommonName,
	IndicatorFileX509IssuerCountry,
	IndicatorFileX509IssuerDistinguishedName,
	IndicatorFileX509IssuerLocality,
	IndicatorFileX509IssuerOrganization,
	IndicatorFileX509IssuerOrganizationalUnit,
	IndicatorFileX509IssuerStateOrProvince,
	IndicatorFileX509NotAfter,
	IndicatorFileX509NotBefore,
	IndicatorFileX509PublicKeyAlgorithm,
	IndicatorFileX509PublicKeyCurve,
	IndicatorFileX509PublicKeyExponent,
	IndicatorFileX509PublicKeySize,
	IndicatorFileX509SerialNumber,
	IndicatorFileX509SignatureAlgorithm,
	IndicatorFileX509SubjectCommonName,
	IndicatorFileX509SubjectCountry,
	IndicatorFileX509SubjectDistinguishedName,
	IndicatorFileX509SubjectLocality,
	IndicatorFileX509SubjectOrganization,
	IndicatorFileX509SubjectOrganizationalUnit,
	IndicatorFileX509SubjectStateOrProvince,
	IndicatorFileX509VersionNumber,
	IndicatorFirstSeen,
	IndicatorGeoCityName,
	IndicatorGeoContinentCode,
	IndicatorGeoContinentName,
	IndicatorGeoCountryIsoCode,
	IndicatorGeoCountryName,
	IndicatorGeoLocation,
	IndicatorGeoName,
	IndicatorGeoPostalCode,
	IndicatorGeoRegionIsoCode,
	IndicatorGeoRegionName,
	IndicatorGeoTimezone,
	IndicatorIp,
	IndicatorLastSeen,
	IndicatorMarkingTlp,
	IndicatorMarkingTlpVersion,
	IndicatorModifiedAt,
	IndicatorName,
	IndicatorPort,
	IndicatorProvider,
	IndicatorReference,
	IndicatorRegistryDataBytes,
	IndicatorRegistryDataStrings,
	IndicatorRegistryDataType,
	IndicatorRegistryHive,
	IndicatorRegistryKey,
	IndicatorRegistryPath,
	IndicatorRegistryValue,
	IndicatorScannerStats,
	IndicatorSightings,
	IndicatorType,
	IndicatorUrlDomain,
	IndicatorUrlExtension,
	IndicatorUrlFragment,
	IndicatorUrlFull,
	IndicatorUrlOriginal,
	IndicatorUrlPassword,
	IndicatorUrlPath,
	IndicatorUrlPort,
	IndicatorUrlQuery,
	IndicatorUrlRegisteredDomain,
	IndicatorUrlScheme,
	IndicatorUrlSubdomain,
	IndicatorUrlTopLevelDomain,
	IndicatorUrlUsername,
	IndicatorX509AlternativeNames,
	IndicatorX509IssuerCommonName,
	IndicatorX509IssuerCountry,
	IndicatorX509IssuerDistinguishedName,
	IndicatorX509IssuerLocality,
	IndicatorX509IssuerOrganization,
	IndicatorX509IssuerOrganizationalUnit,
	IndicatorX509IssuerStateOrProvince,
	IndicatorX509NotAfter,
	IndicatorX509NotBefore,
	IndicatorX509PublicKeyAlgorithm,
	IndicatorX509PublicKeyCurve,
	IndicatorX509PublicKeyExponent,
	IndicatorX509PublicKeySize,
	IndicatorX509SerialNumber,
	IndicatorX509SignatureAlgorithm,
	IndicatorX509SubjectCommonName,
	IndicatorX509SubjectCountry,
	IndicatorX509SubjectDistinguishedName,
	IndicatorX509SubjectLocality,
	IndicatorX509SubjectOrganization,
	IndicatorX509SubjectOrganizationalUnit,
	IndicatorX509SubjectStateOrProvince,
	IndicatorX509VersionNumber,
	SoftwareAlias,
	SoftwareID,
	SoftwareName,
	SoftwarePlatforms,
	SoftwareReference,
	SoftwareType,
	TacticID,
	TacticName,
	TacticReference,
	TechniqueID,
	TechniqueName,
	TechniqueReference,
	TechniqueSubtechniqueID,
	TechniqueSubtechniqueName,
	TechniqueSubtechniqueReference,
}

type EnrichmentsIndicatorConfidenceExpectedType struct {
	High         string
	Low          string
	Medium       string
	None         string
	NotSpecified string
}

var EnrichmentsIndicatorConfidenceExpectedValues EnrichmentsIndicatorConfidenceExpectedType = EnrichmentsIndicatorConfidenceExpectedType{
	High:         `High`,
	Low:          `Low`,
	Medium:       `Medium`,
	None:         `None`,
	NotSpecified: `Not Specified`,
}

type EnrichmentsIndicatorMarkingTlpExpectedType struct {
	AMBER       string
	AMBERSTRICT string
	CLEAR       string
	GREEN       string
	RED         string
	WHITE       string
}

var EnrichmentsIndicatorMarkingTlpExpectedValues EnrichmentsIndicatorMarkingTlpExpectedType = EnrichmentsIndicatorMarkingTlpExpectedType{
	AMBER:       `AMBER`,
	AMBERSTRICT: `AMBER+STRICT`,
	CLEAR:       `CLEAR`,
	GREEN:       `GREEN`,
	RED:         `RED`,
	WHITE:       `WHITE`,
}

type EnrichmentsIndicatorTypeExpectedType struct {
	Artifact           string
	AutonomousSystem   string
	Directory          string
	DomainName         string
	EmailAddr          string
	File               string
	Ipv4Addr           string
	Ipv6Addr           string
	MacAddr            string
	Mutex              string
	Port               string
	Process            string
	Software           string
	Url                string
	UserAccount        string
	WindowsRegistryKey string
	X509Certificate    string
}

var EnrichmentsIndicatorTypeExpectedValues EnrichmentsIndicatorTypeExpectedType = EnrichmentsIndicatorTypeExpectedType{
	Artifact:           `artifact`,
	AutonomousSystem:   `autonomous-system`,
	Directory:          `directory`,
	DomainName:         `domain-name`,
	EmailAddr:          `email-addr`,
	File:               `file`,
	Ipv4Addr:           `ipv4-addr`,
	Ipv6Addr:           `ipv6-addr`,
	MacAddr:            `mac-addr`,
	Mutex:              `mutex`,
	Port:               `port`,
	Process:            `process`,
	Software:           `software`,
	Url:                `url`,
	UserAccount:        `user-account`,
	WindowsRegistryKey: `windows-registry-key`,
	X509Certificate:    `x509-certificate`,
}

type IndicatorConfidenceExpectedType struct {
	High         string
	Low          string
	Medium       string
	None         string
	NotSpecified string
}

var IndicatorConfidenceExpectedValues IndicatorConfidenceExpectedType = IndicatorConfidenceExpectedType{
	High:         `High`,
	Low:          `Low`,
	Medium:       `Medium`,
	None:         `None`,
	NotSpecified: `Not Specified`,
}

type IndicatorMarkingTlpExpectedType struct {
	AMBER       string
	AMBERSTRICT string
	CLEAR       string
	GREEN       string
	RED         string
	WHITE       string
}

var IndicatorMarkingTlpExpectedValues IndicatorMarkingTlpExpectedType = IndicatorMarkingTlpExpectedType{
	AMBER:       `AMBER`,
	AMBERSTRICT: `AMBER+STRICT`,
	CLEAR:       `CLEAR`,
	GREEN:       `GREEN`,
	RED:         `RED`,
	WHITE:       `WHITE`,
}

type IndicatorTypeExpectedType struct {
	Artifact           string
	AutonomousSystem   string
	Directory          string
	DomainName         string
	EmailAddr          string
	File               string
	Ipv4Addr           string
	Ipv6Addr           string
	MacAddr            string
	Mutex              string
	Port               string
	Process            string
	Software           string
	Url                string
	UserAccount        string
	WindowsRegistryKey string
	X509Certificate    string
}

var IndicatorTypeExpectedValues IndicatorTypeExpectedType = IndicatorTypeExpectedType{
	Artifact:           `artifact`,
	AutonomousSystem:   `autonomous-system`,
	Directory:          `directory`,
	DomainName:         `domain-name`,
	EmailAddr:          `email-addr`,
	File:               `file`,
	Ipv4Addr:           `ipv4-addr`,
	Ipv6Addr:           `ipv6-addr`,
	MacAddr:            `mac-addr`,
	Mutex:              `mutex`,
	Port:               `port`,
	Process:            `process`,
	Software:           `software`,
	Url:                `url`,
	UserAccount:        `user-account`,
	WindowsRegistryKey: `windows-registry-key`,
	X509Certificate:    `x509-certificate`,
}

type SoftwarePlatformsExpectedType struct {
	AWS       string
	Azure     string
	AzureAD   string
	GCP       string
	Linux     string
	MacOS     string
	Network   string
	Office365 string
	SaaS      string
	Windows   string
}

var SoftwarePlatformsExpectedValues SoftwarePlatformsExpectedType = SoftwarePlatformsExpectedType{
	AWS:       `AWS`,
	Azure:     `Azure`,
	AzureAD:   `Azure AD`,
	GCP:       `GCP`,
	Linux:     `Linux`,
	MacOS:     `macOS`,
	Network:   `Network`,
	Office365: `Office 365`,
	SaaS:      `SaaS`,
	Windows:   `Windows`,
}

type SoftwareTypeExpectedType struct {
	Malware string
	Tool    string
}

var SoftwareTypeExpectedValues SoftwareTypeExpectedType = SoftwareTypeExpectedType{
	Malware: `Malware`,
	Tool:    `Tool`,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	EnrichmentsIndicatorAsNumber                          fields.Long
	EnrichmentsIndicatorAsOrganizationName                fields.KeyWord
	EnrichmentsIndicatorConfidence                        fields.KeyWord
	EnrichmentsIndicatorDescription                       fields.KeyWord
	EnrichmentsIndicatorEmailAddress                      fields.KeyWord
	EnrichmentsIndicatorFileAccessed                      fields.Date
	EnrichmentsIndicatorFileAttributes                    fields.KeyWord
	EnrichmentsIndicatorFileCodeSignatureDigestAlgorithm  fields.KeyWord
	EnrichmentsIndicatorFileCodeSignatureExists           fields.Boolean
	EnrichmentsIndicatorFileCodeSignatureSigningID        fields.KeyWord
	EnrichmentsIndicatorFileCodeSignatureStatus           fields.KeyWord
	EnrichmentsIndicatorFileCodeSignatureSubjectName      fields.KeyWord
	EnrichmentsIndicatorFileCodeSignatureTeamID           fields.KeyWord
	EnrichmentsIndicatorFileCodeSignatureTimestamp        fields.Date
	EnrichmentsIndicatorFileCodeSignatureTrusted          fields.Boolean
	EnrichmentsIndicatorFileCodeSignatureValid            fields.Boolean
	EnrichmentsIndicatorFileCreated                       fields.Date
	EnrichmentsIndicatorFileCtime                         fields.Date
	EnrichmentsIndicatorFileDevice                        fields.KeyWord
	EnrichmentsIndicatorFileDirectory                     fields.KeyWord
	EnrichmentsIndicatorFileDriveLetter                   fields.KeyWord
	EnrichmentsIndicatorFileElfArchitecture               fields.KeyWord
	EnrichmentsIndicatorFileElfByteOrder                  fields.KeyWord
	EnrichmentsIndicatorFileElfCpuType                    fields.KeyWord
	EnrichmentsIndicatorFileElfCreationDate               fields.Date
	EnrichmentsIndicatorFileElfExports                    fields.Flattened
	EnrichmentsIndicatorFileElfGoImportHash               fields.KeyWord
	EnrichmentsIndicatorFileElfGoImports                  fields.Flattened
	EnrichmentsIndicatorFileElfGoImportsNamesEntropy      fields.Long
	EnrichmentsIndicatorFileElfGoImportsNamesVarEntropy   fields.Long
	EnrichmentsIndicatorFileElfGoStripped                 fields.Boolean
	EnrichmentsIndicatorFileElfHeaderAbiVersion           fields.KeyWord
	EnrichmentsIndicatorFileElfHeaderClass                fields.KeyWord
	EnrichmentsIndicatorFileElfHeaderData                 fields.KeyWord
	EnrichmentsIndicatorFileElfHeaderEntrypoint           fields.Long
	EnrichmentsIndicatorFileElfHeaderObjectVersion        fields.KeyWord
	EnrichmentsIndicatorFileElfHeaderOsAbi                fields.KeyWord
	EnrichmentsIndicatorFileElfHeaderType                 fields.KeyWord
	EnrichmentsIndicatorFileElfHeaderVersion              fields.KeyWord
	EnrichmentsIndicatorFileElfImportHash                 fields.KeyWord
	EnrichmentsIndicatorFileElfImports                    fields.Flattened
	EnrichmentsIndicatorFileElfImportsNamesEntropy        fields.Long
	EnrichmentsIndicatorFileElfImportsNamesVarEntropy     fields.Long
	EnrichmentsIndicatorFileElfSectionsChi2               fields.Long
	EnrichmentsIndicatorFileElfSectionsEntropy            fields.Long
	EnrichmentsIndicatorFileElfSectionsFlags              fields.KeyWord
	EnrichmentsIndicatorFileElfSectionsName               fields.KeyWord
	EnrichmentsIndicatorFileElfSectionsPhysicalOffset     fields.KeyWord
	EnrichmentsIndicatorFileElfSectionsPhysicalSize       fields.Long
	EnrichmentsIndicatorFileElfSectionsType               fields.KeyWord
	EnrichmentsIndicatorFileElfSectionsVarEntropy         fields.Long
	EnrichmentsIndicatorFileElfSectionsVirtualAddress     fields.Long
	EnrichmentsIndicatorFileElfSectionsVirtualSize        fields.Long
	EnrichmentsIndicatorFileElfSegmentsSections           fields.KeyWord
	EnrichmentsIndicatorFileElfSegmentsType               fields.KeyWord
	EnrichmentsIndicatorFileElfSharedLibraries            fields.KeyWord
	EnrichmentsIndicatorFileElfTelfhash                   fields.KeyWord
	EnrichmentsIndicatorFileExtension                     fields.KeyWord
	EnrichmentsIndicatorFileForkName                      fields.KeyWord
	EnrichmentsIndicatorFileGid                           fields.KeyWord
	EnrichmentsIndicatorFileGroup                         fields.KeyWord
	EnrichmentsIndicatorFileHashMd5                       fields.KeyWord
	EnrichmentsIndicatorFileHashSha1                      fields.KeyWord
	EnrichmentsIndicatorFileHashSha256                    fields.KeyWord
	EnrichmentsIndicatorFileHashSha384                    fields.KeyWord
	EnrichmentsIndicatorFileHashSha512                    fields.KeyWord
	EnrichmentsIndicatorFileHashSsdeep                    fields.KeyWord
	EnrichmentsIndicatorFileHashTlsh                      fields.KeyWord
	EnrichmentsIndicatorFileInode                         fields.KeyWord
	EnrichmentsIndicatorFileMimeType                      fields.KeyWord
	EnrichmentsIndicatorFileMode                          fields.KeyWord
	EnrichmentsIndicatorFileMtime                         fields.Date
	EnrichmentsIndicatorFileName                          fields.KeyWord
	EnrichmentsIndicatorFileOwner                         fields.KeyWord
	EnrichmentsIndicatorFilePath                          fields.KeyWord
	EnrichmentsIndicatorFilePeArchitecture                fields.KeyWord
	EnrichmentsIndicatorFilePeCompany                     fields.KeyWord
	EnrichmentsIndicatorFilePeDescription                 fields.KeyWord
	EnrichmentsIndicatorFilePeFileVersion                 fields.KeyWord
	EnrichmentsIndicatorFilePeGoImportHash                fields.KeyWord
	EnrichmentsIndicatorFilePeGoImports                   fields.Flattened
	EnrichmentsIndicatorFilePeGoImportsNamesEntropy       fields.Long
	EnrichmentsIndicatorFilePeGoImportsNamesVarEntropy    fields.Long
	EnrichmentsIndicatorFilePeGoStripped                  fields.Boolean
	EnrichmentsIndicatorFilePeImphash                     fields.KeyWord
	EnrichmentsIndicatorFilePeImportHash                  fields.KeyWord
	EnrichmentsIndicatorFilePeImports                     fields.Flattened
	EnrichmentsIndicatorFilePeImportsNamesEntropy         fields.Long
	EnrichmentsIndicatorFilePeImportsNamesVarEntropy      fields.Long
	EnrichmentsIndicatorFilePeOriginalFileName            fields.KeyWord
	EnrichmentsIndicatorFilePePehash                      fields.KeyWord
	EnrichmentsIndicatorFilePeProduct                     fields.KeyWord
	EnrichmentsIndicatorFilePeSectionsEntropy             fields.Long
	EnrichmentsIndicatorFilePeSectionsName                fields.KeyWord
	EnrichmentsIndicatorFilePeSectionsPhysicalSize        fields.Long
	EnrichmentsIndicatorFilePeSectionsVarEntropy          fields.Long
	EnrichmentsIndicatorFilePeSectionsVirtualSize         fields.Long
	EnrichmentsIndicatorFileSize                          fields.Long
	EnrichmentsIndicatorFileTargetPath                    fields.KeyWord
	EnrichmentsIndicatorFileType                          fields.KeyWord
	EnrichmentsIndicatorFileUid                           fields.KeyWord
	EnrichmentsIndicatorFileX509AlternativeNames          fields.KeyWord
	EnrichmentsIndicatorFileX509IssuerCommonName          fields.KeyWord
	EnrichmentsIndicatorFileX509IssuerCountry             fields.KeyWord
	EnrichmentsIndicatorFileX509IssuerDistinguishedName   fields.KeyWord
	EnrichmentsIndicatorFileX509IssuerLocality            fields.KeyWord
	EnrichmentsIndicatorFileX509IssuerOrganization        fields.KeyWord
	EnrichmentsIndicatorFileX509IssuerOrganizationalUnit  fields.KeyWord
	EnrichmentsIndicatorFileX509IssuerStateOrProvince     fields.KeyWord
	EnrichmentsIndicatorFileX509NotAfter                  fields.Date
	EnrichmentsIndicatorFileX509NotBefore                 fields.Date
	EnrichmentsIndicatorFileX509PublicKeyAlgorithm        fields.KeyWord
	EnrichmentsIndicatorFileX509PublicKeyCurve            fields.KeyWord
	EnrichmentsIndicatorFileX509PublicKeyExponent         fields.Long
	EnrichmentsIndicatorFileX509PublicKeySize             fields.Long
	EnrichmentsIndicatorFileX509SerialNumber              fields.KeyWord
	EnrichmentsIndicatorFileX509SignatureAlgorithm        fields.KeyWord
	EnrichmentsIndicatorFileX509SubjectCommonName         fields.KeyWord
	EnrichmentsIndicatorFileX509SubjectCountry            fields.KeyWord
	EnrichmentsIndicatorFileX509SubjectDistinguishedName  fields.KeyWord
	EnrichmentsIndicatorFileX509SubjectLocality           fields.KeyWord
	EnrichmentsIndicatorFileX509SubjectOrganization       fields.KeyWord
	EnrichmentsIndicatorFileX509SubjectOrganizationalUnit fields.KeyWord
	EnrichmentsIndicatorFileX509SubjectStateOrProvince    fields.KeyWord
	EnrichmentsIndicatorFileX509VersionNumber             fields.KeyWord
	EnrichmentsIndicatorFirstSeen                         fields.Date
	EnrichmentsIndicatorGeoCityName                       fields.KeyWord
	EnrichmentsIndicatorGeoContinentCode                  fields.KeyWord
	EnrichmentsIndicatorGeoContinentName                  fields.KeyWord
	EnrichmentsIndicatorGeoCountryIsoCode                 fields.KeyWord
	EnrichmentsIndicatorGeoCountryName                    fields.KeyWord
	EnrichmentsIndicatorGeoLocation                       fields.GeoPoint
	EnrichmentsIndicatorGeoName                           fields.KeyWord
	EnrichmentsIndicatorGeoPostalCode                     fields.KeyWord
	EnrichmentsIndicatorGeoRegionIsoCode                  fields.KeyWord
	EnrichmentsIndicatorGeoRegionName                     fields.KeyWord
	EnrichmentsIndicatorGeoTimezone                       fields.KeyWord
	EnrichmentsIndicatorIp                                fields.IP
	EnrichmentsIndicatorLastSeen                          fields.Date
	EnrichmentsIndicatorMarkingTlp                        fields.KeyWord
	EnrichmentsIndicatorMarkingTlpVersion                 fields.KeyWord
	EnrichmentsIndicatorModifiedAt                        fields.Date
	EnrichmentsIndicatorName                              fields.KeyWord
	EnrichmentsIndicatorPort                              fields.Long
	EnrichmentsIndicatorProvider                          fields.KeyWord
	EnrichmentsIndicatorReference                         fields.KeyWord
	EnrichmentsIndicatorRegistryDataBytes                 fields.KeyWord
	EnrichmentsIndicatorRegistryDataStrings               fields.Wildcard
	EnrichmentsIndicatorRegistryDataType                  fields.KeyWord
	EnrichmentsIndicatorRegistryHive                      fields.KeyWord
	EnrichmentsIndicatorRegistryKey                       fields.KeyWord
	EnrichmentsIndicatorRegistryPath                      fields.KeyWord
	EnrichmentsIndicatorRegistryValue                     fields.KeyWord
	EnrichmentsIndicatorScannerStats                      fields.Long
	EnrichmentsIndicatorSightings                         fields.Long
	EnrichmentsIndicatorType                              fields.KeyWord
	EnrichmentsIndicatorUrlDomain                         fields.KeyWord
	EnrichmentsIndicatorUrlExtension                      fields.KeyWord
	EnrichmentsIndicatorUrlFragment                       fields.KeyWord
	EnrichmentsIndicatorUrlFull                           fields.Wildcard
	EnrichmentsIndicatorUrlOriginal                       fields.Wildcard
	EnrichmentsIndicatorUrlPassword                       fields.KeyWord
	EnrichmentsIndicatorUrlPath                           fields.Wildcard
	EnrichmentsIndicatorUrlPort                           fields.Long
	EnrichmentsIndicatorUrlQuery                          fields.KeyWord
	EnrichmentsIndicatorUrlRegisteredDomain               fields.KeyWord
	EnrichmentsIndicatorUrlScheme                         fields.KeyWord
	EnrichmentsIndicatorUrlSubdomain                      fields.KeyWord
	EnrichmentsIndicatorUrlTopLevelDomain                 fields.KeyWord
	EnrichmentsIndicatorUrlUsername                       fields.KeyWord
	EnrichmentsIndicatorX509AlternativeNames              fields.KeyWord
	EnrichmentsIndicatorX509IssuerCommonName              fields.KeyWord
	EnrichmentsIndicatorX509IssuerCountry                 fields.KeyWord
	EnrichmentsIndicatorX509IssuerDistinguishedName       fields.KeyWord
	EnrichmentsIndicatorX509IssuerLocality                fields.KeyWord
	EnrichmentsIndicatorX509IssuerOrganization            fields.KeyWord
	EnrichmentsIndicatorX509IssuerOrganizationalUnit      fields.KeyWord
	EnrichmentsIndicatorX509IssuerStateOrProvince         fields.KeyWord
	EnrichmentsIndicatorX509NotAfter                      fields.Date
	EnrichmentsIndicatorX509NotBefore                     fields.Date
	EnrichmentsIndicatorX509PublicKeyAlgorithm            fields.KeyWord
	EnrichmentsIndicatorX509PublicKeyCurve                fields.KeyWord
	EnrichmentsIndicatorX509PublicKeyExponent             fields.Long
	EnrichmentsIndicatorX509PublicKeySize                 fields.Long
	EnrichmentsIndicatorX509SerialNumber                  fields.KeyWord
	EnrichmentsIndicatorX509SignatureAlgorithm            fields.KeyWord
	EnrichmentsIndicatorX509SubjectCommonName             fields.KeyWord
	EnrichmentsIndicatorX509SubjectCountry                fields.KeyWord
	EnrichmentsIndicatorX509SubjectDistinguishedName      fields.KeyWord
	EnrichmentsIndicatorX509SubjectLocality               fields.KeyWord
	EnrichmentsIndicatorX509SubjectOrganization           fields.KeyWord
	EnrichmentsIndicatorX509SubjectOrganizationalUnit     fields.KeyWord
	EnrichmentsIndicatorX509SubjectStateOrProvince        fields.KeyWord
	EnrichmentsIndicatorX509VersionNumber                 fields.KeyWord
	EnrichmentsMatchedAtomic                              fields.KeyWord
	EnrichmentsMatchedField                               fields.KeyWord
	EnrichmentsMatchedID                                  fields.KeyWord
	EnrichmentsMatchedIndex                               fields.KeyWord
	EnrichmentsMatchedOccurred                            fields.Date
	EnrichmentsMatchedType                                fields.KeyWord
	FeedDashboardID                                       fields.KeyWord
	FeedDescription                                       fields.KeyWord
	FeedName                                              fields.KeyWord
	FeedReference                                         fields.KeyWord
	Framework                                             fields.KeyWord
	GroupAlias                                            fields.KeyWord
	GroupID                                               fields.KeyWord
	GroupName                                             fields.KeyWord
	GroupReference                                        fields.KeyWord
	IndicatorAsNumber                                     fields.Long
	IndicatorAsOrganizationName                           fields.KeyWord
	IndicatorConfidence                                   fields.KeyWord
	IndicatorDescription                                  fields.KeyWord
	IndicatorEmailAddress                                 fields.KeyWord
	IndicatorFileAccessed                                 fields.Date
	IndicatorFileAttributes                               fields.KeyWord
	IndicatorFileCodeSignatureDigestAlgorithm             fields.KeyWord
	IndicatorFileCodeSignatureExists                      fields.Boolean
	IndicatorFileCodeSignatureSigningID                   fields.KeyWord
	IndicatorFileCodeSignatureStatus                      fields.KeyWord
	IndicatorFileCodeSignatureSubjectName                 fields.KeyWord
	IndicatorFileCodeSignatureTeamID                      fields.KeyWord
	IndicatorFileCodeSignatureTimestamp                   fields.Date
	IndicatorFileCodeSignatureTrusted                     fields.Boolean
	IndicatorFileCodeSignatureValid                       fields.Boolean
	IndicatorFileCreated                                  fields.Date
	IndicatorFileCtime                                    fields.Date
	IndicatorFileDevice                                   fields.KeyWord
	IndicatorFileDirectory                                fields.KeyWord
	IndicatorFileDriveLetter                              fields.KeyWord
	IndicatorFileElfArchitecture                          fields.KeyWord
	IndicatorFileElfByteOrder                             fields.KeyWord
	IndicatorFileElfCpuType                               fields.KeyWord
	IndicatorFileElfCreationDate                          fields.Date
	IndicatorFileElfExports                               fields.Flattened
	IndicatorFileElfGoImportHash                          fields.KeyWord
	IndicatorFileElfGoImports                             fields.Flattened
	IndicatorFileElfGoImportsNamesEntropy                 fields.Long
	IndicatorFileElfGoImportsNamesVarEntropy              fields.Long
	IndicatorFileElfGoStripped                            fields.Boolean
	IndicatorFileElfHeaderAbiVersion                      fields.KeyWord
	IndicatorFileElfHeaderClass                           fields.KeyWord
	IndicatorFileElfHeaderData                            fields.KeyWord
	IndicatorFileElfHeaderEntrypoint                      fields.Long
	IndicatorFileElfHeaderObjectVersion                   fields.KeyWord
	IndicatorFileElfHeaderOsAbi                           fields.KeyWord
	IndicatorFileElfHeaderType                            fields.KeyWord
	IndicatorFileElfHeaderVersion                         fields.KeyWord
	IndicatorFileElfImportHash                            fields.KeyWord
	IndicatorFileElfImports                               fields.Flattened
	IndicatorFileElfImportsNamesEntropy                   fields.Long
	IndicatorFileElfImportsNamesVarEntropy                fields.Long
	IndicatorFileElfSectionsChi2                          fields.Long
	IndicatorFileElfSectionsEntropy                       fields.Long
	IndicatorFileElfSectionsFlags                         fields.KeyWord
	IndicatorFileElfSectionsName                          fields.KeyWord
	IndicatorFileElfSectionsPhysicalOffset                fields.KeyWord
	IndicatorFileElfSectionsPhysicalSize                  fields.Long
	IndicatorFileElfSectionsType                          fields.KeyWord
	IndicatorFileElfSectionsVarEntropy                    fields.Long
	IndicatorFileElfSectionsVirtualAddress                fields.Long
	IndicatorFileElfSectionsVirtualSize                   fields.Long
	IndicatorFileElfSegmentsSections                      fields.KeyWord
	IndicatorFileElfSegmentsType                          fields.KeyWord
	IndicatorFileElfSharedLibraries                       fields.KeyWord
	IndicatorFileElfTelfhash                              fields.KeyWord
	IndicatorFileExtension                                fields.KeyWord
	IndicatorFileForkName                                 fields.KeyWord
	IndicatorFileGid                                      fields.KeyWord
	IndicatorFileGroup                                    fields.KeyWord
	IndicatorFileHashMd5                                  fields.KeyWord
	IndicatorFileHashSha1                                 fields.KeyWord
	IndicatorFileHashSha256                               fields.KeyWord
	IndicatorFileHashSha384                               fields.KeyWord
	IndicatorFileHashSha512                               fields.KeyWord
	IndicatorFileHashSsdeep                               fields.KeyWord
	IndicatorFileHashTlsh                                 fields.KeyWord
	IndicatorFileInode                                    fields.KeyWord
	IndicatorFileMimeType                                 fields.KeyWord
	IndicatorFileMode                                     fields.KeyWord
	IndicatorFileMtime                                    fields.Date
	IndicatorFileName                                     fields.KeyWord
	IndicatorFileOwner                                    fields.KeyWord
	IndicatorFilePath                                     fields.KeyWord
	IndicatorFilePeArchitecture                           fields.KeyWord
	IndicatorFilePeCompany                                fields.KeyWord
	IndicatorFilePeDescription                            fields.KeyWord
	IndicatorFilePeFileVersion                            fields.KeyWord
	IndicatorFilePeGoImportHash                           fields.KeyWord
	IndicatorFilePeGoImports                              fields.Flattened
	IndicatorFilePeGoImportsNamesEntropy                  fields.Long
	IndicatorFilePeGoImportsNamesVarEntropy               fields.Long
	IndicatorFilePeGoStripped                             fields.Boolean
	IndicatorFilePeImphash                                fields.KeyWord
	IndicatorFilePeImportHash                             fields.KeyWord
	IndicatorFilePeImports                                fields.Flattened
	IndicatorFilePeImportsNamesEntropy                    fields.Long
	IndicatorFilePeImportsNamesVarEntropy                 fields.Long
	IndicatorFilePeOriginalFileName                       fields.KeyWord
	IndicatorFilePePehash                                 fields.KeyWord
	IndicatorFilePeProduct                                fields.KeyWord
	IndicatorFilePeSectionsEntropy                        fields.Long
	IndicatorFilePeSectionsName                           fields.KeyWord
	IndicatorFilePeSectionsPhysicalSize                   fields.Long
	IndicatorFilePeSectionsVarEntropy                     fields.Long
	IndicatorFilePeSectionsVirtualSize                    fields.Long
	IndicatorFileSize                                     fields.Long
	IndicatorFileTargetPath                               fields.KeyWord
	IndicatorFileType                                     fields.KeyWord
	IndicatorFileUid                                      fields.KeyWord
	IndicatorFileX509AlternativeNames                     fields.KeyWord
	IndicatorFileX509IssuerCommonName                     fields.KeyWord
	IndicatorFileX509IssuerCountry                        fields.KeyWord
	IndicatorFileX509IssuerDistinguishedName              fields.KeyWord
	IndicatorFileX509IssuerLocality                       fields.KeyWord
	IndicatorFileX509IssuerOrganization                   fields.KeyWord
	IndicatorFileX509IssuerOrganizationalUnit             fields.KeyWord
	IndicatorFileX509IssuerStateOrProvince                fields.KeyWord
	IndicatorFileX509NotAfter                             fields.Date
	IndicatorFileX509NotBefore                            fields.Date
	IndicatorFileX509PublicKeyAlgorithm                   fields.KeyWord
	IndicatorFileX509PublicKeyCurve                       fields.KeyWord
	IndicatorFileX509PublicKeyExponent                    fields.Long
	IndicatorFileX509PublicKeySize                        fields.Long
	IndicatorFileX509SerialNumber                         fields.KeyWord
	IndicatorFileX509SignatureAlgorithm                   fields.KeyWord
	IndicatorFileX509SubjectCommonName                    fields.KeyWord
	IndicatorFileX509SubjectCountry                       fields.KeyWord
	IndicatorFileX509SubjectDistinguishedName             fields.KeyWord
	IndicatorFileX509SubjectLocality                      fields.KeyWord
	IndicatorFileX509SubjectOrganization                  fields.KeyWord
	IndicatorFileX509SubjectOrganizationalUnit            fields.KeyWord
	IndicatorFileX509SubjectStateOrProvince               fields.KeyWord
	IndicatorFileX509VersionNumber                        fields.KeyWord
	IndicatorFirstSeen                                    fields.Date
	IndicatorGeoCityName                                  fields.KeyWord
	IndicatorGeoContinentCode                             fields.KeyWord
	IndicatorGeoContinentName                             fields.KeyWord
	IndicatorGeoCountryIsoCode                            fields.KeyWord
	IndicatorGeoCountryName                               fields.KeyWord
	IndicatorGeoLocation                                  fields.GeoPoint
	IndicatorGeoName                                      fields.KeyWord
	IndicatorGeoPostalCode                                fields.KeyWord
	IndicatorGeoRegionIsoCode                             fields.KeyWord
	IndicatorGeoRegionName                                fields.KeyWord
	IndicatorGeoTimezone                                  fields.KeyWord
	IndicatorIp                                           fields.IP
	IndicatorLastSeen                                     fields.Date
	IndicatorMarkingTlp                                   fields.KeyWord
	IndicatorMarkingTlpVersion                            fields.KeyWord
	IndicatorModifiedAt                                   fields.Date
	IndicatorName                                         fields.KeyWord
	IndicatorPort                                         fields.Long
	IndicatorProvider                                     fields.KeyWord
	IndicatorReference                                    fields.KeyWord
	IndicatorRegistryDataBytes                            fields.KeyWord
	IndicatorRegistryDataStrings                          fields.Wildcard
	IndicatorRegistryDataType                             fields.KeyWord
	IndicatorRegistryHive                                 fields.KeyWord
	IndicatorRegistryKey                                  fields.KeyWord
	IndicatorRegistryPath                                 fields.KeyWord
	IndicatorRegistryValue                                fields.KeyWord
	IndicatorScannerStats                                 fields.Long
	IndicatorSightings                                    fields.Long
	IndicatorType                                         fields.KeyWord
	IndicatorUrlDomain                                    fields.KeyWord
	IndicatorUrlExtension                                 fields.KeyWord
	IndicatorUrlFragment                                  fields.KeyWord
	IndicatorUrlFull                                      fields.Wildcard
	IndicatorUrlOriginal                                  fields.Wildcard
	IndicatorUrlPassword                                  fields.KeyWord
	IndicatorUrlPath                                      fields.Wildcard
	IndicatorUrlPort                                      fields.Long
	IndicatorUrlQuery                                     fields.KeyWord
	IndicatorUrlRegisteredDomain                          fields.KeyWord
	IndicatorUrlScheme                                    fields.KeyWord
	IndicatorUrlSubdomain                                 fields.KeyWord
	IndicatorUrlTopLevelDomain                            fields.KeyWord
	IndicatorUrlUsername                                  fields.KeyWord
	IndicatorX509AlternativeNames                         fields.KeyWord
	IndicatorX509IssuerCommonName                         fields.KeyWord
	IndicatorX509IssuerCountry                            fields.KeyWord
	IndicatorX509IssuerDistinguishedName                  fields.KeyWord
	IndicatorX509IssuerLocality                           fields.KeyWord
	IndicatorX509IssuerOrganization                       fields.KeyWord
	IndicatorX509IssuerOrganizationalUnit                 fields.KeyWord
	IndicatorX509IssuerStateOrProvince                    fields.KeyWord
	IndicatorX509NotAfter                                 fields.Date
	IndicatorX509NotBefore                                fields.Date
	IndicatorX509PublicKeyAlgorithm                       fields.KeyWord
	IndicatorX509PublicKeyCurve                           fields.KeyWord
	IndicatorX509PublicKeyExponent                        fields.Long
	IndicatorX509PublicKeySize                            fields.Long
	IndicatorX509SerialNumber                             fields.KeyWord
	IndicatorX509SignatureAlgorithm                       fields.KeyWord
	IndicatorX509SubjectCommonName                        fields.KeyWord
	IndicatorX509SubjectCountry                           fields.KeyWord
	IndicatorX509SubjectDistinguishedName                 fields.KeyWord
	IndicatorX509SubjectLocality                          fields.KeyWord
	IndicatorX509SubjectOrganization                      fields.KeyWord
	IndicatorX509SubjectOrganizationalUnit                fields.KeyWord
	IndicatorX509SubjectStateOrProvince                   fields.KeyWord
	IndicatorX509VersionNumber                            fields.KeyWord
	SoftwareAlias                                         fields.KeyWord
	SoftwareID                                            fields.KeyWord
	SoftwareName                                          fields.KeyWord
	SoftwarePlatforms                                     fields.KeyWord
	SoftwareReference                                     fields.KeyWord
	SoftwareType                                          fields.KeyWord
	TacticID                                              fields.KeyWord
	TacticName                                            fields.KeyWord
	TacticReference                                       fields.KeyWord
	TechniqueID                                           fields.KeyWord
	TechniqueName                                         fields.KeyWord
	TechniqueReference                                    fields.KeyWord
	TechniqueSubtechniqueID                               fields.KeyWord
	TechniqueSubtechniqueName                             fields.KeyWord
	TechniqueSubtechniqueReference                        fields.KeyWord
}

var Types TypesType = TypesType{}
