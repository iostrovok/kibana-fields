package threat

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Enrichments                                           fields.Field = "threat.enrichments"                                                 // List of objects containing indicators enriching the event.
	EnrichmentsIndicator                                  fields.Field = "threat.enrichments.indicator"                                       // Object containing indicators enriching the event.
	EnrichmentsIndicatorAsNumber                          fields.Field = "threat.enrichments.indicator.as.number"                             // Unique number allocated to the autonomous system.
	EnrichmentsIndicatorAsOrganizationName                fields.Field = "threat.enrichments.indicator.as.organization.name"                  // Organization name.
	EnrichmentsIndicatorConfidence                        fields.Field = "threat.enrichments.indicator.confidence"                            // Indicator confidence rating
	EnrichmentsIndicatorDescription                       fields.Field = "threat.enrichments.indicator.description"                           // Indicator description
	EnrichmentsIndicatorEmailAddress                      fields.Field = "threat.enrichments.indicator.email.address"                         // Indicator email address
	EnrichmentsIndicatorFileAccessed                      fields.Field = "threat.enrichments.indicator.file.accessed"                         // Last time the file was accessed.
	EnrichmentsIndicatorFileAttributes                    fields.Field = "threat.enrichments.indicator.file.attributes"                       // Array of file attributes.
	EnrichmentsIndicatorFileCodeSignatureDigestAlgorithm  fields.Field = "threat.enrichments.indicator.file.code_signature.digest_algorithm"  // Hashing algorithm used to sign the process.
	EnrichmentsIndicatorFileCodeSignatureExists           fields.Field = "threat.enrichments.indicator.file.code_signature.exists"            // Boolean to capture if a signature is present.
	EnrichmentsIndicatorFileCodeSignatureFlags            fields.Field = "threat.enrichments.indicator.file.code_signature.flags"             // Code signing flags of the process
	EnrichmentsIndicatorFileCodeSignatureSigningID        fields.Field = "threat.enrichments.indicator.file.code_signature.signing_id"        // The identifier used to sign the process.
	EnrichmentsIndicatorFileCodeSignatureStatus           fields.Field = "threat.enrichments.indicator.file.code_signature.status"            // Additional information about the certificate status.
	EnrichmentsIndicatorFileCodeSignatureSubjectName      fields.Field = "threat.enrichments.indicator.file.code_signature.subject_name"      // Subject name of the code signer
	EnrichmentsIndicatorFileCodeSignatureTeamID           fields.Field = "threat.enrichments.indicator.file.code_signature.team_id"           // The team identifier used to sign the process.
	EnrichmentsIndicatorFileCodeSignatureThumbprintSha256 fields.Field = "threat.enrichments.indicator.file.code_signature.thumbprint_sha256" // SHA256 hash of the certificate.
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
	EnrichmentsIndicatorFileElfSections                   fields.Field = "threat.enrichments.indicator.file.elf.sections"                     // Section information of the ELF file.
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
	EnrichmentsIndicatorFileElfSegments                   fields.Field = "threat.enrichments.indicator.file.elf.segments"                     // ELF object segment list.
	EnrichmentsIndicatorFileElfSegmentsSections           fields.Field = "threat.enrichments.indicator.file.elf.segments.sections"            // ELF object segment sections.
	EnrichmentsIndicatorFileElfSegmentsType               fields.Field = "threat.enrichments.indicator.file.elf.segments.type"                // ELF object segment type.
	EnrichmentsIndicatorFileElfSharedLibraries            fields.Field = "threat.enrichments.indicator.file.elf.shared_libraries"             // List of shared libraries used by this ELF object.
	EnrichmentsIndicatorFileElfTelfhash                   fields.Field = "threat.enrichments.indicator.file.elf.telfhash"                     // telfhash hash for ELF file.
	EnrichmentsIndicatorFileExtension                     fields.Field = "threat.enrichments.indicator.file.extension"                        // File extension, excluding the leading dot.
	EnrichmentsIndicatorFileForkName                      fields.Field = "threat.enrichments.indicator.file.fork_name"                        // A fork is additional data associated with a filesystem object.
	EnrichmentsIndicatorFileGid                           fields.Field = "threat.enrichments.indicator.file.gid"                              // Primary group ID (GID) of the file.
	EnrichmentsIndicatorFileGroup                         fields.Field = "threat.enrichments.indicator.file.group"                            // Primary group name of the file.
	EnrichmentsIndicatorFileHashCdhash                    fields.Field = "threat.enrichments.indicator.file.hash.cdhash"                      // The Code Directory (CD) hash of an executable.
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
	EnrichmentsIndicatorFileOriginReferrerUrl             fields.Field = "threat.enrichments.indicator.file.origin_referrer_url"              // The URL of the webpage that linked to the file.
	EnrichmentsIndicatorFileOriginUrl                     fields.Field = "threat.enrichments.indicator.file.origin_url"                       // The URL where the file is hosted.
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
	EnrichmentsIndicatorFilePeSections                    fields.Field = "threat.enrichments.indicator.file.pe.sections"                      // Section information of the PE file.
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
	IndicatorFileCodeSignatureFlags                       fields.Field = "threat.indicator.file.code_signature.flags"                         // Code signing flags of the process
	IndicatorFileCodeSignatureSigningID                   fields.Field = "threat.indicator.file.code_signature.signing_id"                    // The identifier used to sign the process.
	IndicatorFileCodeSignatureStatus                      fields.Field = "threat.indicator.file.code_signature.status"                        // Additional information about the certificate status.
	IndicatorFileCodeSignatureSubjectName                 fields.Field = "threat.indicator.file.code_signature.subject_name"                  // Subject name of the code signer
	IndicatorFileCodeSignatureTeamID                      fields.Field = "threat.indicator.file.code_signature.team_id"                       // The team identifier used to sign the process.
	IndicatorFileCodeSignatureThumbprintSha256            fields.Field = "threat.indicator.file.code_signature.thumbprint_sha256"             // SHA256 hash of the certificate.
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
	IndicatorFileElfSections                              fields.Field = "threat.indicator.file.elf.sections"                                 // Section information of the ELF file.
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
	IndicatorFileElfSegments                              fields.Field = "threat.indicator.file.elf.segments"                                 // ELF object segment list.
	IndicatorFileElfSegmentsSections                      fields.Field = "threat.indicator.file.elf.segments.sections"                        // ELF object segment sections.
	IndicatorFileElfSegmentsType                          fields.Field = "threat.indicator.file.elf.segments.type"                            // ELF object segment type.
	IndicatorFileElfSharedLibraries                       fields.Field = "threat.indicator.file.elf.shared_libraries"                         // List of shared libraries used by this ELF object.
	IndicatorFileElfTelfhash                              fields.Field = "threat.indicator.file.elf.telfhash"                                 // telfhash hash for ELF file.
	IndicatorFileExtension                                fields.Field = "threat.indicator.file.extension"                                    // File extension, excluding the leading dot.
	IndicatorFileForkName                                 fields.Field = "threat.indicator.file.fork_name"                                    // A fork is additional data associated with a filesystem object.
	IndicatorFileGid                                      fields.Field = "threat.indicator.file.gid"                                          // Primary group ID (GID) of the file.
	IndicatorFileGroup                                    fields.Field = "threat.indicator.file.group"                                        // Primary group name of the file.
	IndicatorFileHashCdhash                               fields.Field = "threat.indicator.file.hash.cdhash"                                  // The Code Directory (CD) hash of an executable.
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
	IndicatorFileOriginReferrerUrl                        fields.Field = "threat.indicator.file.origin_referrer_url"                          // The URL of the webpage that linked to the file.
	IndicatorFileOriginUrl                                fields.Field = "threat.indicator.file.origin_url"                                   // The URL where the file is hosted.
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
	IndicatorFilePeSections                               fields.Field = "threat.indicator.file.pe.sections"                                  // Section information of the PE file.
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
	IndicatorID                                           fields.Field = "threat.indicator.id"                                                // ID of the indicator
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
	Enrichments,
	EnrichmentsIndicator,
	EnrichmentsIndicatorAsNumber,
	EnrichmentsIndicatorAsOrganizationName,
	EnrichmentsIndicatorConfidence,
	EnrichmentsIndicatorDescription,
	EnrichmentsIndicatorEmailAddress,
	EnrichmentsIndicatorFileAccessed,
	EnrichmentsIndicatorFileAttributes,
	EnrichmentsIndicatorFileCodeSignatureDigestAlgorithm,
	EnrichmentsIndicatorFileCodeSignatureExists,
	EnrichmentsIndicatorFileCodeSignatureFlags,
	EnrichmentsIndicatorFileCodeSignatureSigningID,
	EnrichmentsIndicatorFileCodeSignatureStatus,
	EnrichmentsIndicatorFileCodeSignatureSubjectName,
	EnrichmentsIndicatorFileCodeSignatureTeamID,
	EnrichmentsIndicatorFileCodeSignatureThumbprintSha256,
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
	EnrichmentsIndicatorFileElfSections,
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
	EnrichmentsIndicatorFileElfSegments,
	EnrichmentsIndicatorFileElfSegmentsSections,
	EnrichmentsIndicatorFileElfSegmentsType,
	EnrichmentsIndicatorFileElfSharedLibraries,
	EnrichmentsIndicatorFileElfTelfhash,
	EnrichmentsIndicatorFileExtension,
	EnrichmentsIndicatorFileForkName,
	EnrichmentsIndicatorFileGid,
	EnrichmentsIndicatorFileGroup,
	EnrichmentsIndicatorFileHashCdhash,
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
	EnrichmentsIndicatorFileOriginReferrerUrl,
	EnrichmentsIndicatorFileOriginUrl,
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
	EnrichmentsIndicatorFilePeSections,
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
	IndicatorFileCodeSignatureFlags,
	IndicatorFileCodeSignatureSigningID,
	IndicatorFileCodeSignatureStatus,
	IndicatorFileCodeSignatureSubjectName,
	IndicatorFileCodeSignatureTeamID,
	IndicatorFileCodeSignatureThumbprintSha256,
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
	IndicatorFileElfSections,
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
	IndicatorFileElfSegments,
	IndicatorFileElfSegmentsSections,
	IndicatorFileElfSegmentsType,
	IndicatorFileElfSharedLibraries,
	IndicatorFileElfTelfhash,
	IndicatorFileExtension,
	IndicatorFileForkName,
	IndicatorFileGid,
	IndicatorFileGroup,
	IndicatorFileHashCdhash,
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
	IndicatorFileOriginReferrerUrl,
	IndicatorFileOriginUrl,
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
	IndicatorFilePeSections,
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
	IndicatorID,
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
	Enrichments                                           fields.Nested
	EnrichmentsIndicator                                  fields.Object
	EnrichmentsIndicatorAsNumber                          fields.Long
	EnrichmentsIndicatorAsOrganizationName                fields.Keyword
	EnrichmentsIndicatorConfidence                        fields.Keyword
	EnrichmentsIndicatorDescription                       fields.Keyword
	EnrichmentsIndicatorEmailAddress                      fields.Keyword
	EnrichmentsIndicatorFileAccessed                      fields.Date
	EnrichmentsIndicatorFileAttributes                    fields.Keyword
	EnrichmentsIndicatorFileCodeSignatureDigestAlgorithm  fields.Keyword
	EnrichmentsIndicatorFileCodeSignatureExists           fields.Boolean
	EnrichmentsIndicatorFileCodeSignatureFlags            fields.Keyword
	EnrichmentsIndicatorFileCodeSignatureSigningID        fields.Keyword
	EnrichmentsIndicatorFileCodeSignatureStatus           fields.Keyword
	EnrichmentsIndicatorFileCodeSignatureSubjectName      fields.Keyword
	EnrichmentsIndicatorFileCodeSignatureTeamID           fields.Keyword
	EnrichmentsIndicatorFileCodeSignatureThumbprintSha256 fields.Keyword
	EnrichmentsIndicatorFileCodeSignatureTimestamp        fields.Date
	EnrichmentsIndicatorFileCodeSignatureTrusted          fields.Boolean
	EnrichmentsIndicatorFileCodeSignatureValid            fields.Boolean
	EnrichmentsIndicatorFileCreated                       fields.Date
	EnrichmentsIndicatorFileCtime                         fields.Date
	EnrichmentsIndicatorFileDevice                        fields.Keyword
	EnrichmentsIndicatorFileDirectory                     fields.Keyword
	EnrichmentsIndicatorFileDriveLetter                   fields.Keyword
	EnrichmentsIndicatorFileElfArchitecture               fields.Keyword
	EnrichmentsIndicatorFileElfByteOrder                  fields.Keyword
	EnrichmentsIndicatorFileElfCpuType                    fields.Keyword
	EnrichmentsIndicatorFileElfCreationDate               fields.Date
	EnrichmentsIndicatorFileElfExports                    fields.Flattened
	EnrichmentsIndicatorFileElfGoImportHash               fields.Keyword
	EnrichmentsIndicatorFileElfGoImports                  fields.Flattened
	EnrichmentsIndicatorFileElfGoImportsNamesEntropy      fields.Long
	EnrichmentsIndicatorFileElfGoImportsNamesVarEntropy   fields.Long
	EnrichmentsIndicatorFileElfGoStripped                 fields.Boolean
	EnrichmentsIndicatorFileElfHeaderAbiVersion           fields.Keyword
	EnrichmentsIndicatorFileElfHeaderClass                fields.Keyword
	EnrichmentsIndicatorFileElfHeaderData                 fields.Keyword
	EnrichmentsIndicatorFileElfHeaderEntrypoint           fields.Long
	EnrichmentsIndicatorFileElfHeaderObjectVersion        fields.Keyword
	EnrichmentsIndicatorFileElfHeaderOsAbi                fields.Keyword
	EnrichmentsIndicatorFileElfHeaderType                 fields.Keyword
	EnrichmentsIndicatorFileElfHeaderVersion              fields.Keyword
	EnrichmentsIndicatorFileElfImportHash                 fields.Keyword
	EnrichmentsIndicatorFileElfImports                    fields.Flattened
	EnrichmentsIndicatorFileElfImportsNamesEntropy        fields.Long
	EnrichmentsIndicatorFileElfImportsNamesVarEntropy     fields.Long
	EnrichmentsIndicatorFileElfSections                   fields.Nested
	EnrichmentsIndicatorFileElfSectionsChi2               fields.Long
	EnrichmentsIndicatorFileElfSectionsEntropy            fields.Long
	EnrichmentsIndicatorFileElfSectionsFlags              fields.Keyword
	EnrichmentsIndicatorFileElfSectionsName               fields.Keyword
	EnrichmentsIndicatorFileElfSectionsPhysicalOffset     fields.Keyword
	EnrichmentsIndicatorFileElfSectionsPhysicalSize       fields.Long
	EnrichmentsIndicatorFileElfSectionsType               fields.Keyword
	EnrichmentsIndicatorFileElfSectionsVarEntropy         fields.Long
	EnrichmentsIndicatorFileElfSectionsVirtualAddress     fields.Long
	EnrichmentsIndicatorFileElfSectionsVirtualSize        fields.Long
	EnrichmentsIndicatorFileElfSegments                   fields.Nested
	EnrichmentsIndicatorFileElfSegmentsSections           fields.Keyword
	EnrichmentsIndicatorFileElfSegmentsType               fields.Keyword
	EnrichmentsIndicatorFileElfSharedLibraries            fields.Keyword
	EnrichmentsIndicatorFileElfTelfhash                   fields.Keyword
	EnrichmentsIndicatorFileExtension                     fields.Keyword
	EnrichmentsIndicatorFileForkName                      fields.Keyword
	EnrichmentsIndicatorFileGid                           fields.Keyword
	EnrichmentsIndicatorFileGroup                         fields.Keyword
	EnrichmentsIndicatorFileHashCdhash                    fields.Keyword
	EnrichmentsIndicatorFileHashMd5                       fields.Keyword
	EnrichmentsIndicatorFileHashSha1                      fields.Keyword
	EnrichmentsIndicatorFileHashSha256                    fields.Keyword
	EnrichmentsIndicatorFileHashSha384                    fields.Keyword
	EnrichmentsIndicatorFileHashSha512                    fields.Keyword
	EnrichmentsIndicatorFileHashSsdeep                    fields.Keyword
	EnrichmentsIndicatorFileHashTlsh                      fields.Keyword
	EnrichmentsIndicatorFileInode                         fields.Keyword
	EnrichmentsIndicatorFileMimeType                      fields.Keyword
	EnrichmentsIndicatorFileMode                          fields.Keyword
	EnrichmentsIndicatorFileMtime                         fields.Date
	EnrichmentsIndicatorFileName                          fields.Keyword
	EnrichmentsIndicatorFileOriginReferrerUrl             fields.Keyword
	EnrichmentsIndicatorFileOriginUrl                     fields.Keyword
	EnrichmentsIndicatorFileOwner                         fields.Keyword
	EnrichmentsIndicatorFilePath                          fields.Keyword
	EnrichmentsIndicatorFilePeArchitecture                fields.Keyword
	EnrichmentsIndicatorFilePeCompany                     fields.Keyword
	EnrichmentsIndicatorFilePeDescription                 fields.Keyword
	EnrichmentsIndicatorFilePeFileVersion                 fields.Keyword
	EnrichmentsIndicatorFilePeGoImportHash                fields.Keyword
	EnrichmentsIndicatorFilePeGoImports                   fields.Flattened
	EnrichmentsIndicatorFilePeGoImportsNamesEntropy       fields.Long
	EnrichmentsIndicatorFilePeGoImportsNamesVarEntropy    fields.Long
	EnrichmentsIndicatorFilePeGoStripped                  fields.Boolean
	EnrichmentsIndicatorFilePeImphash                     fields.Keyword
	EnrichmentsIndicatorFilePeImportHash                  fields.Keyword
	EnrichmentsIndicatorFilePeImports                     fields.Flattened
	EnrichmentsIndicatorFilePeImportsNamesEntropy         fields.Long
	EnrichmentsIndicatorFilePeImportsNamesVarEntropy      fields.Long
	EnrichmentsIndicatorFilePeOriginalFileName            fields.Keyword
	EnrichmentsIndicatorFilePePehash                      fields.Keyword
	EnrichmentsIndicatorFilePeProduct                     fields.Keyword
	EnrichmentsIndicatorFilePeSections                    fields.Nested
	EnrichmentsIndicatorFilePeSectionsEntropy             fields.Long
	EnrichmentsIndicatorFilePeSectionsName                fields.Keyword
	EnrichmentsIndicatorFilePeSectionsPhysicalSize        fields.Long
	EnrichmentsIndicatorFilePeSectionsVarEntropy          fields.Long
	EnrichmentsIndicatorFilePeSectionsVirtualSize         fields.Long
	EnrichmentsIndicatorFileSize                          fields.Long
	EnrichmentsIndicatorFileTargetPath                    fields.Keyword
	EnrichmentsIndicatorFileType                          fields.Keyword
	EnrichmentsIndicatorFileUid                           fields.Keyword
	EnrichmentsIndicatorFileX509AlternativeNames          fields.Keyword
	EnrichmentsIndicatorFileX509IssuerCommonName          fields.Keyword
	EnrichmentsIndicatorFileX509IssuerCountry             fields.Keyword
	EnrichmentsIndicatorFileX509IssuerDistinguishedName   fields.Keyword
	EnrichmentsIndicatorFileX509IssuerLocality            fields.Keyword
	EnrichmentsIndicatorFileX509IssuerOrganization        fields.Keyword
	EnrichmentsIndicatorFileX509IssuerOrganizationalUnit  fields.Keyword
	EnrichmentsIndicatorFileX509IssuerStateOrProvince     fields.Keyword
	EnrichmentsIndicatorFileX509NotAfter                  fields.Date
	EnrichmentsIndicatorFileX509NotBefore                 fields.Date
	EnrichmentsIndicatorFileX509PublicKeyAlgorithm        fields.Keyword
	EnrichmentsIndicatorFileX509PublicKeyCurve            fields.Keyword
	EnrichmentsIndicatorFileX509PublicKeyExponent         fields.Long
	EnrichmentsIndicatorFileX509PublicKeySize             fields.Long
	EnrichmentsIndicatorFileX509SerialNumber              fields.Keyword
	EnrichmentsIndicatorFileX509SignatureAlgorithm        fields.Keyword
	EnrichmentsIndicatorFileX509SubjectCommonName         fields.Keyword
	EnrichmentsIndicatorFileX509SubjectCountry            fields.Keyword
	EnrichmentsIndicatorFileX509SubjectDistinguishedName  fields.Keyword
	EnrichmentsIndicatorFileX509SubjectLocality           fields.Keyword
	EnrichmentsIndicatorFileX509SubjectOrganization       fields.Keyword
	EnrichmentsIndicatorFileX509SubjectOrganizationalUnit fields.Keyword
	EnrichmentsIndicatorFileX509SubjectStateOrProvince    fields.Keyword
	EnrichmentsIndicatorFileX509VersionNumber             fields.Keyword
	EnrichmentsIndicatorFirstSeen                         fields.Date
	EnrichmentsIndicatorGeoCityName                       fields.Keyword
	EnrichmentsIndicatorGeoContinentCode                  fields.Keyword
	EnrichmentsIndicatorGeoContinentName                  fields.Keyword
	EnrichmentsIndicatorGeoCountryIsoCode                 fields.Keyword
	EnrichmentsIndicatorGeoCountryName                    fields.Keyword
	EnrichmentsIndicatorGeoLocation                       fields.GeoPoint
	EnrichmentsIndicatorGeoName                           fields.Keyword
	EnrichmentsIndicatorGeoPostalCode                     fields.Keyword
	EnrichmentsIndicatorGeoRegionIsoCode                  fields.Keyword
	EnrichmentsIndicatorGeoRegionName                     fields.Keyword
	EnrichmentsIndicatorGeoTimezone                       fields.Keyword
	EnrichmentsIndicatorIp                                fields.IP
	EnrichmentsIndicatorLastSeen                          fields.Date
	EnrichmentsIndicatorMarkingTlp                        fields.Keyword
	EnrichmentsIndicatorMarkingTlpVersion                 fields.Keyword
	EnrichmentsIndicatorModifiedAt                        fields.Date
	EnrichmentsIndicatorName                              fields.Keyword
	EnrichmentsIndicatorPort                              fields.Long
	EnrichmentsIndicatorProvider                          fields.Keyword
	EnrichmentsIndicatorReference                         fields.Keyword
	EnrichmentsIndicatorRegistryDataBytes                 fields.Keyword
	EnrichmentsIndicatorRegistryDataStrings               fields.Wildcard
	EnrichmentsIndicatorRegistryDataType                  fields.Keyword
	EnrichmentsIndicatorRegistryHive                      fields.Keyword
	EnrichmentsIndicatorRegistryKey                       fields.Keyword
	EnrichmentsIndicatorRegistryPath                      fields.Keyword
	EnrichmentsIndicatorRegistryValue                     fields.Keyword
	EnrichmentsIndicatorScannerStats                      fields.Long
	EnrichmentsIndicatorSightings                         fields.Long
	EnrichmentsIndicatorType                              fields.Keyword
	EnrichmentsIndicatorUrlDomain                         fields.Keyword
	EnrichmentsIndicatorUrlExtension                      fields.Keyword
	EnrichmentsIndicatorUrlFragment                       fields.Keyword
	EnrichmentsIndicatorUrlFull                           fields.Wildcard
	EnrichmentsIndicatorUrlOriginal                       fields.Wildcard
	EnrichmentsIndicatorUrlPassword                       fields.Keyword
	EnrichmentsIndicatorUrlPath                           fields.Wildcard
	EnrichmentsIndicatorUrlPort                           fields.Long
	EnrichmentsIndicatorUrlQuery                          fields.Keyword
	EnrichmentsIndicatorUrlRegisteredDomain               fields.Keyword
	EnrichmentsIndicatorUrlScheme                         fields.Keyword
	EnrichmentsIndicatorUrlSubdomain                      fields.Keyword
	EnrichmentsIndicatorUrlTopLevelDomain                 fields.Keyword
	EnrichmentsIndicatorUrlUsername                       fields.Keyword
	EnrichmentsIndicatorX509AlternativeNames              fields.Keyword
	EnrichmentsIndicatorX509IssuerCommonName              fields.Keyword
	EnrichmentsIndicatorX509IssuerCountry                 fields.Keyword
	EnrichmentsIndicatorX509IssuerDistinguishedName       fields.Keyword
	EnrichmentsIndicatorX509IssuerLocality                fields.Keyword
	EnrichmentsIndicatorX509IssuerOrganization            fields.Keyword
	EnrichmentsIndicatorX509IssuerOrganizationalUnit      fields.Keyword
	EnrichmentsIndicatorX509IssuerStateOrProvince         fields.Keyword
	EnrichmentsIndicatorX509NotAfter                      fields.Date
	EnrichmentsIndicatorX509NotBefore                     fields.Date
	EnrichmentsIndicatorX509PublicKeyAlgorithm            fields.Keyword
	EnrichmentsIndicatorX509PublicKeyCurve                fields.Keyword
	EnrichmentsIndicatorX509PublicKeyExponent             fields.Long
	EnrichmentsIndicatorX509PublicKeySize                 fields.Long
	EnrichmentsIndicatorX509SerialNumber                  fields.Keyword
	EnrichmentsIndicatorX509SignatureAlgorithm            fields.Keyword
	EnrichmentsIndicatorX509SubjectCommonName             fields.Keyword
	EnrichmentsIndicatorX509SubjectCountry                fields.Keyword
	EnrichmentsIndicatorX509SubjectDistinguishedName      fields.Keyword
	EnrichmentsIndicatorX509SubjectLocality               fields.Keyword
	EnrichmentsIndicatorX509SubjectOrganization           fields.Keyword
	EnrichmentsIndicatorX509SubjectOrganizationalUnit     fields.Keyword
	EnrichmentsIndicatorX509SubjectStateOrProvince        fields.Keyword
	EnrichmentsIndicatorX509VersionNumber                 fields.Keyword
	EnrichmentsMatchedAtomic                              fields.Keyword
	EnrichmentsMatchedField                               fields.Keyword
	EnrichmentsMatchedID                                  fields.Keyword
	EnrichmentsMatchedIndex                               fields.Keyword
	EnrichmentsMatchedOccurred                            fields.Date
	EnrichmentsMatchedType                                fields.Keyword
	FeedDashboardID                                       fields.Keyword
	FeedDescription                                       fields.Keyword
	FeedName                                              fields.Keyword
	FeedReference                                         fields.Keyword
	Framework                                             fields.Keyword
	GroupAlias                                            fields.Keyword
	GroupID                                               fields.Keyword
	GroupName                                             fields.Keyword
	GroupReference                                        fields.Keyword
	IndicatorAsNumber                                     fields.Long
	IndicatorAsOrganizationName                           fields.Keyword
	IndicatorConfidence                                   fields.Keyword
	IndicatorDescription                                  fields.Keyword
	IndicatorEmailAddress                                 fields.Keyword
	IndicatorFileAccessed                                 fields.Date
	IndicatorFileAttributes                               fields.Keyword
	IndicatorFileCodeSignatureDigestAlgorithm             fields.Keyword
	IndicatorFileCodeSignatureExists                      fields.Boolean
	IndicatorFileCodeSignatureFlags                       fields.Keyword
	IndicatorFileCodeSignatureSigningID                   fields.Keyword
	IndicatorFileCodeSignatureStatus                      fields.Keyword
	IndicatorFileCodeSignatureSubjectName                 fields.Keyword
	IndicatorFileCodeSignatureTeamID                      fields.Keyword
	IndicatorFileCodeSignatureThumbprintSha256            fields.Keyword
	IndicatorFileCodeSignatureTimestamp                   fields.Date
	IndicatorFileCodeSignatureTrusted                     fields.Boolean
	IndicatorFileCodeSignatureValid                       fields.Boolean
	IndicatorFileCreated                                  fields.Date
	IndicatorFileCtime                                    fields.Date
	IndicatorFileDevice                                   fields.Keyword
	IndicatorFileDirectory                                fields.Keyword
	IndicatorFileDriveLetter                              fields.Keyword
	IndicatorFileElfArchitecture                          fields.Keyword
	IndicatorFileElfByteOrder                             fields.Keyword
	IndicatorFileElfCpuType                               fields.Keyword
	IndicatorFileElfCreationDate                          fields.Date
	IndicatorFileElfExports                               fields.Flattened
	IndicatorFileElfGoImportHash                          fields.Keyword
	IndicatorFileElfGoImports                             fields.Flattened
	IndicatorFileElfGoImportsNamesEntropy                 fields.Long
	IndicatorFileElfGoImportsNamesVarEntropy              fields.Long
	IndicatorFileElfGoStripped                            fields.Boolean
	IndicatorFileElfHeaderAbiVersion                      fields.Keyword
	IndicatorFileElfHeaderClass                           fields.Keyword
	IndicatorFileElfHeaderData                            fields.Keyword
	IndicatorFileElfHeaderEntrypoint                      fields.Long
	IndicatorFileElfHeaderObjectVersion                   fields.Keyword
	IndicatorFileElfHeaderOsAbi                           fields.Keyword
	IndicatorFileElfHeaderType                            fields.Keyword
	IndicatorFileElfHeaderVersion                         fields.Keyword
	IndicatorFileElfImportHash                            fields.Keyword
	IndicatorFileElfImports                               fields.Flattened
	IndicatorFileElfImportsNamesEntropy                   fields.Long
	IndicatorFileElfImportsNamesVarEntropy                fields.Long
	IndicatorFileElfSections                              fields.Nested
	IndicatorFileElfSectionsChi2                          fields.Long
	IndicatorFileElfSectionsEntropy                       fields.Long
	IndicatorFileElfSectionsFlags                         fields.Keyword
	IndicatorFileElfSectionsName                          fields.Keyword
	IndicatorFileElfSectionsPhysicalOffset                fields.Keyword
	IndicatorFileElfSectionsPhysicalSize                  fields.Long
	IndicatorFileElfSectionsType                          fields.Keyword
	IndicatorFileElfSectionsVarEntropy                    fields.Long
	IndicatorFileElfSectionsVirtualAddress                fields.Long
	IndicatorFileElfSectionsVirtualSize                   fields.Long
	IndicatorFileElfSegments                              fields.Nested
	IndicatorFileElfSegmentsSections                      fields.Keyword
	IndicatorFileElfSegmentsType                          fields.Keyword
	IndicatorFileElfSharedLibraries                       fields.Keyword
	IndicatorFileElfTelfhash                              fields.Keyword
	IndicatorFileExtension                                fields.Keyword
	IndicatorFileForkName                                 fields.Keyword
	IndicatorFileGid                                      fields.Keyword
	IndicatorFileGroup                                    fields.Keyword
	IndicatorFileHashCdhash                               fields.Keyword
	IndicatorFileHashMd5                                  fields.Keyword
	IndicatorFileHashSha1                                 fields.Keyword
	IndicatorFileHashSha256                               fields.Keyword
	IndicatorFileHashSha384                               fields.Keyword
	IndicatorFileHashSha512                               fields.Keyword
	IndicatorFileHashSsdeep                               fields.Keyword
	IndicatorFileHashTlsh                                 fields.Keyword
	IndicatorFileInode                                    fields.Keyword
	IndicatorFileMimeType                                 fields.Keyword
	IndicatorFileMode                                     fields.Keyword
	IndicatorFileMtime                                    fields.Date
	IndicatorFileName                                     fields.Keyword
	IndicatorFileOriginReferrerUrl                        fields.Keyword
	IndicatorFileOriginUrl                                fields.Keyword
	IndicatorFileOwner                                    fields.Keyword
	IndicatorFilePath                                     fields.Keyword
	IndicatorFilePeArchitecture                           fields.Keyword
	IndicatorFilePeCompany                                fields.Keyword
	IndicatorFilePeDescription                            fields.Keyword
	IndicatorFilePeFileVersion                            fields.Keyword
	IndicatorFilePeGoImportHash                           fields.Keyword
	IndicatorFilePeGoImports                              fields.Flattened
	IndicatorFilePeGoImportsNamesEntropy                  fields.Long
	IndicatorFilePeGoImportsNamesVarEntropy               fields.Long
	IndicatorFilePeGoStripped                             fields.Boolean
	IndicatorFilePeImphash                                fields.Keyword
	IndicatorFilePeImportHash                             fields.Keyword
	IndicatorFilePeImports                                fields.Flattened
	IndicatorFilePeImportsNamesEntropy                    fields.Long
	IndicatorFilePeImportsNamesVarEntropy                 fields.Long
	IndicatorFilePeOriginalFileName                       fields.Keyword
	IndicatorFilePePehash                                 fields.Keyword
	IndicatorFilePeProduct                                fields.Keyword
	IndicatorFilePeSections                               fields.Nested
	IndicatorFilePeSectionsEntropy                        fields.Long
	IndicatorFilePeSectionsName                           fields.Keyword
	IndicatorFilePeSectionsPhysicalSize                   fields.Long
	IndicatorFilePeSectionsVarEntropy                     fields.Long
	IndicatorFilePeSectionsVirtualSize                    fields.Long
	IndicatorFileSize                                     fields.Long
	IndicatorFileTargetPath                               fields.Keyword
	IndicatorFileType                                     fields.Keyword
	IndicatorFileUid                                      fields.Keyword
	IndicatorFileX509AlternativeNames                     fields.Keyword
	IndicatorFileX509IssuerCommonName                     fields.Keyword
	IndicatorFileX509IssuerCountry                        fields.Keyword
	IndicatorFileX509IssuerDistinguishedName              fields.Keyword
	IndicatorFileX509IssuerLocality                       fields.Keyword
	IndicatorFileX509IssuerOrganization                   fields.Keyword
	IndicatorFileX509IssuerOrganizationalUnit             fields.Keyword
	IndicatorFileX509IssuerStateOrProvince                fields.Keyword
	IndicatorFileX509NotAfter                             fields.Date
	IndicatorFileX509NotBefore                            fields.Date
	IndicatorFileX509PublicKeyAlgorithm                   fields.Keyword
	IndicatorFileX509PublicKeyCurve                       fields.Keyword
	IndicatorFileX509PublicKeyExponent                    fields.Long
	IndicatorFileX509PublicKeySize                        fields.Long
	IndicatorFileX509SerialNumber                         fields.Keyword
	IndicatorFileX509SignatureAlgorithm                   fields.Keyword
	IndicatorFileX509SubjectCommonName                    fields.Keyword
	IndicatorFileX509SubjectCountry                       fields.Keyword
	IndicatorFileX509SubjectDistinguishedName             fields.Keyword
	IndicatorFileX509SubjectLocality                      fields.Keyword
	IndicatorFileX509SubjectOrganization                  fields.Keyword
	IndicatorFileX509SubjectOrganizationalUnit            fields.Keyword
	IndicatorFileX509SubjectStateOrProvince               fields.Keyword
	IndicatorFileX509VersionNumber                        fields.Keyword
	IndicatorFirstSeen                                    fields.Date
	IndicatorGeoCityName                                  fields.Keyword
	IndicatorGeoContinentCode                             fields.Keyword
	IndicatorGeoContinentName                             fields.Keyword
	IndicatorGeoCountryIsoCode                            fields.Keyword
	IndicatorGeoCountryName                               fields.Keyword
	IndicatorGeoLocation                                  fields.GeoPoint
	IndicatorGeoName                                      fields.Keyword
	IndicatorGeoPostalCode                                fields.Keyword
	IndicatorGeoRegionIsoCode                             fields.Keyword
	IndicatorGeoRegionName                                fields.Keyword
	IndicatorGeoTimezone                                  fields.Keyword
	IndicatorID                                           fields.Keyword
	IndicatorIp                                           fields.IP
	IndicatorLastSeen                                     fields.Date
	IndicatorMarkingTlp                                   fields.Keyword
	IndicatorMarkingTlpVersion                            fields.Keyword
	IndicatorModifiedAt                                   fields.Date
	IndicatorName                                         fields.Keyword
	IndicatorPort                                         fields.Long
	IndicatorProvider                                     fields.Keyword
	IndicatorReference                                    fields.Keyword
	IndicatorRegistryDataBytes                            fields.Keyword
	IndicatorRegistryDataStrings                          fields.Wildcard
	IndicatorRegistryDataType                             fields.Keyword
	IndicatorRegistryHive                                 fields.Keyword
	IndicatorRegistryKey                                  fields.Keyword
	IndicatorRegistryPath                                 fields.Keyword
	IndicatorRegistryValue                                fields.Keyword
	IndicatorScannerStats                                 fields.Long
	IndicatorSightings                                    fields.Long
	IndicatorType                                         fields.Keyword
	IndicatorUrlDomain                                    fields.Keyword
	IndicatorUrlExtension                                 fields.Keyword
	IndicatorUrlFragment                                  fields.Keyword
	IndicatorUrlFull                                      fields.Wildcard
	IndicatorUrlOriginal                                  fields.Wildcard
	IndicatorUrlPassword                                  fields.Keyword
	IndicatorUrlPath                                      fields.Wildcard
	IndicatorUrlPort                                      fields.Long
	IndicatorUrlQuery                                     fields.Keyword
	IndicatorUrlRegisteredDomain                          fields.Keyword
	IndicatorUrlScheme                                    fields.Keyword
	IndicatorUrlSubdomain                                 fields.Keyword
	IndicatorUrlTopLevelDomain                            fields.Keyword
	IndicatorUrlUsername                                  fields.Keyword
	IndicatorX509AlternativeNames                         fields.Keyword
	IndicatorX509IssuerCommonName                         fields.Keyword
	IndicatorX509IssuerCountry                            fields.Keyword
	IndicatorX509IssuerDistinguishedName                  fields.Keyword
	IndicatorX509IssuerLocality                           fields.Keyword
	IndicatorX509IssuerOrganization                       fields.Keyword
	IndicatorX509IssuerOrganizationalUnit                 fields.Keyword
	IndicatorX509IssuerStateOrProvince                    fields.Keyword
	IndicatorX509NotAfter                                 fields.Date
	IndicatorX509NotBefore                                fields.Date
	IndicatorX509PublicKeyAlgorithm                       fields.Keyword
	IndicatorX509PublicKeyCurve                           fields.Keyword
	IndicatorX509PublicKeyExponent                        fields.Long
	IndicatorX509PublicKeySize                            fields.Long
	IndicatorX509SerialNumber                             fields.Keyword
	IndicatorX509SignatureAlgorithm                       fields.Keyword
	IndicatorX509SubjectCommonName                        fields.Keyword
	IndicatorX509SubjectCountry                           fields.Keyword
	IndicatorX509SubjectDistinguishedName                 fields.Keyword
	IndicatorX509SubjectLocality                          fields.Keyword
	IndicatorX509SubjectOrganization                      fields.Keyword
	IndicatorX509SubjectOrganizationalUnit                fields.Keyword
	IndicatorX509SubjectStateOrProvince                   fields.Keyword
	IndicatorX509VersionNumber                            fields.Keyword
	SoftwareAlias                                         fields.Keyword
	SoftwareID                                            fields.Keyword
	SoftwareName                                          fields.Keyword
	SoftwarePlatforms                                     fields.Keyword
	SoftwareReference                                     fields.Keyword
	SoftwareType                                          fields.Keyword
	TacticID                                              fields.Keyword
	TacticName                                            fields.Keyword
	TacticReference                                       fields.Keyword
	TechniqueID                                           fields.Keyword
	TechniqueName                                         fields.Keyword
	TechniqueReference                                    fields.Keyword
	TechniqueSubtechniqueID                               fields.Keyword
	TechniqueSubtechniqueName                             fields.Keyword
	TechniqueSubtechniqueReference                        fields.Keyword
}

var Types TypesType = TypesType{}
