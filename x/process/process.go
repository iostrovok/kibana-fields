package process

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Args                                     fields.Field = "process.args"                                           // Array of process arguments.
	ArgsCount                                fields.Field = "process.args_count"                                     // Length of the process.args array.
	CodeSignatureDigestAlgorithm             fields.Field = "process.code_signature.digest_algorithm"                // Hashing algorithm used to sign the process.
	CodeSignatureExists                      fields.Field = "process.code_signature.exists"                          // Boolean to capture if a signature is present.
	CodeSignatureFlags                       fields.Field = "process.code_signature.flags"                           // Code signing flags of the process
	CodeSignatureSigningID                   fields.Field = "process.code_signature.signing_id"                      // The identifier used to sign the process.
	CodeSignatureStatus                      fields.Field = "process.code_signature.status"                          // Additional information about the certificate status.
	CodeSignatureSubjectName                 fields.Field = "process.code_signature.subject_name"                    // Subject name of the code signer
	CodeSignatureTeamID                      fields.Field = "process.code_signature.team_id"                         // The team identifier used to sign the process.
	CodeSignatureThumbprintSha256            fields.Field = "process.code_signature.thumbprint_sha256"               // SHA256 hash of the certificate.
	CodeSignatureTimestamp                   fields.Field = "process.code_signature.timestamp"                       // When the signature was generated and signed.
	CodeSignatureTrusted                     fields.Field = "process.code_signature.trusted"                         // Stores the trust status of the certificate chain.
	CodeSignatureValid                       fields.Field = "process.code_signature.valid"                           // Boolean to capture if the digital signature is verified against the binary content.
	CommandLine                              fields.Field = "process.command_line"                                   // Full command line that started the process.
	ElfArchitecture                          fields.Field = "process.elf.architecture"                               // Machine architecture of the ELF file.
	ElfByteOrder                             fields.Field = "process.elf.byte_order"                                 // Byte sequence of ELF file.
	ElfCpuType                               fields.Field = "process.elf.cpu_type"                                   // CPU type of the ELF file.
	ElfCreationDate                          fields.Field = "process.elf.creation_date"                              // Build or compile date.
	ElfExports                               fields.Field = "process.elf.exports"                                    // List of exported element names and types.
	ElfGoImportHash                          fields.Field = "process.elf.go_import_hash"                             // A hash of the Go language imports in an ELF file.
	ElfGoImports                             fields.Field = "process.elf.go_imports"                                 // List of imported Go language element names and types.
	ElfGoImportsNamesEntropy                 fields.Field = "process.elf.go_imports_names_entropy"                   // Shannon entropy calculation from the list of Go imports.
	ElfGoImportsNamesVarEntropy              fields.Field = "process.elf.go_imports_names_var_entropy"               // Variance for Shannon entropy calculation from the list of Go imports.
	ElfGoStripped                            fields.Field = "process.elf.go_stripped"                                // Whether the file is a stripped or obfuscated Go executable.
	ElfHeaderAbiVersion                      fields.Field = "process.elf.header.abi_version"                         // Version of the ELF Application Binary Interface (ABI).
	ElfHeaderClass                           fields.Field = "process.elf.header.class"                               // Header class of the ELF file.
	ElfHeaderData                            fields.Field = "process.elf.header.data"                                // Data table of the ELF header.
	ElfHeaderEntrypoint                      fields.Field = "process.elf.header.entrypoint"                          // Header entrypoint of the ELF file.
	ElfHeaderObjectVersion                   fields.Field = "process.elf.header.object_version"                      // "0x1" for original ELF files.
	ElfHeaderOsAbi                           fields.Field = "process.elf.header.os_abi"                              // Application Binary Interface (ABI) of the Linux OS.
	ElfHeaderType                            fields.Field = "process.elf.header.type"                                // Header type of the ELF file.
	ElfHeaderVersion                         fields.Field = "process.elf.header.version"                             // Version of the ELF header.
	ElfImportHash                            fields.Field = "process.elf.import_hash"                                // A hash of the imports in an ELF file.
	ElfImports                               fields.Field = "process.elf.imports"                                    // List of imported element names and types.
	ElfImportsNamesEntropy                   fields.Field = "process.elf.imports_names_entropy"                      // Shannon entropy calculation from the list of imported element names and types.
	ElfImportsNamesVarEntropy                fields.Field = "process.elf.imports_names_var_entropy"                  // Variance for Shannon entropy calculation from the list of imported element names and types.
	ElfSections                              fields.Field = "process.elf.sections"                                   // Section information of the ELF file.
	ElfSectionsChi2                          fields.Field = "process.elf.sections.chi2"                              // Chi-square probability distribution of the section.
	ElfSectionsEntropy                       fields.Field = "process.elf.sections.entropy"                           // Shannon entropy calculation from the section.
	ElfSectionsFlags                         fields.Field = "process.elf.sections.flags"                             // ELF Section List flags.
	ElfSectionsName                          fields.Field = "process.elf.sections.name"                              // ELF Section List name.
	ElfSectionsPhysicalOffset                fields.Field = "process.elf.sections.physical_offset"                   // ELF Section List offset.
	ElfSectionsPhysicalSize                  fields.Field = "process.elf.sections.physical_size"                     // ELF Section List physical size.
	ElfSectionsType                          fields.Field = "process.elf.sections.type"                              // ELF Section List type.
	ElfSectionsVarEntropy                    fields.Field = "process.elf.sections.var_entropy"                       // Variance for Shannon entropy calculation from the section.
	ElfSectionsVirtualAddress                fields.Field = "process.elf.sections.virtual_address"                   // ELF Section List virtual address.
	ElfSectionsVirtualSize                   fields.Field = "process.elf.sections.virtual_size"                      // ELF Section List virtual size.
	ElfSegments                              fields.Field = "process.elf.segments"                                   // ELF object segment list.
	ElfSegmentsSections                      fields.Field = "process.elf.segments.sections"                          // ELF object segment sections.
	ElfSegmentsType                          fields.Field = "process.elf.segments.type"                              // ELF object segment type.
	ElfSharedLibraries                       fields.Field = "process.elf.shared_libraries"                           // List of shared libraries used by this ELF object.
	ElfTelfhash                              fields.Field = "process.elf.telfhash"                                   // telfhash hash for ELF file.
	End                                      fields.Field = "process.end"                                            // The time the process ended.
	EntityID                                 fields.Field = "process.entity_id"                                      // Unique identifier for the process.
	EntryLeaderArgs                          fields.Field = "process.entry_leader.args"                              // Array of process arguments.
	EntryLeaderArgsCount                     fields.Field = "process.entry_leader.args_count"                        // Length of the process.args array.
	EntryLeaderAttestedGroupsName            fields.Field = "process.entry_leader.attested_groups.name"              // Name of the group.
	EntryLeaderAttestedUserID                fields.Field = "process.entry_leader.attested_user.id"                  // Unique identifier of the user.
	EntryLeaderAttestedUserName              fields.Field = "process.entry_leader.attested_user.name"                // Short name or login of the user.
	EntryLeaderCommandLine                   fields.Field = "process.entry_leader.command_line"                      // Full command line that started the process.
	EntryLeaderEntityID                      fields.Field = "process.entry_leader.entity_id"                         // Unique identifier for the process.
	EntryLeaderEntryMetaSourceIp             fields.Field = "process.entry_leader.entry_meta.source.ip"              // IP address of the source.
	EntryLeaderEntryMetaType                 fields.Field = "process.entry_leader.entry_meta.type"                   // The entry type for the entry session leader.
	EntryLeaderExecutable                    fields.Field = "process.entry_leader.executable"                        // Absolute path to the process executable.
	EntryLeaderGroupID                       fields.Field = "process.entry_leader.group.id"                          // Unique identifier for the group on the system/platform.
	EntryLeaderGroupName                     fields.Field = "process.entry_leader.group.name"                        // Name of the group.
	EntryLeaderInteractive                   fields.Field = "process.entry_leader.interactive"                       // Whether the process is connected to an interactive shell.
	EntryLeaderName                          fields.Field = "process.entry_leader.name"                              // Process name.
	EntryLeaderParentEntityID                fields.Field = "process.entry_leader.parent.entity_id"                  // Unique identifier for the process.
	EntryLeaderParentPid                     fields.Field = "process.entry_leader.parent.pid"                        // Process id.
	EntryLeaderParentSessionLeaderEntityID   fields.Field = "process.entry_leader.parent.session_leader.entity_id"   // Unique identifier for the process.
	EntryLeaderParentSessionLeaderPid        fields.Field = "process.entry_leader.parent.session_leader.pid"         // Process id.
	EntryLeaderParentSessionLeaderStart      fields.Field = "process.entry_leader.parent.session_leader.start"       // The time the process started.
	EntryLeaderParentSessionLeaderVpid       fields.Field = "process.entry_leader.parent.session_leader.vpid"        // Virtual process id.
	EntryLeaderParentStart                   fields.Field = "process.entry_leader.parent.start"                      // The time the process started.
	EntryLeaderParentVpid                    fields.Field = "process.entry_leader.parent.vpid"                       // Virtual process id.
	EntryLeaderPid                           fields.Field = "process.entry_leader.pid"                               // Process id.
	EntryLeaderRealGroupID                   fields.Field = "process.entry_leader.real_group.id"                     // Unique identifier for the group on the system/platform.
	EntryLeaderRealGroupName                 fields.Field = "process.entry_leader.real_group.name"                   // Name of the group.
	EntryLeaderRealUserID                    fields.Field = "process.entry_leader.real_user.id"                      // Unique identifier of the user.
	EntryLeaderRealUserName                  fields.Field = "process.entry_leader.real_user.name"                    // Short name or login of the user.
	EntryLeaderSameAs                        fields.Field = "process.entry_leader.same_as_process"                   // This boolean is used to identify if a leader process is the same as the top level process.
	EntryLeaderSavedGroupID                  fields.Field = "process.entry_leader.saved_group.id"                    // Unique identifier for the group on the system/platform.
	EntryLeaderSavedGroupName                fields.Field = "process.entry_leader.saved_group.name"                  // Name of the group.
	EntryLeaderSavedUserID                   fields.Field = "process.entry_leader.saved_user.id"                     // Unique identifier of the user.
	EntryLeaderSavedUserName                 fields.Field = "process.entry_leader.saved_user.name"                   // Short name or login of the user.
	EntryLeaderStart                         fields.Field = "process.entry_leader.start"                             // The time the process started.
	EntryLeaderSupplementalGroupsID          fields.Field = "process.entry_leader.supplemental_groups.id"            // Unique identifier for the group on the system/platform.
	EntryLeaderSupplementalGroupsName        fields.Field = "process.entry_leader.supplemental_groups.name"          // Name of the group.
	EntryLeaderTty                           fields.Field = "process.entry_leader.tty"                               // Information about the controlling TTY device.
	EntryLeaderTtyCharDeviceMajor            fields.Field = "process.entry_leader.tty.char_device.major"             // The TTY character device's major number.
	EntryLeaderTtyCharDeviceMinor            fields.Field = "process.entry_leader.tty.char_device.minor"             // The TTY character device's minor number.
	EntryLeaderUserID                        fields.Field = "process.entry_leader.user.id"                           // Unique identifier of the user.
	EntryLeaderUserName                      fields.Field = "process.entry_leader.user.name"                         // Short name or login of the user.
	EntryLeaderVpid                          fields.Field = "process.entry_leader.vpid"                              // Virtual process id.
	EntryLeaderWorkingDirectory              fields.Field = "process.entry_leader.working_directory"                 // The working directory of the process.
	EnvVars                                  fields.Field = "process.env_vars"                                       // Array of environment variable bindings.
	Executable                               fields.Field = "process.executable"                                     // Absolute path to the process executable.
	ExitCode                                 fields.Field = "process.exit_code"                                      // The exit code of the process.
	GroupID                                  fields.Field = "process.group.id"                                       // Unique identifier for the group on the system/platform.
	GroupLeaderArgs                          fields.Field = "process.group_leader.args"                              // Array of process arguments.
	GroupLeaderArgsCount                     fields.Field = "process.group_leader.args_count"                        // Length of the process.args array.
	GroupLeaderCommandLine                   fields.Field = "process.group_leader.command_line"                      // Full command line that started the process.
	GroupLeaderEntityID                      fields.Field = "process.group_leader.entity_id"                         // Unique identifier for the process.
	GroupLeaderExecutable                    fields.Field = "process.group_leader.executable"                        // Absolute path to the process executable.
	GroupLeaderGroupID                       fields.Field = "process.group_leader.group.id"                          // Unique identifier for the group on the system/platform.
	GroupLeaderGroupName                     fields.Field = "process.group_leader.group.name"                        // Name of the group.
	GroupLeaderInteractive                   fields.Field = "process.group_leader.interactive"                       // Whether the process is connected to an interactive shell.
	GroupLeaderName                          fields.Field = "process.group_leader.name"                              // Process name.
	GroupLeaderPid                           fields.Field = "process.group_leader.pid"                               // Process id.
	GroupLeaderRealGroupID                   fields.Field = "process.group_leader.real_group.id"                     // Unique identifier for the group on the system/platform.
	GroupLeaderRealGroupName                 fields.Field = "process.group_leader.real_group.name"                   // Name of the group.
	GroupLeaderRealUserID                    fields.Field = "process.group_leader.real_user.id"                      // Unique identifier of the user.
	GroupLeaderRealUserName                  fields.Field = "process.group_leader.real_user.name"                    // Short name or login of the user.
	GroupLeaderSameAs                        fields.Field = "process.group_leader.same_as_process"                   // This boolean is used to identify if a leader process is the same as the top level process.
	GroupLeaderSavedGroupID                  fields.Field = "process.group_leader.saved_group.id"                    // Unique identifier for the group on the system/platform.
	GroupLeaderSavedGroupName                fields.Field = "process.group_leader.saved_group.name"                  // Name of the group.
	GroupLeaderSavedUserID                   fields.Field = "process.group_leader.saved_user.id"                     // Unique identifier of the user.
	GroupLeaderSavedUserName                 fields.Field = "process.group_leader.saved_user.name"                   // Short name or login of the user.
	GroupLeaderStart                         fields.Field = "process.group_leader.start"                             // The time the process started.
	GroupLeaderSupplementalGroupsID          fields.Field = "process.group_leader.supplemental_groups.id"            // Unique identifier for the group on the system/platform.
	GroupLeaderSupplementalGroupsName        fields.Field = "process.group_leader.supplemental_groups.name"          // Name of the group.
	GroupLeaderTty                           fields.Field = "process.group_leader.tty"                               // Information about the controlling TTY device.
	GroupLeaderTtyCharDeviceMajor            fields.Field = "process.group_leader.tty.char_device.major"             // The TTY character device's major number.
	GroupLeaderTtyCharDeviceMinor            fields.Field = "process.group_leader.tty.char_device.minor"             // The TTY character device's minor number.
	GroupLeaderUserID                        fields.Field = "process.group_leader.user.id"                           // Unique identifier of the user.
	GroupLeaderUserName                      fields.Field = "process.group_leader.user.name"                         // Short name or login of the user.
	GroupLeaderVpid                          fields.Field = "process.group_leader.vpid"                              // Virtual process id.
	GroupLeaderWorkingDirectory              fields.Field = "process.group_leader.working_directory"                 // The working directory of the process.
	GroupName                                fields.Field = "process.group.name"                                     // Name of the group.
	HashCdhash                               fields.Field = "process.hash.cdhash"                                    // The Code Directory (CD) hash of an executable.
	HashMd5                                  fields.Field = "process.hash.md5"                                       // MD5 hash.
	HashSha1                                 fields.Field = "process.hash.sha1"                                      // SHA1 hash.
	HashSha256                               fields.Field = "process.hash.sha256"                                    // SHA256 hash.
	HashSha384                               fields.Field = "process.hash.sha384"                                    // SHA384 hash.
	HashSha512                               fields.Field = "process.hash.sha512"                                    // SHA512 hash.
	HashSsdeep                               fields.Field = "process.hash.ssdeep"                                    // SSDEEP hash.
	HashTlsh                                 fields.Field = "process.hash.tlsh"                                      // TLSH hash.
	Interactive                              fields.Field = "process.interactive"                                    // Whether the process is connected to an interactive shell.
	Io                                       fields.Field = "process.io"                                             // A chunk of input or output (IO) from a single process.
	IoBytesSkipped                           fields.Field = "process.io.bytes_skipped"                               // An array of byte offsets and lengths denoting where IO data has been skipped.
	IoBytesSkippedLength                     fields.Field = "process.io.bytes_skipped.length"                        // The length of bytes skipped.
	IoBytesSkippedOffset                     fields.Field = "process.io.bytes_skipped.offset"                        // The byte offset into this event's io.text (or io.bytes in the future) where length bytes were skipped.
	IoMaxBytesPerExceeded                    fields.Field = "process.io.max_bytes_per_process_exceeded"              // If true, the process producing the output has exceeded the max_kilobytes_per_process configuration setting.
	IoText                                   fields.Field = "process.io.text"                                        // A chunk of output or input sanitized to UTF-8.
	IoTotalBytesCaptured                     fields.Field = "process.io.total_bytes_captured"                        // The total number of bytes captured in this event.
	IoTotalBytesSkipped                      fields.Field = "process.io.total_bytes_skipped"                         // The total number of bytes that were not captured due to implementation restrictions such as buffer size limits.
	IoType                                   fields.Field = "process.io.type"                                        // The type of object on which the IO action (read or write) was taken.
	MachoGoImportHash                        fields.Field = "process.macho.go_import_hash"                           // A hash of the Go language imports in a Mach-O file.
	MachoGoImports                           fields.Field = "process.macho.go_imports"                               // List of imported Go language element names and types.
	MachoGoImportsNamesEntropy               fields.Field = "process.macho.go_imports_names_entropy"                 // Shannon entropy calculation from the list of Go imports.
	MachoGoImportsNamesVarEntropy            fields.Field = "process.macho.go_imports_names_var_entropy"             // Variance for Shannon entropy calculation from the list of Go imports.
	MachoGoStripped                          fields.Field = "process.macho.go_stripped"                              // Whether the file is a stripped or obfuscated Go executable.
	MachoImportHash                          fields.Field = "process.macho.import_hash"                              // A hash of the imports in a Mach-O file.
	MachoImports                             fields.Field = "process.macho.imports"                                  // List of imported element names and types.
	MachoImportsNamesEntropy                 fields.Field = "process.macho.imports_names_entropy"                    // Shannon entropy calculation from the list of imported element names and types.
	MachoImportsNamesVarEntropy              fields.Field = "process.macho.imports_names_var_entropy"                // Variance for Shannon entropy calculation from the list of imported element names and types.
	MachoSections                            fields.Field = "process.macho.sections"                                 // Section information of the Mach-O file.
	MachoSectionsEntropy                     fields.Field = "process.macho.sections.entropy"                         // Shannon entropy calculation from the section.
	MachoSectionsName                        fields.Field = "process.macho.sections.name"                            // Mach-O Section List name.
	MachoSectionsPhysicalSize                fields.Field = "process.macho.sections.physical_size"                   // Mach-O Section List physical size.
	MachoSectionsVarEntropy                  fields.Field = "process.macho.sections.var_entropy"                     // Variance for Shannon entropy calculation from the section.
	MachoSectionsVirtualSize                 fields.Field = "process.macho.sections.virtual_size"                    // Mach-O Section List virtual size. This is always the same as `physical_size`.
	MachoSymhash                             fields.Field = "process.macho.symhash"                                  // A hash of the imports in a Mach-O file.
	Name                                     fields.Field = "process.name"                                           // Process name.
	ParentArgs                               fields.Field = "process.parent.args"                                    // Array of process arguments.
	ParentArgsCount                          fields.Field = "process.parent.args_count"                              // Length of the process.args array.
	ParentCodeSignatureDigestAlgorithm       fields.Field = "process.parent.code_signature.digest_algorithm"         // Hashing algorithm used to sign the process.
	ParentCodeSignatureExists                fields.Field = "process.parent.code_signature.exists"                   // Boolean to capture if a signature is present.
	ParentCodeSignatureFlags                 fields.Field = "process.parent.code_signature.flags"                    // Code signing flags of the process
	ParentCodeSignatureSigningID             fields.Field = "process.parent.code_signature.signing_id"               // The identifier used to sign the process.
	ParentCodeSignatureStatus                fields.Field = "process.parent.code_signature.status"                   // Additional information about the certificate status.
	ParentCodeSignatureSubjectName           fields.Field = "process.parent.code_signature.subject_name"             // Subject name of the code signer
	ParentCodeSignatureTeamID                fields.Field = "process.parent.code_signature.team_id"                  // The team identifier used to sign the process.
	ParentCodeSignatureThumbprintSha256      fields.Field = "process.parent.code_signature.thumbprint_sha256"        // SHA256 hash of the certificate.
	ParentCodeSignatureTimestamp             fields.Field = "process.parent.code_signature.timestamp"                // When the signature was generated and signed.
	ParentCodeSignatureTrusted               fields.Field = "process.parent.code_signature.trusted"                  // Stores the trust status of the certificate chain.
	ParentCodeSignatureValid                 fields.Field = "process.parent.code_signature.valid"                    // Boolean to capture if the digital signature is verified against the binary content.
	ParentCommandLine                        fields.Field = "process.parent.command_line"                            // Full command line that started the process.
	ParentElfArchitecture                    fields.Field = "process.parent.elf.architecture"                        // Machine architecture of the ELF file.
	ParentElfByteOrder                       fields.Field = "process.parent.elf.byte_order"                          // Byte sequence of ELF file.
	ParentElfCpuType                         fields.Field = "process.parent.elf.cpu_type"                            // CPU type of the ELF file.
	ParentElfCreationDate                    fields.Field = "process.parent.elf.creation_date"                       // Build or compile date.
	ParentElfExports                         fields.Field = "process.parent.elf.exports"                             // List of exported element names and types.
	ParentElfGoImportHash                    fields.Field = "process.parent.elf.go_import_hash"                      // A hash of the Go language imports in an ELF file.
	ParentElfGoImports                       fields.Field = "process.parent.elf.go_imports"                          // List of imported Go language element names and types.
	ParentElfGoImportsNamesEntropy           fields.Field = "process.parent.elf.go_imports_names_entropy"            // Shannon entropy calculation from the list of Go imports.
	ParentElfGoImportsNamesVarEntropy        fields.Field = "process.parent.elf.go_imports_names_var_entropy"        // Variance for Shannon entropy calculation from the list of Go imports.
	ParentElfGoStripped                      fields.Field = "process.parent.elf.go_stripped"                         // Whether the file is a stripped or obfuscated Go executable.
	ParentElfHeaderAbiVersion                fields.Field = "process.parent.elf.header.abi_version"                  // Version of the ELF Application Binary Interface (ABI).
	ParentElfHeaderClass                     fields.Field = "process.parent.elf.header.class"                        // Header class of the ELF file.
	ParentElfHeaderData                      fields.Field = "process.parent.elf.header.data"                         // Data table of the ELF header.
	ParentElfHeaderEntrypoint                fields.Field = "process.parent.elf.header.entrypoint"                   // Header entrypoint of the ELF file.
	ParentElfHeaderObjectVersion             fields.Field = "process.parent.elf.header.object_version"               // "0x1" for original ELF files.
	ParentElfHeaderOsAbi                     fields.Field = "process.parent.elf.header.os_abi"                       // Application Binary Interface (ABI) of the Linux OS.
	ParentElfHeaderType                      fields.Field = "process.parent.elf.header.type"                         // Header type of the ELF file.
	ParentElfHeaderVersion                   fields.Field = "process.parent.elf.header.version"                      // Version of the ELF header.
	ParentElfImportHash                      fields.Field = "process.parent.elf.import_hash"                         // A hash of the imports in an ELF file.
	ParentElfImports                         fields.Field = "process.parent.elf.imports"                             // List of imported element names and types.
	ParentElfImportsNamesEntropy             fields.Field = "process.parent.elf.imports_names_entropy"               // Shannon entropy calculation from the list of imported element names and types.
	ParentElfImportsNamesVarEntropy          fields.Field = "process.parent.elf.imports_names_var_entropy"           // Variance for Shannon entropy calculation from the list of imported element names and types.
	ParentElfSections                        fields.Field = "process.parent.elf.sections"                            // Section information of the ELF file.
	ParentElfSectionsChi2                    fields.Field = "process.parent.elf.sections.chi2"                       // Chi-square probability distribution of the section.
	ParentElfSectionsEntropy                 fields.Field = "process.parent.elf.sections.entropy"                    // Shannon entropy calculation from the section.
	ParentElfSectionsFlags                   fields.Field = "process.parent.elf.sections.flags"                      // ELF Section List flags.
	ParentElfSectionsName                    fields.Field = "process.parent.elf.sections.name"                       // ELF Section List name.
	ParentElfSectionsPhysicalOffset          fields.Field = "process.parent.elf.sections.physical_offset"            // ELF Section List offset.
	ParentElfSectionsPhysicalSize            fields.Field = "process.parent.elf.sections.physical_size"              // ELF Section List physical size.
	ParentElfSectionsType                    fields.Field = "process.parent.elf.sections.type"                       // ELF Section List type.
	ParentElfSectionsVarEntropy              fields.Field = "process.parent.elf.sections.var_entropy"                // Variance for Shannon entropy calculation from the section.
	ParentElfSectionsVirtualAddress          fields.Field = "process.parent.elf.sections.virtual_address"            // ELF Section List virtual address.
	ParentElfSectionsVirtualSize             fields.Field = "process.parent.elf.sections.virtual_size"               // ELF Section List virtual size.
	ParentElfSegments                        fields.Field = "process.parent.elf.segments"                            // ELF object segment list.
	ParentElfSegmentsSections                fields.Field = "process.parent.elf.segments.sections"                   // ELF object segment sections.
	ParentElfSegmentsType                    fields.Field = "process.parent.elf.segments.type"                       // ELF object segment type.
	ParentElfSharedLibraries                 fields.Field = "process.parent.elf.shared_libraries"                    // List of shared libraries used by this ELF object.
	ParentElfTelfhash                        fields.Field = "process.parent.elf.telfhash"                            // telfhash hash for ELF file.
	ParentEnd                                fields.Field = "process.parent.end"                                     // The time the process ended.
	ParentEntityID                           fields.Field = "process.parent.entity_id"                               // Unique identifier for the process.
	ParentExecutable                         fields.Field = "process.parent.executable"                              // Absolute path to the process executable.
	ParentExitCode                           fields.Field = "process.parent.exit_code"                               // The exit code of the process.
	ParentGroupID                            fields.Field = "process.parent.group.id"                                // Unique identifier for the group on the system/platform.
	ParentGroupLeaderEntityID                fields.Field = "process.parent.group_leader.entity_id"                  // Unique identifier for the process.
	ParentGroupLeaderPid                     fields.Field = "process.parent.group_leader.pid"                        // Process id.
	ParentGroupLeaderStart                   fields.Field = "process.parent.group_leader.start"                      // The time the process started.
	ParentGroupLeaderVpid                    fields.Field = "process.parent.group_leader.vpid"                       // Virtual process id.
	ParentGroupName                          fields.Field = "process.parent.group.name"                              // Name of the group.
	ParentHashCdhash                         fields.Field = "process.parent.hash.cdhash"                             // The Code Directory (CD) hash of an executable.
	ParentHashMd5                            fields.Field = "process.parent.hash.md5"                                // MD5 hash.
	ParentHashSha1                           fields.Field = "process.parent.hash.sha1"                               // SHA1 hash.
	ParentHashSha256                         fields.Field = "process.parent.hash.sha256"                             // SHA256 hash.
	ParentHashSha384                         fields.Field = "process.parent.hash.sha384"                             // SHA384 hash.
	ParentHashSha512                         fields.Field = "process.parent.hash.sha512"                             // SHA512 hash.
	ParentHashSsdeep                         fields.Field = "process.parent.hash.ssdeep"                             // SSDEEP hash.
	ParentHashTlsh                           fields.Field = "process.parent.hash.tlsh"                               // TLSH hash.
	ParentInteractive                        fields.Field = "process.parent.interactive"                             // Whether the process is connected to an interactive shell.
	ParentMachoGoImportHash                  fields.Field = "process.parent.macho.go_import_hash"                    // A hash of the Go language imports in a Mach-O file.
	ParentMachoGoImports                     fields.Field = "process.parent.macho.go_imports"                        // List of imported Go language element names and types.
	ParentMachoGoImportsNamesEntropy         fields.Field = "process.parent.macho.go_imports_names_entropy"          // Shannon entropy calculation from the list of Go imports.
	ParentMachoGoImportsNamesVarEntropy      fields.Field = "process.parent.macho.go_imports_names_var_entropy"      // Variance for Shannon entropy calculation from the list of Go imports.
	ParentMachoGoStripped                    fields.Field = "process.parent.macho.go_stripped"                       // Whether the file is a stripped or obfuscated Go executable.
	ParentMachoImportHash                    fields.Field = "process.parent.macho.import_hash"                       // A hash of the imports in a Mach-O file.
	ParentMachoImports                       fields.Field = "process.parent.macho.imports"                           // List of imported element names and types.
	ParentMachoImportsNamesEntropy           fields.Field = "process.parent.macho.imports_names_entropy"             // Shannon entropy calculation from the list of imported element names and types.
	ParentMachoImportsNamesVarEntropy        fields.Field = "process.parent.macho.imports_names_var_entropy"         // Variance for Shannon entropy calculation from the list of imported element names and types.
	ParentMachoSections                      fields.Field = "process.parent.macho.sections"                          // Section information of the Mach-O file.
	ParentMachoSectionsEntropy               fields.Field = "process.parent.macho.sections.entropy"                  // Shannon entropy calculation from the section.
	ParentMachoSectionsName                  fields.Field = "process.parent.macho.sections.name"                     // Mach-O Section List name.
	ParentMachoSectionsPhysicalSize          fields.Field = "process.parent.macho.sections.physical_size"            // Mach-O Section List physical size.
	ParentMachoSectionsVarEntropy            fields.Field = "process.parent.macho.sections.var_entropy"              // Variance for Shannon entropy calculation from the section.
	ParentMachoSectionsVirtualSize           fields.Field = "process.parent.macho.sections.virtual_size"             // Mach-O Section List virtual size. This is always the same as `physical_size`.
	ParentMachoSymhash                       fields.Field = "process.parent.macho.symhash"                           // A hash of the imports in a Mach-O file.
	ParentName                               fields.Field = "process.parent.name"                                    // Process name.
	ParentPeArchitecture                     fields.Field = "process.parent.pe.architecture"                         // CPU architecture target for the file.
	ParentPeCompany                          fields.Field = "process.parent.pe.company"                              // Internal company name of the file, provided at compile-time.
	ParentPeDescription                      fields.Field = "process.parent.pe.description"                          // Internal description of the file, provided at compile-time.
	ParentPeFileVersion                      fields.Field = "process.parent.pe.file_version"                         // Process name.
	ParentPeGoImportHash                     fields.Field = "process.parent.pe.go_import_hash"                       // A hash of the Go language imports in a PE file.
	ParentPeGoImports                        fields.Field = "process.parent.pe.go_imports"                           // List of imported Go language element names and types.
	ParentPeGoImportsNamesEntropy            fields.Field = "process.parent.pe.go_imports_names_entropy"             // Shannon entropy calculation from the list of Go imports.
	ParentPeGoImportsNamesVarEntropy         fields.Field = "process.parent.pe.go_imports_names_var_entropy"         // Variance for Shannon entropy calculation from the list of Go imports.
	ParentPeGoStripped                       fields.Field = "process.parent.pe.go_stripped"                          // Whether the file is a stripped or obfuscated Go executable.
	ParentPeImphash                          fields.Field = "process.parent.pe.imphash"                              // A hash of the imports in a PE file.
	ParentPeImportHash                       fields.Field = "process.parent.pe.import_hash"                          // A hash of the imports in a PE file.
	ParentPeImports                          fields.Field = "process.parent.pe.imports"                              // List of imported element names and types.
	ParentPeImportsNamesEntropy              fields.Field = "process.parent.pe.imports_names_entropy"                // Shannon entropy calculation from the list of imported element names and types.
	ParentPeImportsNamesVarEntropy           fields.Field = "process.parent.pe.imports_names_var_entropy"            // Variance for Shannon entropy calculation from the list of imported element names and types.
	ParentPeOriginalFileName                 fields.Field = "process.parent.pe.original_file_name"                   // Internal name of the file, provided at compile-time.
	ParentPePehash                           fields.Field = "process.parent.pe.pehash"                               // A hash of the PE header and data from one or more PE sections.
	ParentPeProduct                          fields.Field = "process.parent.pe.product"                              // Internal product name of the file, provided at compile-time.
	ParentPeSections                         fields.Field = "process.parent.pe.sections"                             // Section information of the PE file.
	ParentPeSectionsEntropy                  fields.Field = "process.parent.pe.sections.entropy"                     // Shannon entropy calculation from the section.
	ParentPeSectionsName                     fields.Field = "process.parent.pe.sections.name"                        // PE Section List name.
	ParentPeSectionsPhysicalSize             fields.Field = "process.parent.pe.sections.physical_size"               // PE Section List physical size.
	ParentPeSectionsVarEntropy               fields.Field = "process.parent.pe.sections.var_entropy"                 // Variance for Shannon entropy calculation from the section.
	ParentPeSectionsVirtualSize              fields.Field = "process.parent.pe.sections.virtual_size"                // PE Section List virtual size. This is always the same as `physical_size`.
	ParentPid                                fields.Field = "process.parent.pid"                                     // Process id.
	ParentRealGroupID                        fields.Field = "process.parent.real_group.id"                           // Unique identifier for the group on the system/platform.
	ParentRealGroupName                      fields.Field = "process.parent.real_group.name"                         // Name of the group.
	ParentRealUserID                         fields.Field = "process.parent.real_user.id"                            // Unique identifier of the user.
	ParentRealUserName                       fields.Field = "process.parent.real_user.name"                          // Short name or login of the user.
	ParentSavedGroupID                       fields.Field = "process.parent.saved_group.id"                          // Unique identifier for the group on the system/platform.
	ParentSavedGroupName                     fields.Field = "process.parent.saved_group.name"                        // Name of the group.
	ParentSavedUserID                        fields.Field = "process.parent.saved_user.id"                           // Unique identifier of the user.
	ParentSavedUserName                      fields.Field = "process.parent.saved_user.name"                         // Short name or login of the user.
	ParentStart                              fields.Field = "process.parent.start"                                   // The time the process started.
	ParentSupplementalGroupsID               fields.Field = "process.parent.supplemental_groups.id"                  // Unique identifier for the group on the system/platform.
	ParentSupplementalGroupsName             fields.Field = "process.parent.supplemental_groups.name"                // Name of the group.
	ParentThreadCapabilitiesEffective        fields.Field = "process.parent.thread.capabilities.effective"           // Array of capabilities used for permission checks.
	ParentThreadCapabilitiesPermitted        fields.Field = "process.parent.thread.capabilities.permitted"           // Array of capabilities a thread could assume.
	ParentThreadID                           fields.Field = "process.parent.thread.id"                               // Thread ID.
	ParentThreadName                         fields.Field = "process.parent.thread.name"                             // Thread name.
	ParentTitle                              fields.Field = "process.parent.title"                                   // Process title.
	ParentTty                                fields.Field = "process.parent.tty"                                     // Information about the controlling TTY device.
	ParentTtyCharDeviceMajor                 fields.Field = "process.parent.tty.char_device.major"                   // The TTY character device's major number.
	ParentTtyCharDeviceMinor                 fields.Field = "process.parent.tty.char_device.minor"                   // The TTY character device's minor number.
	ParentUptime                             fields.Field = "process.parent.uptime"                                  // Seconds the process has been up.
	ParentUserID                             fields.Field = "process.parent.user.id"                                 // Unique identifier of the user.
	ParentUserName                           fields.Field = "process.parent.user.name"                               // Short name or login of the user.
	ParentVpid                               fields.Field = "process.parent.vpid"                                    // Virtual process id.
	ParentWorkingDirectory                   fields.Field = "process.parent.working_directory"                       // The working directory of the process.
	PeArchitecture                           fields.Field = "process.pe.architecture"                                // CPU architecture target for the file.
	PeCompany                                fields.Field = "process.pe.company"                                     // Internal company name of the file, provided at compile-time.
	PeDescription                            fields.Field = "process.pe.description"                                 // Internal description of the file, provided at compile-time.
	PeFileVersion                            fields.Field = "process.pe.file_version"                                // Process name.
	PeGoImportHash                           fields.Field = "process.pe.go_import_hash"                              // A hash of the Go language imports in a PE file.
	PeGoImports                              fields.Field = "process.pe.go_imports"                                  // List of imported Go language element names and types.
	PeGoImportsNamesEntropy                  fields.Field = "process.pe.go_imports_names_entropy"                    // Shannon entropy calculation from the list of Go imports.
	PeGoImportsNamesVarEntropy               fields.Field = "process.pe.go_imports_names_var_entropy"                // Variance for Shannon entropy calculation from the list of Go imports.
	PeGoStripped                             fields.Field = "process.pe.go_stripped"                                 // Whether the file is a stripped or obfuscated Go executable.
	PeImphash                                fields.Field = "process.pe.imphash"                                     // A hash of the imports in a PE file.
	PeImportHash                             fields.Field = "process.pe.import_hash"                                 // A hash of the imports in a PE file.
	PeImports                                fields.Field = "process.pe.imports"                                     // List of imported element names and types.
	PeImportsNamesEntropy                    fields.Field = "process.pe.imports_names_entropy"                       // Shannon entropy calculation from the list of imported element names and types.
	PeImportsNamesVarEntropy                 fields.Field = "process.pe.imports_names_var_entropy"                   // Variance for Shannon entropy calculation from the list of imported element names and types.
	PeOriginalFileName                       fields.Field = "process.pe.original_file_name"                          // Internal name of the file, provided at compile-time.
	PePehash                                 fields.Field = "process.pe.pehash"                                      // A hash of the PE header and data from one or more PE sections.
	PeProduct                                fields.Field = "process.pe.product"                                     // Internal product name of the file, provided at compile-time.
	PeSections                               fields.Field = "process.pe.sections"                                    // Section information of the PE file.
	PeSectionsEntropy                        fields.Field = "process.pe.sections.entropy"                            // Shannon entropy calculation from the section.
	PeSectionsName                           fields.Field = "process.pe.sections.name"                               // PE Section List name.
	PeSectionsPhysicalSize                   fields.Field = "process.pe.sections.physical_size"                      // PE Section List physical size.
	PeSectionsVarEntropy                     fields.Field = "process.pe.sections.var_entropy"                        // Variance for Shannon entropy calculation from the section.
	PeSectionsVirtualSize                    fields.Field = "process.pe.sections.virtual_size"                       // PE Section List virtual size. This is always the same as `physical_size`.
	Pid                                      fields.Field = "process.pid"                                            // Process id.
	PreviousArgs                             fields.Field = "process.previous.args"                                  // Array of process arguments.
	PreviousArgsCount                        fields.Field = "process.previous.args_count"                            // Length of the process.args array.
	PreviousExecutable                       fields.Field = "process.previous.executable"                            // Absolute path to the process executable.
	RealGroupID                              fields.Field = "process.real_group.id"                                  // Unique identifier for the group on the system/platform.
	RealGroupName                            fields.Field = "process.real_group.name"                                // Name of the group.
	RealUserID                               fields.Field = "process.real_user.id"                                   // Unique identifier of the user.
	RealUserName                             fields.Field = "process.real_user.name"                                 // Short name or login of the user.
	SavedGroupID                             fields.Field = "process.saved_group.id"                                 // Unique identifier for the group on the system/platform.
	SavedGroupName                           fields.Field = "process.saved_group.name"                               // Name of the group.
	SavedUserID                              fields.Field = "process.saved_user.id"                                  // Unique identifier of the user.
	SavedUserName                            fields.Field = "process.saved_user.name"                                // Short name or login of the user.
	SessionLeaderArgs                        fields.Field = "process.session_leader.args"                            // Array of process arguments.
	SessionLeaderArgsCount                   fields.Field = "process.session_leader.args_count"                      // Length of the process.args array.
	SessionLeaderCommandLine                 fields.Field = "process.session_leader.command_line"                    // Full command line that started the process.
	SessionLeaderEntityID                    fields.Field = "process.session_leader.entity_id"                       // Unique identifier for the process.
	SessionLeaderExecutable                  fields.Field = "process.session_leader.executable"                      // Absolute path to the process executable.
	SessionLeaderGroupID                     fields.Field = "process.session_leader.group.id"                        // Unique identifier for the group on the system/platform.
	SessionLeaderGroupName                   fields.Field = "process.session_leader.group.name"                      // Name of the group.
	SessionLeaderInteractive                 fields.Field = "process.session_leader.interactive"                     // Whether the process is connected to an interactive shell.
	SessionLeaderName                        fields.Field = "process.session_leader.name"                            // Process name.
	SessionLeaderParentEntityID              fields.Field = "process.session_leader.parent.entity_id"                // Unique identifier for the process.
	SessionLeaderParentPid                   fields.Field = "process.session_leader.parent.pid"                      // Process id.
	SessionLeaderParentSessionLeaderEntityID fields.Field = "process.session_leader.parent.session_leader.entity_id" // Unique identifier for the process.
	SessionLeaderParentSessionLeaderPid      fields.Field = "process.session_leader.parent.session_leader.pid"       // Process id.
	SessionLeaderParentSessionLeaderStart    fields.Field = "process.session_leader.parent.session_leader.start"     // The time the process started.
	SessionLeaderParentSessionLeaderVpid     fields.Field = "process.session_leader.parent.session_leader.vpid"      // Virtual process id.
	SessionLeaderParentStart                 fields.Field = "process.session_leader.parent.start"                    // The time the process started.
	SessionLeaderParentVpid                  fields.Field = "process.session_leader.parent.vpid"                     // Virtual process id.
	SessionLeaderPid                         fields.Field = "process.session_leader.pid"                             // Process id.
	SessionLeaderRealGroupID                 fields.Field = "process.session_leader.real_group.id"                   // Unique identifier for the group on the system/platform.
	SessionLeaderRealGroupName               fields.Field = "process.session_leader.real_group.name"                 // Name of the group.
	SessionLeaderRealUserID                  fields.Field = "process.session_leader.real_user.id"                    // Unique identifier of the user.
	SessionLeaderRealUserName                fields.Field = "process.session_leader.real_user.name"                  // Short name or login of the user.
	SessionLeaderSameAs                      fields.Field = "process.session_leader.same_as_process"                 // This boolean is used to identify if a leader process is the same as the top level process.
	SessionLeaderSavedGroupID                fields.Field = "process.session_leader.saved_group.id"                  // Unique identifier for the group on the system/platform.
	SessionLeaderSavedGroupName              fields.Field = "process.session_leader.saved_group.name"                // Name of the group.
	SessionLeaderSavedUserID                 fields.Field = "process.session_leader.saved_user.id"                   // Unique identifier of the user.
	SessionLeaderSavedUserName               fields.Field = "process.session_leader.saved_user.name"                 // Short name or login of the user.
	SessionLeaderStart                       fields.Field = "process.session_leader.start"                           // The time the process started.
	SessionLeaderSupplementalGroupsID        fields.Field = "process.session_leader.supplemental_groups.id"          // Unique identifier for the group on the system/platform.
	SessionLeaderSupplementalGroupsName      fields.Field = "process.session_leader.supplemental_groups.name"        // Name of the group.
	SessionLeaderTty                         fields.Field = "process.session_leader.tty"                             // Information about the controlling TTY device.
	SessionLeaderTtyCharDeviceMajor          fields.Field = "process.session_leader.tty.char_device.major"           // The TTY character device's major number.
	SessionLeaderTtyCharDeviceMinor          fields.Field = "process.session_leader.tty.char_device.minor"           // The TTY character device's minor number.
	SessionLeaderUserID                      fields.Field = "process.session_leader.user.id"                         // Unique identifier of the user.
	SessionLeaderUserName                    fields.Field = "process.session_leader.user.name"                       // Short name or login of the user.
	SessionLeaderVpid                        fields.Field = "process.session_leader.vpid"                            // Virtual process id.
	SessionLeaderWorkingDirectory            fields.Field = "process.session_leader.working_directory"               // The working directory of the process.
	Start                                    fields.Field = "process.start"                                          // The time the process started.
	SupplementalGroupsID                     fields.Field = "process.supplemental_groups.id"                         // Unique identifier for the group on the system/platform.
	SupplementalGroupsName                   fields.Field = "process.supplemental_groups.name"                       // Name of the group.
	ThreadCapabilitiesEffective              fields.Field = "process.thread.capabilities.effective"                  // Array of capabilities used for permission checks.
	ThreadCapabilitiesPermitted              fields.Field = "process.thread.capabilities.permitted"                  // Array of capabilities a thread could assume.
	ThreadID                                 fields.Field = "process.thread.id"                                      // Thread ID.
	ThreadName                               fields.Field = "process.thread.name"                                    // Thread name.
	Title                                    fields.Field = "process.title"                                          // Process title.
	Tty                                      fields.Field = "process.tty"                                            // Information about the controlling TTY device.
	TtyCharDeviceMajor                       fields.Field = "process.tty.char_device.major"                          // The TTY character device's major number.
	TtyCharDeviceMinor                       fields.Field = "process.tty.char_device.minor"                          // The TTY character device's minor number.
	TtyColumns                               fields.Field = "process.tty.columns"                                    // The number of character columns per line. e.g terminal width
	TtyRows                                  fields.Field = "process.tty.rows"                                       // The number of character rows in the terminal. e.g terminal height
	Uptime                                   fields.Field = "process.uptime"                                         // Seconds the process has been up.
	UserID                                   fields.Field = "process.user.id"                                        // Unique identifier of the user.
	UserName                                 fields.Field = "process.user.name"                                      // Short name or login of the user.
	Vpid                                     fields.Field = "process.vpid"                                           // Virtual process id.
	WorkingDirectory                         fields.Field = "process.working_directory"                              // The working directory of the process.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Args,
	ArgsCount,
	CodeSignatureDigestAlgorithm,
	CodeSignatureExists,
	CodeSignatureFlags,
	CodeSignatureSigningID,
	CodeSignatureStatus,
	CodeSignatureSubjectName,
	CodeSignatureTeamID,
	CodeSignatureThumbprintSha256,
	CodeSignatureTimestamp,
	CodeSignatureTrusted,
	CodeSignatureValid,
	CommandLine,
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
	End,
	EntityID,
	EntryLeaderArgs,
	EntryLeaderArgsCount,
	EntryLeaderAttestedGroupsName,
	EntryLeaderAttestedUserID,
	EntryLeaderAttestedUserName,
	EntryLeaderCommandLine,
	EntryLeaderEntityID,
	EntryLeaderEntryMetaSourceIp,
	EntryLeaderEntryMetaType,
	EntryLeaderExecutable,
	EntryLeaderGroupID,
	EntryLeaderGroupName,
	EntryLeaderInteractive,
	EntryLeaderName,
	EntryLeaderParentEntityID,
	EntryLeaderParentPid,
	EntryLeaderParentSessionLeaderEntityID,
	EntryLeaderParentSessionLeaderPid,
	EntryLeaderParentSessionLeaderStart,
	EntryLeaderParentSessionLeaderVpid,
	EntryLeaderParentStart,
	EntryLeaderParentVpid,
	EntryLeaderPid,
	EntryLeaderRealGroupID,
	EntryLeaderRealGroupName,
	EntryLeaderRealUserID,
	EntryLeaderRealUserName,
	EntryLeaderSameAs,
	EntryLeaderSavedGroupID,
	EntryLeaderSavedGroupName,
	EntryLeaderSavedUserID,
	EntryLeaderSavedUserName,
	EntryLeaderStart,
	EntryLeaderSupplementalGroupsID,
	EntryLeaderSupplementalGroupsName,
	EntryLeaderTty,
	EntryLeaderTtyCharDeviceMajor,
	EntryLeaderTtyCharDeviceMinor,
	EntryLeaderUserID,
	EntryLeaderUserName,
	EntryLeaderVpid,
	EntryLeaderWorkingDirectory,
	EnvVars,
	Executable,
	ExitCode,
	GroupID,
	GroupLeaderArgs,
	GroupLeaderArgsCount,
	GroupLeaderCommandLine,
	GroupLeaderEntityID,
	GroupLeaderExecutable,
	GroupLeaderGroupID,
	GroupLeaderGroupName,
	GroupLeaderInteractive,
	GroupLeaderName,
	GroupLeaderPid,
	GroupLeaderRealGroupID,
	GroupLeaderRealGroupName,
	GroupLeaderRealUserID,
	GroupLeaderRealUserName,
	GroupLeaderSameAs,
	GroupLeaderSavedGroupID,
	GroupLeaderSavedGroupName,
	GroupLeaderSavedUserID,
	GroupLeaderSavedUserName,
	GroupLeaderStart,
	GroupLeaderSupplementalGroupsID,
	GroupLeaderSupplementalGroupsName,
	GroupLeaderTty,
	GroupLeaderTtyCharDeviceMajor,
	GroupLeaderTtyCharDeviceMinor,
	GroupLeaderUserID,
	GroupLeaderUserName,
	GroupLeaderVpid,
	GroupLeaderWorkingDirectory,
	GroupName,
	HashCdhash,
	HashMd5,
	HashSha1,
	HashSha256,
	HashSha384,
	HashSha512,
	HashSsdeep,
	HashTlsh,
	Interactive,
	Io,
	IoBytesSkipped,
	IoBytesSkippedLength,
	IoBytesSkippedOffset,
	IoMaxBytesPerExceeded,
	IoText,
	IoTotalBytesCaptured,
	IoTotalBytesSkipped,
	IoType,
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
	Name,
	ParentArgs,
	ParentArgsCount,
	ParentCodeSignatureDigestAlgorithm,
	ParentCodeSignatureExists,
	ParentCodeSignatureFlags,
	ParentCodeSignatureSigningID,
	ParentCodeSignatureStatus,
	ParentCodeSignatureSubjectName,
	ParentCodeSignatureTeamID,
	ParentCodeSignatureThumbprintSha256,
	ParentCodeSignatureTimestamp,
	ParentCodeSignatureTrusted,
	ParentCodeSignatureValid,
	ParentCommandLine,
	ParentElfArchitecture,
	ParentElfByteOrder,
	ParentElfCpuType,
	ParentElfCreationDate,
	ParentElfExports,
	ParentElfGoImportHash,
	ParentElfGoImports,
	ParentElfGoImportsNamesEntropy,
	ParentElfGoImportsNamesVarEntropy,
	ParentElfGoStripped,
	ParentElfHeaderAbiVersion,
	ParentElfHeaderClass,
	ParentElfHeaderData,
	ParentElfHeaderEntrypoint,
	ParentElfHeaderObjectVersion,
	ParentElfHeaderOsAbi,
	ParentElfHeaderType,
	ParentElfHeaderVersion,
	ParentElfImportHash,
	ParentElfImports,
	ParentElfImportsNamesEntropy,
	ParentElfImportsNamesVarEntropy,
	ParentElfSections,
	ParentElfSectionsChi2,
	ParentElfSectionsEntropy,
	ParentElfSectionsFlags,
	ParentElfSectionsName,
	ParentElfSectionsPhysicalOffset,
	ParentElfSectionsPhysicalSize,
	ParentElfSectionsType,
	ParentElfSectionsVarEntropy,
	ParentElfSectionsVirtualAddress,
	ParentElfSectionsVirtualSize,
	ParentElfSegments,
	ParentElfSegmentsSections,
	ParentElfSegmentsType,
	ParentElfSharedLibraries,
	ParentElfTelfhash,
	ParentEnd,
	ParentEntityID,
	ParentExecutable,
	ParentExitCode,
	ParentGroupID,
	ParentGroupLeaderEntityID,
	ParentGroupLeaderPid,
	ParentGroupLeaderStart,
	ParentGroupLeaderVpid,
	ParentGroupName,
	ParentHashCdhash,
	ParentHashMd5,
	ParentHashSha1,
	ParentHashSha256,
	ParentHashSha384,
	ParentHashSha512,
	ParentHashSsdeep,
	ParentHashTlsh,
	ParentInteractive,
	ParentMachoGoImportHash,
	ParentMachoGoImports,
	ParentMachoGoImportsNamesEntropy,
	ParentMachoGoImportsNamesVarEntropy,
	ParentMachoGoStripped,
	ParentMachoImportHash,
	ParentMachoImports,
	ParentMachoImportsNamesEntropy,
	ParentMachoImportsNamesVarEntropy,
	ParentMachoSections,
	ParentMachoSectionsEntropy,
	ParentMachoSectionsName,
	ParentMachoSectionsPhysicalSize,
	ParentMachoSectionsVarEntropy,
	ParentMachoSectionsVirtualSize,
	ParentMachoSymhash,
	ParentName,
	ParentPeArchitecture,
	ParentPeCompany,
	ParentPeDescription,
	ParentPeFileVersion,
	ParentPeGoImportHash,
	ParentPeGoImports,
	ParentPeGoImportsNamesEntropy,
	ParentPeGoImportsNamesVarEntropy,
	ParentPeGoStripped,
	ParentPeImphash,
	ParentPeImportHash,
	ParentPeImports,
	ParentPeImportsNamesEntropy,
	ParentPeImportsNamesVarEntropy,
	ParentPeOriginalFileName,
	ParentPePehash,
	ParentPeProduct,
	ParentPeSections,
	ParentPeSectionsEntropy,
	ParentPeSectionsName,
	ParentPeSectionsPhysicalSize,
	ParentPeSectionsVarEntropy,
	ParentPeSectionsVirtualSize,
	ParentPid,
	ParentRealGroupID,
	ParentRealGroupName,
	ParentRealUserID,
	ParentRealUserName,
	ParentSavedGroupID,
	ParentSavedGroupName,
	ParentSavedUserID,
	ParentSavedUserName,
	ParentStart,
	ParentSupplementalGroupsID,
	ParentSupplementalGroupsName,
	ParentThreadCapabilitiesEffective,
	ParentThreadCapabilitiesPermitted,
	ParentThreadID,
	ParentThreadName,
	ParentTitle,
	ParentTty,
	ParentTtyCharDeviceMajor,
	ParentTtyCharDeviceMinor,
	ParentUptime,
	ParentUserID,
	ParentUserName,
	ParentVpid,
	ParentWorkingDirectory,
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
	Pid,
	PreviousArgs,
	PreviousArgsCount,
	PreviousExecutable,
	RealGroupID,
	RealGroupName,
	RealUserID,
	RealUserName,
	SavedGroupID,
	SavedGroupName,
	SavedUserID,
	SavedUserName,
	SessionLeaderArgs,
	SessionLeaderArgsCount,
	SessionLeaderCommandLine,
	SessionLeaderEntityID,
	SessionLeaderExecutable,
	SessionLeaderGroupID,
	SessionLeaderGroupName,
	SessionLeaderInteractive,
	SessionLeaderName,
	SessionLeaderParentEntityID,
	SessionLeaderParentPid,
	SessionLeaderParentSessionLeaderEntityID,
	SessionLeaderParentSessionLeaderPid,
	SessionLeaderParentSessionLeaderStart,
	SessionLeaderParentSessionLeaderVpid,
	SessionLeaderParentStart,
	SessionLeaderParentVpid,
	SessionLeaderPid,
	SessionLeaderRealGroupID,
	SessionLeaderRealGroupName,
	SessionLeaderRealUserID,
	SessionLeaderRealUserName,
	SessionLeaderSameAs,
	SessionLeaderSavedGroupID,
	SessionLeaderSavedGroupName,
	SessionLeaderSavedUserID,
	SessionLeaderSavedUserName,
	SessionLeaderStart,
	SessionLeaderSupplementalGroupsID,
	SessionLeaderSupplementalGroupsName,
	SessionLeaderTty,
	SessionLeaderTtyCharDeviceMajor,
	SessionLeaderTtyCharDeviceMinor,
	SessionLeaderUserID,
	SessionLeaderUserName,
	SessionLeaderVpid,
	SessionLeaderWorkingDirectory,
	Start,
	SupplementalGroupsID,
	SupplementalGroupsName,
	ThreadCapabilitiesEffective,
	ThreadCapabilitiesPermitted,
	ThreadID,
	ThreadName,
	Title,
	Tty,
	TtyCharDeviceMajor,
	TtyCharDeviceMinor,
	TtyColumns,
	TtyRows,
	Uptime,
	UserID,
	UserName,
	Vpid,
	WorkingDirectory,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Args                                     fields.Keyword
	ArgsCount                                fields.Long
	CodeSignatureDigestAlgorithm             fields.Keyword
	CodeSignatureExists                      fields.Boolean
	CodeSignatureFlags                       fields.Keyword
	CodeSignatureSigningID                   fields.Keyword
	CodeSignatureStatus                      fields.Keyword
	CodeSignatureSubjectName                 fields.Keyword
	CodeSignatureTeamID                      fields.Keyword
	CodeSignatureThumbprintSha256            fields.Keyword
	CodeSignatureTimestamp                   fields.Date
	CodeSignatureTrusted                     fields.Boolean
	CodeSignatureValid                       fields.Boolean
	CommandLine                              fields.Wildcard
	ElfArchitecture                          fields.Keyword
	ElfByteOrder                             fields.Keyword
	ElfCpuType                               fields.Keyword
	ElfCreationDate                          fields.Date
	ElfExports                               fields.Flattened
	ElfGoImportHash                          fields.Keyword
	ElfGoImports                             fields.Flattened
	ElfGoImportsNamesEntropy                 fields.Long
	ElfGoImportsNamesVarEntropy              fields.Long
	ElfGoStripped                            fields.Boolean
	ElfHeaderAbiVersion                      fields.Keyword
	ElfHeaderClass                           fields.Keyword
	ElfHeaderData                            fields.Keyword
	ElfHeaderEntrypoint                      fields.Long
	ElfHeaderObjectVersion                   fields.Keyword
	ElfHeaderOsAbi                           fields.Keyword
	ElfHeaderType                            fields.Keyword
	ElfHeaderVersion                         fields.Keyword
	ElfImportHash                            fields.Keyword
	ElfImports                               fields.Flattened
	ElfImportsNamesEntropy                   fields.Long
	ElfImportsNamesVarEntropy                fields.Long
	ElfSections                              fields.Nested
	ElfSectionsChi2                          fields.Long
	ElfSectionsEntropy                       fields.Long
	ElfSectionsFlags                         fields.Keyword
	ElfSectionsName                          fields.Keyword
	ElfSectionsPhysicalOffset                fields.Keyword
	ElfSectionsPhysicalSize                  fields.Long
	ElfSectionsType                          fields.Keyword
	ElfSectionsVarEntropy                    fields.Long
	ElfSectionsVirtualAddress                fields.Long
	ElfSectionsVirtualSize                   fields.Long
	ElfSegments                              fields.Nested
	ElfSegmentsSections                      fields.Keyword
	ElfSegmentsType                          fields.Keyword
	ElfSharedLibraries                       fields.Keyword
	ElfTelfhash                              fields.Keyword
	End                                      fields.Date
	EntityID                                 fields.Keyword
	EntryLeaderArgs                          fields.Keyword
	EntryLeaderArgsCount                     fields.Long
	EntryLeaderAttestedGroupsName            fields.Keyword
	EntryLeaderAttestedUserID                fields.Keyword
	EntryLeaderAttestedUserName              fields.Keyword
	EntryLeaderCommandLine                   fields.Wildcard
	EntryLeaderEntityID                      fields.Keyword
	EntryLeaderEntryMetaSourceIp             fields.IP
	EntryLeaderEntryMetaType                 fields.Keyword
	EntryLeaderExecutable                    fields.Keyword
	EntryLeaderGroupID                       fields.Keyword
	EntryLeaderGroupName                     fields.Keyword
	EntryLeaderInteractive                   fields.Boolean
	EntryLeaderName                          fields.Keyword
	EntryLeaderParentEntityID                fields.Keyword
	EntryLeaderParentPid                     fields.Long
	EntryLeaderParentSessionLeaderEntityID   fields.Keyword
	EntryLeaderParentSessionLeaderPid        fields.Long
	EntryLeaderParentSessionLeaderStart      fields.Date
	EntryLeaderParentSessionLeaderVpid       fields.Long
	EntryLeaderParentStart                   fields.Date
	EntryLeaderParentVpid                    fields.Long
	EntryLeaderPid                           fields.Long
	EntryLeaderRealGroupID                   fields.Keyword
	EntryLeaderRealGroupName                 fields.Keyword
	EntryLeaderRealUserID                    fields.Keyword
	EntryLeaderRealUserName                  fields.Keyword
	EntryLeaderSameAs                        fields.Boolean
	EntryLeaderSavedGroupID                  fields.Keyword
	EntryLeaderSavedGroupName                fields.Keyword
	EntryLeaderSavedUserID                   fields.Keyword
	EntryLeaderSavedUserName                 fields.Keyword
	EntryLeaderStart                         fields.Date
	EntryLeaderSupplementalGroupsID          fields.Keyword
	EntryLeaderSupplementalGroupsName        fields.Keyword
	EntryLeaderTty                           fields.Object
	EntryLeaderTtyCharDeviceMajor            fields.Long
	EntryLeaderTtyCharDeviceMinor            fields.Long
	EntryLeaderUserID                        fields.Keyword
	EntryLeaderUserName                      fields.Keyword
	EntryLeaderVpid                          fields.Long
	EntryLeaderWorkingDirectory              fields.Keyword
	EnvVars                                  fields.Keyword
	Executable                               fields.Keyword
	ExitCode                                 fields.Long
	GroupID                                  fields.Keyword
	GroupLeaderArgs                          fields.Keyword
	GroupLeaderArgsCount                     fields.Long
	GroupLeaderCommandLine                   fields.Wildcard
	GroupLeaderEntityID                      fields.Keyword
	GroupLeaderExecutable                    fields.Keyword
	GroupLeaderGroupID                       fields.Keyword
	GroupLeaderGroupName                     fields.Keyword
	GroupLeaderInteractive                   fields.Boolean
	GroupLeaderName                          fields.Keyword
	GroupLeaderPid                           fields.Long
	GroupLeaderRealGroupID                   fields.Keyword
	GroupLeaderRealGroupName                 fields.Keyword
	GroupLeaderRealUserID                    fields.Keyword
	GroupLeaderRealUserName                  fields.Keyword
	GroupLeaderSameAs                        fields.Boolean
	GroupLeaderSavedGroupID                  fields.Keyword
	GroupLeaderSavedGroupName                fields.Keyword
	GroupLeaderSavedUserID                   fields.Keyword
	GroupLeaderSavedUserName                 fields.Keyword
	GroupLeaderStart                         fields.Date
	GroupLeaderSupplementalGroupsID          fields.Keyword
	GroupLeaderSupplementalGroupsName        fields.Keyword
	GroupLeaderTty                           fields.Object
	GroupLeaderTtyCharDeviceMajor            fields.Long
	GroupLeaderTtyCharDeviceMinor            fields.Long
	GroupLeaderUserID                        fields.Keyword
	GroupLeaderUserName                      fields.Keyword
	GroupLeaderVpid                          fields.Long
	GroupLeaderWorkingDirectory              fields.Keyword
	GroupName                                fields.Keyword
	HashCdhash                               fields.Keyword
	HashMd5                                  fields.Keyword
	HashSha1                                 fields.Keyword
	HashSha256                               fields.Keyword
	HashSha384                               fields.Keyword
	HashSha512                               fields.Keyword
	HashSsdeep                               fields.Keyword
	HashTlsh                                 fields.Keyword
	Interactive                              fields.Boolean
	Io                                       fields.Object
	IoBytesSkipped                           fields.Object
	IoBytesSkippedLength                     fields.Long
	IoBytesSkippedOffset                     fields.Long
	IoMaxBytesPerExceeded                    fields.Boolean
	IoText                                   fields.Wildcard
	IoTotalBytesCaptured                     fields.Long
	IoTotalBytesSkipped                      fields.Long
	IoType                                   fields.Keyword
	MachoGoImportHash                        fields.Keyword
	MachoGoImports                           fields.Flattened
	MachoGoImportsNamesEntropy               fields.Long
	MachoGoImportsNamesVarEntropy            fields.Long
	MachoGoStripped                          fields.Boolean
	MachoImportHash                          fields.Keyword
	MachoImports                             fields.Flattened
	MachoImportsNamesEntropy                 fields.Long
	MachoImportsNamesVarEntropy              fields.Long
	MachoSections                            fields.Nested
	MachoSectionsEntropy                     fields.Long
	MachoSectionsName                        fields.Keyword
	MachoSectionsPhysicalSize                fields.Long
	MachoSectionsVarEntropy                  fields.Long
	MachoSectionsVirtualSize                 fields.Long
	MachoSymhash                             fields.Keyword
	Name                                     fields.Keyword
	ParentArgs                               fields.Keyword
	ParentArgsCount                          fields.Long
	ParentCodeSignatureDigestAlgorithm       fields.Keyword
	ParentCodeSignatureExists                fields.Boolean
	ParentCodeSignatureFlags                 fields.Keyword
	ParentCodeSignatureSigningID             fields.Keyword
	ParentCodeSignatureStatus                fields.Keyword
	ParentCodeSignatureSubjectName           fields.Keyword
	ParentCodeSignatureTeamID                fields.Keyword
	ParentCodeSignatureThumbprintSha256      fields.Keyword
	ParentCodeSignatureTimestamp             fields.Date
	ParentCodeSignatureTrusted               fields.Boolean
	ParentCodeSignatureValid                 fields.Boolean
	ParentCommandLine                        fields.Wildcard
	ParentElfArchitecture                    fields.Keyword
	ParentElfByteOrder                       fields.Keyword
	ParentElfCpuType                         fields.Keyword
	ParentElfCreationDate                    fields.Date
	ParentElfExports                         fields.Flattened
	ParentElfGoImportHash                    fields.Keyword
	ParentElfGoImports                       fields.Flattened
	ParentElfGoImportsNamesEntropy           fields.Long
	ParentElfGoImportsNamesVarEntropy        fields.Long
	ParentElfGoStripped                      fields.Boolean
	ParentElfHeaderAbiVersion                fields.Keyword
	ParentElfHeaderClass                     fields.Keyword
	ParentElfHeaderData                      fields.Keyword
	ParentElfHeaderEntrypoint                fields.Long
	ParentElfHeaderObjectVersion             fields.Keyword
	ParentElfHeaderOsAbi                     fields.Keyword
	ParentElfHeaderType                      fields.Keyword
	ParentElfHeaderVersion                   fields.Keyword
	ParentElfImportHash                      fields.Keyword
	ParentElfImports                         fields.Flattened
	ParentElfImportsNamesEntropy             fields.Long
	ParentElfImportsNamesVarEntropy          fields.Long
	ParentElfSections                        fields.Nested
	ParentElfSectionsChi2                    fields.Long
	ParentElfSectionsEntropy                 fields.Long
	ParentElfSectionsFlags                   fields.Keyword
	ParentElfSectionsName                    fields.Keyword
	ParentElfSectionsPhysicalOffset          fields.Keyword
	ParentElfSectionsPhysicalSize            fields.Long
	ParentElfSectionsType                    fields.Keyword
	ParentElfSectionsVarEntropy              fields.Long
	ParentElfSectionsVirtualAddress          fields.Long
	ParentElfSectionsVirtualSize             fields.Long
	ParentElfSegments                        fields.Nested
	ParentElfSegmentsSections                fields.Keyword
	ParentElfSegmentsType                    fields.Keyword
	ParentElfSharedLibraries                 fields.Keyword
	ParentElfTelfhash                        fields.Keyword
	ParentEnd                                fields.Date
	ParentEntityID                           fields.Keyword
	ParentExecutable                         fields.Keyword
	ParentExitCode                           fields.Long
	ParentGroupID                            fields.Keyword
	ParentGroupLeaderEntityID                fields.Keyword
	ParentGroupLeaderPid                     fields.Long
	ParentGroupLeaderStart                   fields.Date
	ParentGroupLeaderVpid                    fields.Long
	ParentGroupName                          fields.Keyword
	ParentHashCdhash                         fields.Keyword
	ParentHashMd5                            fields.Keyword
	ParentHashSha1                           fields.Keyword
	ParentHashSha256                         fields.Keyword
	ParentHashSha384                         fields.Keyword
	ParentHashSha512                         fields.Keyword
	ParentHashSsdeep                         fields.Keyword
	ParentHashTlsh                           fields.Keyword
	ParentInteractive                        fields.Boolean
	ParentMachoGoImportHash                  fields.Keyword
	ParentMachoGoImports                     fields.Flattened
	ParentMachoGoImportsNamesEntropy         fields.Long
	ParentMachoGoImportsNamesVarEntropy      fields.Long
	ParentMachoGoStripped                    fields.Boolean
	ParentMachoImportHash                    fields.Keyword
	ParentMachoImports                       fields.Flattened
	ParentMachoImportsNamesEntropy           fields.Long
	ParentMachoImportsNamesVarEntropy        fields.Long
	ParentMachoSections                      fields.Nested
	ParentMachoSectionsEntropy               fields.Long
	ParentMachoSectionsName                  fields.Keyword
	ParentMachoSectionsPhysicalSize          fields.Long
	ParentMachoSectionsVarEntropy            fields.Long
	ParentMachoSectionsVirtualSize           fields.Long
	ParentMachoSymhash                       fields.Keyword
	ParentName                               fields.Keyword
	ParentPeArchitecture                     fields.Keyword
	ParentPeCompany                          fields.Keyword
	ParentPeDescription                      fields.Keyword
	ParentPeFileVersion                      fields.Keyword
	ParentPeGoImportHash                     fields.Keyword
	ParentPeGoImports                        fields.Flattened
	ParentPeGoImportsNamesEntropy            fields.Long
	ParentPeGoImportsNamesVarEntropy         fields.Long
	ParentPeGoStripped                       fields.Boolean
	ParentPeImphash                          fields.Keyword
	ParentPeImportHash                       fields.Keyword
	ParentPeImports                          fields.Flattened
	ParentPeImportsNamesEntropy              fields.Long
	ParentPeImportsNamesVarEntropy           fields.Long
	ParentPeOriginalFileName                 fields.Keyword
	ParentPePehash                           fields.Keyword
	ParentPeProduct                          fields.Keyword
	ParentPeSections                         fields.Nested
	ParentPeSectionsEntropy                  fields.Long
	ParentPeSectionsName                     fields.Keyword
	ParentPeSectionsPhysicalSize             fields.Long
	ParentPeSectionsVarEntropy               fields.Long
	ParentPeSectionsVirtualSize              fields.Long
	ParentPid                                fields.Long
	ParentRealGroupID                        fields.Keyword
	ParentRealGroupName                      fields.Keyword
	ParentRealUserID                         fields.Keyword
	ParentRealUserName                       fields.Keyword
	ParentSavedGroupID                       fields.Keyword
	ParentSavedGroupName                     fields.Keyword
	ParentSavedUserID                        fields.Keyword
	ParentSavedUserName                      fields.Keyword
	ParentStart                              fields.Date
	ParentSupplementalGroupsID               fields.Keyword
	ParentSupplementalGroupsName             fields.Keyword
	ParentThreadCapabilitiesEffective        fields.Keyword
	ParentThreadCapabilitiesPermitted        fields.Keyword
	ParentThreadID                           fields.Long
	ParentThreadName                         fields.Keyword
	ParentTitle                              fields.Keyword
	ParentTty                                fields.Object
	ParentTtyCharDeviceMajor                 fields.Long
	ParentTtyCharDeviceMinor                 fields.Long
	ParentUptime                             fields.Long
	ParentUserID                             fields.Keyword
	ParentUserName                           fields.Keyword
	ParentVpid                               fields.Long
	ParentWorkingDirectory                   fields.Keyword
	PeArchitecture                           fields.Keyword
	PeCompany                                fields.Keyword
	PeDescription                            fields.Keyword
	PeFileVersion                            fields.Keyword
	PeGoImportHash                           fields.Keyword
	PeGoImports                              fields.Flattened
	PeGoImportsNamesEntropy                  fields.Long
	PeGoImportsNamesVarEntropy               fields.Long
	PeGoStripped                             fields.Boolean
	PeImphash                                fields.Keyword
	PeImportHash                             fields.Keyword
	PeImports                                fields.Flattened
	PeImportsNamesEntropy                    fields.Long
	PeImportsNamesVarEntropy                 fields.Long
	PeOriginalFileName                       fields.Keyword
	PePehash                                 fields.Keyword
	PeProduct                                fields.Keyword
	PeSections                               fields.Nested
	PeSectionsEntropy                        fields.Long
	PeSectionsName                           fields.Keyword
	PeSectionsPhysicalSize                   fields.Long
	PeSectionsVarEntropy                     fields.Long
	PeSectionsVirtualSize                    fields.Long
	Pid                                      fields.Long
	PreviousArgs                             fields.Keyword
	PreviousArgsCount                        fields.Long
	PreviousExecutable                       fields.Keyword
	RealGroupID                              fields.Keyword
	RealGroupName                            fields.Keyword
	RealUserID                               fields.Keyword
	RealUserName                             fields.Keyword
	SavedGroupID                             fields.Keyword
	SavedGroupName                           fields.Keyword
	SavedUserID                              fields.Keyword
	SavedUserName                            fields.Keyword
	SessionLeaderArgs                        fields.Keyword
	SessionLeaderArgsCount                   fields.Long
	SessionLeaderCommandLine                 fields.Wildcard
	SessionLeaderEntityID                    fields.Keyword
	SessionLeaderExecutable                  fields.Keyword
	SessionLeaderGroupID                     fields.Keyword
	SessionLeaderGroupName                   fields.Keyword
	SessionLeaderInteractive                 fields.Boolean
	SessionLeaderName                        fields.Keyword
	SessionLeaderParentEntityID              fields.Keyword
	SessionLeaderParentPid                   fields.Long
	SessionLeaderParentSessionLeaderEntityID fields.Keyword
	SessionLeaderParentSessionLeaderPid      fields.Long
	SessionLeaderParentSessionLeaderStart    fields.Date
	SessionLeaderParentSessionLeaderVpid     fields.Long
	SessionLeaderParentStart                 fields.Date
	SessionLeaderParentVpid                  fields.Long
	SessionLeaderPid                         fields.Long
	SessionLeaderRealGroupID                 fields.Keyword
	SessionLeaderRealGroupName               fields.Keyword
	SessionLeaderRealUserID                  fields.Keyword
	SessionLeaderRealUserName                fields.Keyword
	SessionLeaderSameAs                      fields.Boolean
	SessionLeaderSavedGroupID                fields.Keyword
	SessionLeaderSavedGroupName              fields.Keyword
	SessionLeaderSavedUserID                 fields.Keyword
	SessionLeaderSavedUserName               fields.Keyword
	SessionLeaderStart                       fields.Date
	SessionLeaderSupplementalGroupsID        fields.Keyword
	SessionLeaderSupplementalGroupsName      fields.Keyword
	SessionLeaderTty                         fields.Object
	SessionLeaderTtyCharDeviceMajor          fields.Long
	SessionLeaderTtyCharDeviceMinor          fields.Long
	SessionLeaderUserID                      fields.Keyword
	SessionLeaderUserName                    fields.Keyword
	SessionLeaderVpid                        fields.Long
	SessionLeaderWorkingDirectory            fields.Keyword
	Start                                    fields.Date
	SupplementalGroupsID                     fields.Keyword
	SupplementalGroupsName                   fields.Keyword
	ThreadCapabilitiesEffective              fields.Keyword
	ThreadCapabilitiesPermitted              fields.Keyword
	ThreadID                                 fields.Long
	ThreadName                               fields.Keyword
	Title                                    fields.Keyword
	Tty                                      fields.Object
	TtyCharDeviceMajor                       fields.Long
	TtyCharDeviceMinor                       fields.Long
	TtyColumns                               fields.Long
	TtyRows                                  fields.Long
	Uptime                                   fields.Long
	UserID                                   fields.Keyword
	UserName                                 fields.Keyword
	Vpid                                     fields.Long
	WorkingDirectory                         fields.Keyword
}

var Types TypesType = TypesType{}
