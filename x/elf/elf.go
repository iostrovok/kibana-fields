package elf

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Architecture             fields.Field = "elf.architecture"                 // Machine architecture of the ELF file.
	ByteOrder                fields.Field = "elf.byte_order"                   // Byte sequence of ELF file.
	CpuType                  fields.Field = "elf.cpu_type"                     // CPU type of the ELF file.
	CreationDate             fields.Field = "elf.creation_date"                // Build or compile date.
	Exports                  fields.Field = "elf.exports"                      // List of exported element names and types.
	GoImportHash             fields.Field = "elf.go_import_hash"               // A hash of the Go language imports in an ELF file.
	GoImports                fields.Field = "elf.go_imports"                   // List of imported Go language element names and types.
	GoImportsNamesEntropy    fields.Field = "elf.go_imports_names_entropy"     // Shannon entropy calculation from the list of Go imports.
	GoImportsNamesVarEntropy fields.Field = "elf.go_imports_names_var_entropy" // Variance for Shannon entropy calculation from the list of Go imports.
	GoStripped               fields.Field = "elf.go_stripped"                  // Whether the file is a stripped or obfuscated Go executable.
	HeaderAbiVersion         fields.Field = "elf.header.abi_version"           // Version of the ELF Application Binary Interface (ABI).
	HeaderClass              fields.Field = "elf.header.class"                 // Header class of the ELF file.
	HeaderData               fields.Field = "elf.header.data"                  // Data table of the ELF header.
	HeaderEntrypoint         fields.Field = "elf.header.entrypoint"            // Header entrypoint of the ELF file.
	HeaderObjectVersion      fields.Field = "elf.header.object_version"        // "0x1" for original ELF files.
	HeaderOsAbi              fields.Field = "elf.header.os_abi"                // Application Binary Interface (ABI) of the Linux OS.
	HeaderType               fields.Field = "elf.header.type"                  // Header type of the ELF file.
	HeaderVersion            fields.Field = "elf.header.version"               // Version of the ELF header.
	ImportHash               fields.Field = "elf.import_hash"                  // A hash of the imports in an ELF file.
	Imports                  fields.Field = "elf.imports"                      // List of imported element names and types.
	ImportsNamesEntropy      fields.Field = "elf.imports_names_entropy"        // Shannon entropy calculation from the list of imported element names and types.
	ImportsNamesVarEntropy   fields.Field = "elf.imports_names_var_entropy"    // Variance for Shannon entropy calculation from the list of imported element names and types.
	Sections                 fields.Field = "elf.sections"                     // Section information of the ELF file.
	SectionsChi2             fields.Field = "elf.sections.chi2"                // Chi-square probability distribution of the section.
	SectionsEntropy          fields.Field = "elf.sections.entropy"             // Shannon entropy calculation from the section.
	SectionsFlags            fields.Field = "elf.sections.flags"               // ELF Section List flags.
	SectionsName             fields.Field = "elf.sections.name"                // ELF Section List name.
	SectionsPhysicalOffset   fields.Field = "elf.sections.physical_offset"     // ELF Section List offset.
	SectionsPhysicalSize     fields.Field = "elf.sections.physical_size"       // ELF Section List physical size.
	SectionsType             fields.Field = "elf.sections.type"                // ELF Section List type.
	SectionsVarEntropy       fields.Field = "elf.sections.var_entropy"         // Variance for Shannon entropy calculation from the section.
	SectionsVirtualAddress   fields.Field = "elf.sections.virtual_address"     // ELF Section List virtual address.
	SectionsVirtualSize      fields.Field = "elf.sections.virtual_size"        // ELF Section List virtual size.
	Segments                 fields.Field = "elf.segments"                     // ELF object segment list.
	SegmentsSections         fields.Field = "elf.segments.sections"            // ELF object segment sections.
	SegmentsType             fields.Field = "elf.segments.type"                // ELF object segment type.
	SharedLibraries          fields.Field = "elf.shared_libraries"             // List of shared libraries used by this ELF object.
	Telfhash                 fields.Field = "elf.telfhash"                     // telfhash hash for ELF file.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Architecture,
	ByteOrder,
	CpuType,
	CreationDate,
	Exports,
	GoImportHash,
	GoImports,
	GoImportsNamesEntropy,
	GoImportsNamesVarEntropy,
	GoStripped,
	HeaderAbiVersion,
	HeaderClass,
	HeaderData,
	HeaderEntrypoint,
	HeaderObjectVersion,
	HeaderOsAbi,
	HeaderType,
	HeaderVersion,
	ImportHash,
	Imports,
	ImportsNamesEntropy,
	ImportsNamesVarEntropy,
	Sections,
	SectionsChi2,
	SectionsEntropy,
	SectionsFlags,
	SectionsName,
	SectionsPhysicalOffset,
	SectionsPhysicalSize,
	SectionsType,
	SectionsVarEntropy,
	SectionsVirtualAddress,
	SectionsVirtualSize,
	Segments,
	SegmentsSections,
	SegmentsType,
	SharedLibraries,
	Telfhash,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Architecture             fields.KeyWord
	ByteOrder                fields.KeyWord
	CpuType                  fields.KeyWord
	CreationDate             fields.Date
	Exports                  fields.Flattened
	GoImportHash             fields.KeyWord
	GoImports                fields.Flattened
	GoImportsNamesEntropy    fields.Long
	GoImportsNamesVarEntropy fields.Long
	GoStripped               fields.Boolean
	HeaderAbiVersion         fields.KeyWord
	HeaderClass              fields.KeyWord
	HeaderData               fields.KeyWord
	HeaderEntrypoint         fields.Long
	HeaderObjectVersion      fields.KeyWord
	HeaderOsAbi              fields.KeyWord
	HeaderType               fields.KeyWord
	HeaderVersion            fields.KeyWord
	ImportHash               fields.KeyWord
	Imports                  fields.Flattened
	ImportsNamesEntropy      fields.Long
	ImportsNamesVarEntropy   fields.Long
	Sections                 fields.Nested
	SectionsChi2             fields.Long
	SectionsEntropy          fields.Long
	SectionsFlags            fields.KeyWord
	SectionsName             fields.KeyWord
	SectionsPhysicalOffset   fields.KeyWord
	SectionsPhysicalSize     fields.Long
	SectionsType             fields.KeyWord
	SectionsVarEntropy       fields.Long
	SectionsVirtualAddress   fields.Long
	SectionsVirtualSize      fields.Long
	Segments                 fields.Nested
	SegmentsSections         fields.KeyWord
	SegmentsType             fields.KeyWord
	SharedLibraries          fields.KeyWord
	Telfhash                 fields.KeyWord
}

var Types TypesType = TypesType{}
