package macho

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	GoImportHash             fields.Field = "macho.go_import_hash"               // A hash of the Go language imports in a Mach-O file.
	GoImports                fields.Field = "macho.go_imports"                   // List of imported Go language element names and types.
	GoImportsNamesEntropy    fields.Field = "macho.go_imports_names_entropy"     // Shannon entropy calculation from the list of Go imports.
	GoImportsNamesVarEntropy fields.Field = "macho.go_imports_names_var_entropy" // Variance for Shannon entropy calculation from the list of Go imports.
	GoStripped               fields.Field = "macho.go_stripped"                  // Whether the file is a stripped or obfuscated Go executable.
	ImportHash               fields.Field = "macho.import_hash"                  // A hash of the imports in a Mach-O file.
	Imports                  fields.Field = "macho.imports"                      // List of imported element names and types.
	ImportsNamesEntropy      fields.Field = "macho.imports_names_entropy"        // Shannon entropy calculation from the list of imported element names and types.
	ImportsNamesVarEntropy   fields.Field = "macho.imports_names_var_entropy"    // Variance for Shannon entropy calculation from the list of imported element names and types.
	SectionsEntropy          fields.Field = "macho.sections.entropy"             // Shannon entropy calculation from the section.
	SectionsName             fields.Field = "macho.sections.name"                // Mach-O Section List name.
	SectionsPhysicalSize     fields.Field = "macho.sections.physical_size"       // Mach-O Section List physical size.
	SectionsVarEntropy       fields.Field = "macho.sections.var_entropy"         // Variance for Shannon entropy calculation from the section.
	SectionsVirtualSize      fields.Field = "macho.sections.virtual_size"        // Mach-O Section List virtual size. This is always the same as `physical_size`.
	Symhash                  fields.Field = "macho.symhash"                      // A hash of the imports in a Mach-O file.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	GoImportHash,
	GoImports,
	GoImportsNamesEntropy,
	GoImportsNamesVarEntropy,
	GoStripped,
	ImportHash,
	Imports,
	ImportsNamesEntropy,
	ImportsNamesVarEntropy,
	SectionsEntropy,
	SectionsName,
	SectionsPhysicalSize,
	SectionsVarEntropy,
	SectionsVirtualSize,
	Symhash,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	GoImportHash             fields.KeyWord
	GoImports                fields.Flattened
	GoImportsNamesEntropy    fields.Long
	GoImportsNamesVarEntropy fields.Long
	GoStripped               fields.Boolean
	ImportHash               fields.KeyWord
	Imports                  fields.Flattened
	ImportsNamesEntropy      fields.Long
	ImportsNamesVarEntropy   fields.Long
	SectionsEntropy          fields.Long
	SectionsName             fields.KeyWord
	SectionsPhysicalSize     fields.Long
	SectionsVarEntropy       fields.Long
	SectionsVirtualSize      fields.Long
	Symhash                  fields.KeyWord
}

var Types TypesType = TypesType{}
