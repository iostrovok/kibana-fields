package pe

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Architecture             fields.Field = "pe.architecture"                 // CPU architecture target for the file.
	Company                  fields.Field = "pe.company"                      // Internal company name of the file, provided at compile-time.
	Description              fields.Field = "pe.description"                  // Internal description of the file, provided at compile-time.
	FileVersion              fields.Field = "pe.file_version"                 // Process name.
	GoImportHash             fields.Field = "pe.go_import_hash"               // A hash of the Go language imports in a PE file.
	GoImports                fields.Field = "pe.go_imports"                   // List of imported Go language element names and types.
	GoImportsNamesEntropy    fields.Field = "pe.go_imports_names_entropy"     // Shannon entropy calculation from the list of Go imports.
	GoImportsNamesVarEntropy fields.Field = "pe.go_imports_names_var_entropy" // Variance for Shannon entropy calculation from the list of Go imports.
	GoStripped               fields.Field = "pe.go_stripped"                  // Whether the file is a stripped or obfuscated Go executable.
	Imphash                  fields.Field = "pe.imphash"                      // A hash of the imports in a PE file.
	ImportHash               fields.Field = "pe.import_hash"                  // A hash of the imports in a PE file.
	Imports                  fields.Field = "pe.imports"                      // List of imported element names and types.
	ImportsNamesEntropy      fields.Field = "pe.imports_names_entropy"        // Shannon entropy calculation from the list of imported element names and types.
	ImportsNamesVarEntropy   fields.Field = "pe.imports_names_var_entropy"    // Variance for Shannon entropy calculation from the list of imported element names and types.
	OriginalFileName         fields.Field = "pe.original_file_name"           // Internal name of the file, provided at compile-time.
	Pehash                   fields.Field = "pe.pehash"                       // A hash of the PE header and data from one or more PE sections.
	Product                  fields.Field = "pe.product"                      // Internal product name of the file, provided at compile-time.
	SectionsEntropy          fields.Field = "pe.sections.entropy"             // Shannon entropy calculation from the section.
	SectionsName             fields.Field = "pe.sections.name"                // PE Section List name.
	SectionsPhysicalSize     fields.Field = "pe.sections.physical_size"       // PE Section List physical size.
	SectionsVarEntropy       fields.Field = "pe.sections.var_entropy"         // Variance for Shannon entropy calculation from the section.
	SectionsVirtualSize      fields.Field = "pe.sections.virtual_size"        // PE Section List virtual size. This is always the same as `physical_size`.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Architecture,
	Company,
	Description,
	FileVersion,
	GoImportHash,
	GoImports,
	GoImportsNamesEntropy,
	GoImportsNamesVarEntropy,
	GoStripped,
	Imphash,
	ImportHash,
	Imports,
	ImportsNamesEntropy,
	ImportsNamesVarEntropy,
	OriginalFileName,
	Pehash,
	Product,
	SectionsEntropy,
	SectionsName,
	SectionsPhysicalSize,
	SectionsVarEntropy,
	SectionsVirtualSize,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Architecture             fields.KeyWord
	Company                  fields.KeyWord
	Description              fields.KeyWord
	FileVersion              fields.KeyWord
	GoImportHash             fields.KeyWord
	GoImports                fields.Flattened
	GoImportsNamesEntropy    fields.Long
	GoImportsNamesVarEntropy fields.Long
	GoStripped               fields.Boolean
	Imphash                  fields.KeyWord
	ImportHash               fields.KeyWord
	Imports                  fields.Flattened
	ImportsNamesEntropy      fields.Long
	ImportsNamesVarEntropy   fields.Long
	OriginalFileName         fields.KeyWord
	Pehash                   fields.KeyWord
	Product                  fields.KeyWord
	SectionsEntropy          fields.Long
	SectionsName             fields.KeyWord
	SectionsPhysicalSize     fields.Long
	SectionsVarEntropy       fields.Long
	SectionsVirtualSize      fields.Long
}

var Types TypesType = TypesType{}
