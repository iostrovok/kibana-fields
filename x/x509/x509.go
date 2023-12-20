package x509

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	AlternativeNames          fields.Field = "x509.alternative_names"           // List of subject alternative names (SAN).
	IssuerCommonName          fields.Field = "x509.issuer.common_name"          // List of common name (CN) of issuing certificate authority.
	IssuerCountry             fields.Field = "x509.issuer.country"              // List of country \(C) codes
	IssuerDistinguishedName   fields.Field = "x509.issuer.distinguished_name"   // Distinguished name (DN) of issuing certificate authority.
	IssuerLocality            fields.Field = "x509.issuer.locality"             // List of locality names (L)
	IssuerOrganization        fields.Field = "x509.issuer.organization"         // List of organizations (O) of issuing certificate authority.
	IssuerOrganizationalUnit  fields.Field = "x509.issuer.organizational_unit"  // List of organizational units (OU) of issuing certificate authority.
	IssuerStateOrProvince     fields.Field = "x509.issuer.state_or_province"    // List of state or province names (ST, S, or P)
	NotAfter                  fields.Field = "x509.not_after"                   // Time at which the certificate is no longer considered valid.
	NotBefore                 fields.Field = "x509.not_before"                  // Time at which the certificate is first considered valid.
	PublicKeyAlgorithm        fields.Field = "x509.public_key_algorithm"        // Algorithm used to generate the public key.
	PublicKeyCurve            fields.Field = "x509.public_key_curve"            // The curve used by the elliptic curve public key algorithm. This is algorithm specific.
	PublicKeyExponent         fields.Field = "x509.public_key_exponent"         // Exponent used to derive the public key. This is algorithm specific.
	PublicKeySize             fields.Field = "x509.public_key_size"             // The size of the public key space in bits.
	SerialNumber              fields.Field = "x509.serial_number"               // Unique serial number issued by the certificate authority.
	SignatureAlgorithm        fields.Field = "x509.signature_algorithm"         // Identifier for certificate signature algorithm.
	SubjectCommonName         fields.Field = "x509.subject.common_name"         // List of common names (CN) of subject.
	SubjectCountry            fields.Field = "x509.subject.country"             // List of country \(C) code
	SubjectDistinguishedName  fields.Field = "x509.subject.distinguished_name"  // Distinguished name (DN) of the certificate subject entity.
	SubjectLocality           fields.Field = "x509.subject.locality"            // List of locality names (L)
	SubjectOrganization       fields.Field = "x509.subject.organization"        // List of organizations (O) of subject.
	SubjectOrganizationalUnit fields.Field = "x509.subject.organizational_unit" // List of organizational units (OU) of subject.
	SubjectStateOrProvince    fields.Field = "x509.subject.state_or_province"   // List of state or province names (ST, S, or P)
	VersionNumber             fields.Field = "x509.version_number"              // Version of x509 format.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	AlternativeNames,
	IssuerCommonName,
	IssuerCountry,
	IssuerDistinguishedName,
	IssuerLocality,
	IssuerOrganization,
	IssuerOrganizationalUnit,
	IssuerStateOrProvince,
	NotAfter,
	NotBefore,
	PublicKeyAlgorithm,
	PublicKeyCurve,
	PublicKeyExponent,
	PublicKeySize,
	SerialNumber,
	SignatureAlgorithm,
	SubjectCommonName,
	SubjectCountry,
	SubjectDistinguishedName,
	SubjectLocality,
	SubjectOrganization,
	SubjectOrganizationalUnit,
	SubjectStateOrProvince,
	VersionNumber,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	AlternativeNames          fields.KeyWord
	IssuerCommonName          fields.KeyWord
	IssuerCountry             fields.KeyWord
	IssuerDistinguishedName   fields.KeyWord
	IssuerLocality            fields.KeyWord
	IssuerOrganization        fields.KeyWord
	IssuerOrganizationalUnit  fields.KeyWord
	IssuerStateOrProvince     fields.KeyWord
	NotAfter                  fields.Date
	NotBefore                 fields.Date
	PublicKeyAlgorithm        fields.KeyWord
	PublicKeyCurve            fields.KeyWord
	PublicKeyExponent         fields.Long
	PublicKeySize             fields.Long
	SerialNumber              fields.KeyWord
	SignatureAlgorithm        fields.KeyWord
	SubjectCommonName         fields.KeyWord
	SubjectCountry            fields.KeyWord
	SubjectDistinguishedName  fields.KeyWord
	SubjectLocality           fields.KeyWord
	SubjectOrganization       fields.KeyWord
	SubjectOrganizationalUnit fields.KeyWord
	SubjectStateOrProvince    fields.KeyWord
	VersionNumber             fields.KeyWord
}

var Types TypesType = TypesType{}
