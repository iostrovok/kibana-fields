package tls

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	Cipher                              fields.Field = "tls.cipher"                                  // String indicating the cipher used during the current connection.
	ClientCertificate                   fields.Field = "tls.client.certificate"                      // PEM-encoded stand-alone certificate offered by the client.
	ClientCertificateChain              fields.Field = "tls.client.certificate_chain"                // Array of PEM-encoded certificates that make up the certificate chain offered by the client.
	ClientHashMd5                       fields.Field = "tls.client.hash.md5"                         // Certificate fingerprint using the MD5 digest of DER-encoded version of certificate offered by the client.
	ClientHashSha1                      fields.Field = "tls.client.hash.sha1"                        // Certificate fingerprint using the SHA1 digest of DER-encoded version of certificate offered by the client.
	ClientHashSha256                    fields.Field = "tls.client.hash.sha256"                      // Certificate fingerprint using the SHA256 digest of DER-encoded version of certificate offered by the client.
	ClientIssuer                        fields.Field = "tls.client.issuer"                           // Distinguished name of subject of the issuer of the x.509 certificate presented by the client.
	ClientJa3                           fields.Field = "tls.client.ja3"                              // A hash that identifies clients based on how they perform an SSL/TLS handshake.
	ClientNotAfter                      fields.Field = "tls.client.not_after"                        // Date/Time indicating when client certificate is no longer considered valid.
	ClientNotBefore                     fields.Field = "tls.client.not_before"                       // Date/Time indicating when client certificate is first considered valid.
	ClientServerName                    fields.Field = "tls.client.server_name"                      // Hostname the client is trying to connect to. Also called the SNI.
	ClientSubject                       fields.Field = "tls.client.subject"                          // Distinguished name of subject of the x.509 certificate presented by the client.
	ClientSupportedCiphers              fields.Field = "tls.client.supported_ciphers"                // Array of ciphers offered by the client during the client hello.
	ClientX509AlternativeNames          fields.Field = "tls.client.x509.alternative_names"           // List of subject alternative names (SAN).
	ClientX509IssuerCommonName          fields.Field = "tls.client.x509.issuer.common_name"          // List of common name (CN) of issuing certificate authority.
	ClientX509IssuerCountry             fields.Field = "tls.client.x509.issuer.country"              // List of country \(C) codes
	ClientX509IssuerDistinguishedName   fields.Field = "tls.client.x509.issuer.distinguished_name"   // Distinguished name (DN) of issuing certificate authority.
	ClientX509IssuerLocality            fields.Field = "tls.client.x509.issuer.locality"             // List of locality names (L)
	ClientX509IssuerOrganization        fields.Field = "tls.client.x509.issuer.organization"         // List of organizations (O) of issuing certificate authority.
	ClientX509IssuerOrganizationalUnit  fields.Field = "tls.client.x509.issuer.organizational_unit"  // List of organizational units (OU) of issuing certificate authority.
	ClientX509IssuerStateOrProvince     fields.Field = "tls.client.x509.issuer.state_or_province"    // List of state or province names (ST, S, or P)
	ClientX509NotAfter                  fields.Field = "tls.client.x509.not_after"                   // Time at which the certificate is no longer considered valid.
	ClientX509NotBefore                 fields.Field = "tls.client.x509.not_before"                  // Time at which the certificate is first considered valid.
	ClientX509PublicKeyAlgorithm        fields.Field = "tls.client.x509.public_key_algorithm"        // Algorithm used to generate the public key.
	ClientX509PublicKeyCurve            fields.Field = "tls.client.x509.public_key_curve"            // The curve used by the elliptic curve public key algorithm. This is algorithm specific.
	ClientX509PublicKeyExponent         fields.Field = "tls.client.x509.public_key_exponent"         // Exponent used to derive the public key. This is algorithm specific.
	ClientX509PublicKeySize             fields.Field = "tls.client.x509.public_key_size"             // The size of the public key space in bits.
	ClientX509SerialNumber              fields.Field = "tls.client.x509.serial_number"               // Unique serial number issued by the certificate authority.
	ClientX509SignatureAlgorithm        fields.Field = "tls.client.x509.signature_algorithm"         // Identifier for certificate signature algorithm.
	ClientX509SubjectCommonName         fields.Field = "tls.client.x509.subject.common_name"         // List of common names (CN) of subject.
	ClientX509SubjectCountry            fields.Field = "tls.client.x509.subject.country"             // List of country \(C) code
	ClientX509SubjectDistinguishedName  fields.Field = "tls.client.x509.subject.distinguished_name"  // Distinguished name (DN) of the certificate subject entity.
	ClientX509SubjectLocality           fields.Field = "tls.client.x509.subject.locality"            // List of locality names (L)
	ClientX509SubjectOrganization       fields.Field = "tls.client.x509.subject.organization"        // List of organizations (O) of subject.
	ClientX509SubjectOrganizationalUnit fields.Field = "tls.client.x509.subject.organizational_unit" // List of organizational units (OU) of subject.
	ClientX509SubjectStateOrProvince    fields.Field = "tls.client.x509.subject.state_or_province"   // List of state or province names (ST, S, or P)
	ClientX509VersionNumber             fields.Field = "tls.client.x509.version_number"              // Version of x509 format.
	Curve                               fields.Field = "tls.curve"                                   // String indicating the curve used for the given cipher, when applicable.
	Established                         fields.Field = "tls.established"                             // Boolean flag indicating if the TLS negotiation was successful and transitioned to an encrypted tunnel.
	NextProtocol                        fields.Field = "tls.next_protocol"                           // String indicating the protocol being tunneled.
	Resumed                             fields.Field = "tls.resumed"                                 // Boolean flag indicating if this TLS connection was resumed from an existing TLS negotiation.
	ServerCertificate                   fields.Field = "tls.server.certificate"                      // PEM-encoded stand-alone certificate offered by the server.
	ServerCertificateChain              fields.Field = "tls.server.certificate_chain"                // Array of PEM-encoded certificates that make up the certificate chain offered by the server.
	ServerHashMd5                       fields.Field = "tls.server.hash.md5"                         // Certificate fingerprint using the MD5 digest of DER-encoded version of certificate offered by the server.
	ServerHashSha1                      fields.Field = "tls.server.hash.sha1"                        // Certificate fingerprint using the SHA1 digest of DER-encoded version of certificate offered by the server.
	ServerHashSha256                    fields.Field = "tls.server.hash.sha256"                      // Certificate fingerprint using the SHA256 digest of DER-encoded version of certificate offered by the server.
	ServerIssuer                        fields.Field = "tls.server.issuer"                           // Subject of the issuer of the x.509 certificate presented by the server.
	ServerJa3s                          fields.Field = "tls.server.ja3s"                             // A hash that identifies servers based on how they perform an SSL/TLS handshake.
	ServerNotAfter                      fields.Field = "tls.server.not_after"                        // Timestamp indicating when server certificate is no longer considered valid.
	ServerNotBefore                     fields.Field = "tls.server.not_before"                       // Timestamp indicating when server certificate is first considered valid.
	ServerSubject                       fields.Field = "tls.server.subject"                          // Subject of the x.509 certificate presented by the server.
	ServerX509AlternativeNames          fields.Field = "tls.server.x509.alternative_names"           // List of subject alternative names (SAN).
	ServerX509IssuerCommonName          fields.Field = "tls.server.x509.issuer.common_name"          // List of common name (CN) of issuing certificate authority.
	ServerX509IssuerCountry             fields.Field = "tls.server.x509.issuer.country"              // List of country \(C) codes
	ServerX509IssuerDistinguishedName   fields.Field = "tls.server.x509.issuer.distinguished_name"   // Distinguished name (DN) of issuing certificate authority.
	ServerX509IssuerLocality            fields.Field = "tls.server.x509.issuer.locality"             // List of locality names (L)
	ServerX509IssuerOrganization        fields.Field = "tls.server.x509.issuer.organization"         // List of organizations (O) of issuing certificate authority.
	ServerX509IssuerOrganizationalUnit  fields.Field = "tls.server.x509.issuer.organizational_unit"  // List of organizational units (OU) of issuing certificate authority.
	ServerX509IssuerStateOrProvince     fields.Field = "tls.server.x509.issuer.state_or_province"    // List of state or province names (ST, S, or P)
	ServerX509NotAfter                  fields.Field = "tls.server.x509.not_after"                   // Time at which the certificate is no longer considered valid.
	ServerX509NotBefore                 fields.Field = "tls.server.x509.not_before"                  // Time at which the certificate is first considered valid.
	ServerX509PublicKeyAlgorithm        fields.Field = "tls.server.x509.public_key_algorithm"        // Algorithm used to generate the public key.
	ServerX509PublicKeyCurve            fields.Field = "tls.server.x509.public_key_curve"            // The curve used by the elliptic curve public key algorithm. This is algorithm specific.
	ServerX509PublicKeyExponent         fields.Field = "tls.server.x509.public_key_exponent"         // Exponent used to derive the public key. This is algorithm specific.
	ServerX509PublicKeySize             fields.Field = "tls.server.x509.public_key_size"             // The size of the public key space in bits.
	ServerX509SerialNumber              fields.Field = "tls.server.x509.serial_number"               // Unique serial number issued by the certificate authority.
	ServerX509SignatureAlgorithm        fields.Field = "tls.server.x509.signature_algorithm"         // Identifier for certificate signature algorithm.
	ServerX509SubjectCommonName         fields.Field = "tls.server.x509.subject.common_name"         // List of common names (CN) of subject.
	ServerX509SubjectCountry            fields.Field = "tls.server.x509.subject.country"             // List of country \(C) code
	ServerX509SubjectDistinguishedName  fields.Field = "tls.server.x509.subject.distinguished_name"  // Distinguished name (DN) of the certificate subject entity.
	ServerX509SubjectLocality           fields.Field = "tls.server.x509.subject.locality"            // List of locality names (L)
	ServerX509SubjectOrganization       fields.Field = "tls.server.x509.subject.organization"        // List of organizations (O) of subject.
	ServerX509SubjectOrganizationalUnit fields.Field = "tls.server.x509.subject.organizational_unit" // List of organizational units (OU) of subject.
	ServerX509SubjectStateOrProvince    fields.Field = "tls.server.x509.subject.state_or_province"   // List of state or province names (ST, S, or P)
	ServerX509VersionNumber             fields.Field = "tls.server.x509.version_number"              // Version of x509 format.
	Version                             fields.Field = "tls.version"                                 // Numeric part of the version parsed from the original string.
	VersionProtocol                     fields.Field = "tls.version_protocol"                        // Normalized lowercase protocol name parsed from original string.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	Cipher,
	ClientCertificate,
	ClientCertificateChain,
	ClientHashMd5,
	ClientHashSha1,
	ClientHashSha256,
	ClientIssuer,
	ClientJa3,
	ClientNotAfter,
	ClientNotBefore,
	ClientServerName,
	ClientSubject,
	ClientSupportedCiphers,
	ClientX509AlternativeNames,
	ClientX509IssuerCommonName,
	ClientX509IssuerCountry,
	ClientX509IssuerDistinguishedName,
	ClientX509IssuerLocality,
	ClientX509IssuerOrganization,
	ClientX509IssuerOrganizationalUnit,
	ClientX509IssuerStateOrProvince,
	ClientX509NotAfter,
	ClientX509NotBefore,
	ClientX509PublicKeyAlgorithm,
	ClientX509PublicKeyCurve,
	ClientX509PublicKeyExponent,
	ClientX509PublicKeySize,
	ClientX509SerialNumber,
	ClientX509SignatureAlgorithm,
	ClientX509SubjectCommonName,
	ClientX509SubjectCountry,
	ClientX509SubjectDistinguishedName,
	ClientX509SubjectLocality,
	ClientX509SubjectOrganization,
	ClientX509SubjectOrganizationalUnit,
	ClientX509SubjectStateOrProvince,
	ClientX509VersionNumber,
	Curve,
	Established,
	NextProtocol,
	Resumed,
	ServerCertificate,
	ServerCertificateChain,
	ServerHashMd5,
	ServerHashSha1,
	ServerHashSha256,
	ServerIssuer,
	ServerJa3s,
	ServerNotAfter,
	ServerNotBefore,
	ServerSubject,
	ServerX509AlternativeNames,
	ServerX509IssuerCommonName,
	ServerX509IssuerCountry,
	ServerX509IssuerDistinguishedName,
	ServerX509IssuerLocality,
	ServerX509IssuerOrganization,
	ServerX509IssuerOrganizationalUnit,
	ServerX509IssuerStateOrProvince,
	ServerX509NotAfter,
	ServerX509NotBefore,
	ServerX509PublicKeyAlgorithm,
	ServerX509PublicKeyCurve,
	ServerX509PublicKeyExponent,
	ServerX509PublicKeySize,
	ServerX509SerialNumber,
	ServerX509SignatureAlgorithm,
	ServerX509SubjectCommonName,
	ServerX509SubjectCountry,
	ServerX509SubjectDistinguishedName,
	ServerX509SubjectLocality,
	ServerX509SubjectOrganization,
	ServerX509SubjectOrganizationalUnit,
	ServerX509SubjectStateOrProvince,
	ServerX509VersionNumber,
	Version,
	VersionProtocol,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	Cipher                              fields.Keyword
	ClientCertificate                   fields.Keyword
	ClientCertificateChain              fields.Keyword
	ClientHashMd5                       fields.Keyword
	ClientHashSha1                      fields.Keyword
	ClientHashSha256                    fields.Keyword
	ClientIssuer                        fields.Keyword
	ClientJa3                           fields.Keyword
	ClientNotAfter                      fields.Date
	ClientNotBefore                     fields.Date
	ClientServerName                    fields.Keyword
	ClientSubject                       fields.Keyword
	ClientSupportedCiphers              fields.Keyword
	ClientX509AlternativeNames          fields.Keyword
	ClientX509IssuerCommonName          fields.Keyword
	ClientX509IssuerCountry             fields.Keyword
	ClientX509IssuerDistinguishedName   fields.Keyword
	ClientX509IssuerLocality            fields.Keyword
	ClientX509IssuerOrganization        fields.Keyword
	ClientX509IssuerOrganizationalUnit  fields.Keyword
	ClientX509IssuerStateOrProvince     fields.Keyword
	ClientX509NotAfter                  fields.Date
	ClientX509NotBefore                 fields.Date
	ClientX509PublicKeyAlgorithm        fields.Keyword
	ClientX509PublicKeyCurve            fields.Keyword
	ClientX509PublicKeyExponent         fields.Long
	ClientX509PublicKeySize             fields.Long
	ClientX509SerialNumber              fields.Keyword
	ClientX509SignatureAlgorithm        fields.Keyword
	ClientX509SubjectCommonName         fields.Keyword
	ClientX509SubjectCountry            fields.Keyword
	ClientX509SubjectDistinguishedName  fields.Keyword
	ClientX509SubjectLocality           fields.Keyword
	ClientX509SubjectOrganization       fields.Keyword
	ClientX509SubjectOrganizationalUnit fields.Keyword
	ClientX509SubjectStateOrProvince    fields.Keyword
	ClientX509VersionNumber             fields.Keyword
	Curve                               fields.Keyword
	Established                         fields.Boolean
	NextProtocol                        fields.Keyword
	Resumed                             fields.Boolean
	ServerCertificate                   fields.Keyword
	ServerCertificateChain              fields.Keyword
	ServerHashMd5                       fields.Keyword
	ServerHashSha1                      fields.Keyword
	ServerHashSha256                    fields.Keyword
	ServerIssuer                        fields.Keyword
	ServerJa3s                          fields.Keyword
	ServerNotAfter                      fields.Date
	ServerNotBefore                     fields.Date
	ServerSubject                       fields.Keyword
	ServerX509AlternativeNames          fields.Keyword
	ServerX509IssuerCommonName          fields.Keyword
	ServerX509IssuerCountry             fields.Keyword
	ServerX509IssuerDistinguishedName   fields.Keyword
	ServerX509IssuerLocality            fields.Keyword
	ServerX509IssuerOrganization        fields.Keyword
	ServerX509IssuerOrganizationalUnit  fields.Keyword
	ServerX509IssuerStateOrProvince     fields.Keyword
	ServerX509NotAfter                  fields.Date
	ServerX509NotBefore                 fields.Date
	ServerX509PublicKeyAlgorithm        fields.Keyword
	ServerX509PublicKeyCurve            fields.Keyword
	ServerX509PublicKeyExponent         fields.Long
	ServerX509PublicKeySize             fields.Long
	ServerX509SerialNumber              fields.Keyword
	ServerX509SignatureAlgorithm        fields.Keyword
	ServerX509SubjectCommonName         fields.Keyword
	ServerX509SubjectCountry            fields.Keyword
	ServerX509SubjectDistinguishedName  fields.Keyword
	ServerX509SubjectLocality           fields.Keyword
	ServerX509SubjectOrganization       fields.Keyword
	ServerX509SubjectOrganizationalUnit fields.Keyword
	ServerX509SubjectStateOrProvince    fields.Keyword
	ServerX509VersionNumber             fields.Keyword
	Version                             fields.Keyword
	VersionProtocol                     fields.Keyword
}

var Types TypesType = TypesType{}
