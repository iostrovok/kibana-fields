package http

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	RequestBodyBytes    fields.Field = "http.request.body.bytes"    // Size in bytes of the request body.
	RequestBodyContent  fields.Field = "http.request.body.content"  // The full HTTP request body.
	RequestBytes        fields.Field = "http.request.bytes"         // Total size in bytes of the request (body and headers).
	RequestID           fields.Field = "http.request.id"            // HTTP request ID.
	RequestMethod       fields.Field = "http.request.method"        // HTTP request method.
	RequestMimeType     fields.Field = "http.request.mime_type"     // Mime type of the body of the request.
	RequestReferrer     fields.Field = "http.request.referrer"      // Referrer for this HTTP request.
	ResponseBodyBytes   fields.Field = "http.response.body.bytes"   // Size in bytes of the response body.
	ResponseBodyContent fields.Field = "http.response.body.content" // The full HTTP response body.
	ResponseBytes       fields.Field = "http.response.bytes"        // Total size in bytes of the response (body and headers).
	ResponseMimeType    fields.Field = "http.response.mime_type"    // Mime type of the body of the response.
	ResponseStatusCode  fields.Field = "http.response.status_code"  // HTTP response status code.
	Version             fields.Field = "http.version"               // HTTP version.

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	RequestBodyBytes,
	RequestBodyContent,
	RequestBytes,
	RequestID,
	RequestMethod,
	RequestMimeType,
	RequestReferrer,
	ResponseBodyBytes,
	ResponseBodyContent,
	ResponseBytes,
	ResponseMimeType,
	ResponseStatusCode,
	Version,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	RequestBodyBytes    fields.Long
	RequestBodyContent  fields.Wildcard
	RequestBytes        fields.Long
	RequestID           fields.KeyWord
	RequestMethod       fields.KeyWord
	RequestMimeType     fields.KeyWord
	RequestReferrer     fields.KeyWord
	ResponseBodyBytes   fields.Long
	ResponseBodyContent fields.Wildcard
	ResponseBytes       fields.Long
	ResponseMimeType    fields.KeyWord
	ResponseStatusCode  fields.Long
	Version             fields.KeyWord
}

var Types TypesType = TypesType{}
