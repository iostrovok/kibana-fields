package http

/*
	Fields related to HTTP activity. Use the url field set to store the url of the request.
*/

import (
	"github.com/iostrovok/kibana-fields/face"
)

// All available fields as constants
const (
	RequestBodyBytes    face.Field = "http.request.body.bytes"
	RequestBodyContent  face.Field = "http.request.body.content"
	RequestBytes        face.Field = "http.request.bytes"
	RequestID           face.Field = "http.request.id"
	RequestMethod       face.Field = "http.request.method"
	RequestMimeType     face.Field = "http.request.mime_type"
	RequestReferrer     face.Field = "http.request.referrer"
	ResponseBodyBytes   face.Field = "http.response.body.bytes"
	ResponseBodyContent face.Field = "http.response.body.content"
	ResponseBytes       face.Field = "http.response.bytes"
	ResponseMimeType    face.Field = "http.response.mime_type"
	ResponseStatusCode  face.Field = "http.response.status_code"
	Version             face.Field = "http.version"
)

// All package constants as list
var Fields = []face.Field{
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

// Types describes kibana types of fields
var Types = map[face.Field]face.Type{
	RequestBodyBytes:    face.Long,
	RequestBodyContent:  face.Wildcard,
	RequestBytes:        face.KeyWord,
	RequestID:           face.KeyWord,
	RequestMethod:       face.KeyWord,
	RequestMimeType:     face.KeyWord,
	RequestReferrer:     face.KeyWord,
	ResponseBodyBytes:   face.Long,
	ResponseBodyContent: face.Wildcard,
	ResponseBytes:       face.Long,
	ResponseMimeType:    face.KeyWord,
	ResponseStatusCode:  face.Long,
	Version:             face.KeyWord,
}
