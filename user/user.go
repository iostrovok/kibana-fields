package user

/*
	The user fields describe information about the user that is relevant to the event.
	Fields can have one entry or multiple entries.
	If a user has more than one id, provide an array that includes all of them.
*/

import "github.com/iostrovok/kibana-fields/face"

// All available fields as constants
const (
	Domain   face.Field = "user.domain"    // Name of the directory the user is a member of. type: keyword
	Email    face.Field = "user.email"     // User email address. type: keyword
	FullName face.Field = "user.full_name" // User’s full name, if available. type: keyword
	Hash     face.Field = "user.hash"      // Unique user hash to correlate information for a user in anonymized form. type: keyword
	ID       face.Field = "user.id"        // One or multiple unique identifiers of the user. type: keyword
	Name     face.Field = "user.name"      // Short name or login of the user. type: keyword
	Roles    face.Field = "user.roles"     // Array of user roles at the time of the event.
)

// All package constants as list
var Fields = []face.Field{
	Domain,
	Email,
	FullName,
	Hash,
	ID,
	Name,
	Roles,
}

// Types describes kibana types of fields
var Types = map[face.Field]face.Type{
	Domain:   face.KeyWord,
	Email:    face.KeyWord,
	FullName: face.KeyWord,
	Hash:     face.KeyWord,
	ID:       face.KeyWord,
	Name:     face.KeyWord,
	Roles:    face.KeyWord,
}
