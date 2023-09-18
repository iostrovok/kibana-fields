package file

/*
	A file is defined as a set of information that has been created on, or has existed on a filesystem.

	File objects can be associated with host events, network events, and/or file events
	(e.g., those produced by File Integrity Monitoring [FIM] products or services).
	File fields provide details about the affected file associated with the event or metric.
*/

import (
	"github.com/iostrovok/kibana-fields/face"
)

// All available fields as constants
const (
	Accessed    face.Field = "file.accessed"
	Attributes  face.Field = "file.attributes"
	Created     face.Field = "file.created"
	Ctime       face.Field = "file.ctime"
	Device      face.Field = "file.device"
	Directory   face.Field = "file.directory"
	DriveLetter face.Field = "file.drive_letter"
	Extension   face.Field = "file.extension"
	ForkName    face.Field = "file.fork_name"
	Gid         face.Field = "file.gid"
	Group       face.Field = "file.group"
	Inode       face.Field = "file.inode"
	MimeYype    face.Field = "file.mime_type"
	Mode        face.Field = "file.mode"
	Mtime       face.Field = "file.mtime"
	Name        face.Field = "file.name"
	Owner       face.Field = "file.owner"
	Path        face.Field = "file.path"
	Size        face.Field = "file.size"
	TargetPath  face.Field = "file.target_path"
	Type        face.Field = "file.type"
	Uid         face.Field = "file.uid"
)

// All package constants as list
var Fields = []face.Field{
	Accessed,
	Attributes,
	Created,
	Ctime,
	Device,
	Directory,
	DriveLetter,
	Extension,
	ForkName,
	Gid,
	Group,
	Inode,
	MimeYype,
	Mode,
	Mtime,
	Name,
	Owner,
	Path,
	Size,
	TargetPath,
	Type,
	Uid,
}

// Types describes kibana types of fields
var Types = map[face.Field]face.Type{
	Accessed:    face.Date,
	Attributes:  face.KeyWord,
	Created:     face.Date,
	Ctime:       face.Date,
	Device:      face.KeyWord,
	Directory:   face.KeyWord,
	DriveLetter: face.KeyWord,
	Extension:   face.KeyWord,
	ForkName:    face.KeyWord,
	Gid:         face.KeyWord,
	Group:       face.KeyWord,
	Inode:       face.KeyWord,
	MimeYype:    face.KeyWord,
	Mode:        face.KeyWord,
	Mtime:       face.Date,
	Name:        face.KeyWord,
	Owner:       face.KeyWord,
	Path:        face.KeyWord,
	Size:        face.Long,
	TargetPath:  face.MultiFields,
	Type:        face.KeyWord,
	Uid:         face.KeyWord,
}
