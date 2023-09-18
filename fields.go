// https://www.elastic.co/guide/en/ecs/master/ecs-field-reference.html
package fields

/*
	The package contains the fields which are reserved in Kibana.
*/

import (
	"github.com/iostrovok/kibana-fields/agent"
	"github.com/iostrovok/kibana-fields/base"
	"github.com/iostrovok/kibana-fields/client"
	"github.com/iostrovok/kibana-fields/cloud"
	"github.com/iostrovok/kibana-fields/error"
	"github.com/iostrovok/kibana-fields/event"
	"github.com/iostrovok/kibana-fields/face"
	"github.com/iostrovok/kibana-fields/file"
	"github.com/iostrovok/kibana-fields/hash"
	"github.com/iostrovok/kibana-fields/http"
	"github.com/iostrovok/kibana-fields/log"
	"github.com/iostrovok/kibana-fields/service"
	"github.com/iostrovok/kibana-fields/tracing"
	"github.com/iostrovok/kibana-fields/url"
	"github.com/iostrovok/kibana-fields/user"
	"github.com/iostrovok/kibana-fields/user_agent"
)

// AllFields includes all fields which are used in the subpackages.
var AllFields []face.Field

// Check equals the AllFields but is provided as hash for fast checking.
var Check map[string]bool
var Types map[face.Field]face.Type

func init() {
	AllFields = make([]face.Field, 0)
	Types = map[face.Field]face.Type{}

	AllFields = append(AllFields, agent.Fields...)
	AllFields = append(AllFields, base.Fields...)
	AllFields = append(AllFields, client.Fields...)
	AllFields = append(AllFields, cloud.Fields...)
	AllFields = append(AllFields, error.Fields...)
	AllFields = append(AllFields, event.Fields...)
	AllFields = append(AllFields, file.Fields...)
	AllFields = append(AllFields, hash.Fields...)
	AllFields = append(AllFields, http.Fields...)
	AllFields = append(AllFields, log.Fields...)
	AllFields = append(AllFields, service.Fields...)
	AllFields = append(AllFields, tracing.Fields...)
	AllFields = append(AllFields, url.Fields...)
	AllFields = append(AllFields, user.Fields...)
	AllFields = append(AllFields, user_agent.Fields...)

	Check = make(map[string]bool, 0)
	for _, v := range AllFields {
		Check[v.String()] = true
	}

	Types = merge(Types, agent.Types)
	Types = merge(Types, base.Types)
	Types = merge(Types, client.Types)
	Types = merge(Types, cloud.Types)
	Types = merge(Types, error.Types)
	Types = merge(Types, event.Types)
	Types = merge(Types, file.Types)
	Types = merge(Types, hash.Types)
	Types = merge(Types, http.Types)
	Types = merge(Types, log.Types)
	Types = merge(Types, service.Types)
	Types = merge(Types, tracing.Types)
	Types = merge(Types, url.Types)
	Types = merge(Types, user.Types)
	Types = merge(Types, user_agent.Types)
}

func merge(a, b map[face.Field]face.Type) map[face.Field]face.Type {
	for k, v := range b {
		a[k] = v
	}

	return a
}
