package check

/*
	The package contains the fields which are reserved in Kibana.
*/

import (
	"github.com/iostrovok/kibana-fields"

	"github.com/iostrovok/kibana-fields/x/agent"
	"github.com/iostrovok/kibana-fields/x/as"
	"github.com/iostrovok/kibana-fields/x/base"
	"github.com/iostrovok/kibana-fields/x/client"
	"github.com/iostrovok/kibana-fields/x/cloud"
	"github.com/iostrovok/kibana-fields/x/code_signature"
	"github.com/iostrovok/kibana-fields/x/container"
	"github.com/iostrovok/kibana-fields/x/data_stream"
	"github.com/iostrovok/kibana-fields/x/destination"
	"github.com/iostrovok/kibana-fields/x/device"
	"github.com/iostrovok/kibana-fields/x/dll"
	"github.com/iostrovok/kibana-fields/x/dns"
	"github.com/iostrovok/kibana-fields/x/ecs"
	"github.com/iostrovok/kibana-fields/x/elf"
	"github.com/iostrovok/kibana-fields/x/email"
	"github.com/iostrovok/kibana-fields/x/error"
	"github.com/iostrovok/kibana-fields/x/event"
	"github.com/iostrovok/kibana-fields/x/faas"
	"github.com/iostrovok/kibana-fields/x/file"
	"github.com/iostrovok/kibana-fields/x/geo"
	"github.com/iostrovok/kibana-fields/x/group"
	"github.com/iostrovok/kibana-fields/x/hash"
	"github.com/iostrovok/kibana-fields/x/host"
	"github.com/iostrovok/kibana-fields/x/http"
	"github.com/iostrovok/kibana-fields/x/iface"
	"github.com/iostrovok/kibana-fields/x/log"
	"github.com/iostrovok/kibana-fields/x/macho"
	"github.com/iostrovok/kibana-fields/x/network"
	"github.com/iostrovok/kibana-fields/x/observer"
	"github.com/iostrovok/kibana-fields/x/orchestrator"
	"github.com/iostrovok/kibana-fields/x/organization"
	"github.com/iostrovok/kibana-fields/x/os"
	"github.com/iostrovok/kibana-fields/x/pe"
	"github.com/iostrovok/kibana-fields/x/pkg"
	"github.com/iostrovok/kibana-fields/x/process"
	"github.com/iostrovok/kibana-fields/x/registry"
	"github.com/iostrovok/kibana-fields/x/related"
	"github.com/iostrovok/kibana-fields/x/risk"
	"github.com/iostrovok/kibana-fields/x/rule"
	"github.com/iostrovok/kibana-fields/x/server"
	"github.com/iostrovok/kibana-fields/x/service"
	"github.com/iostrovok/kibana-fields/x/source"
	"github.com/iostrovok/kibana-fields/x/threat"
	"github.com/iostrovok/kibana-fields/x/tls"
	"github.com/iostrovok/kibana-fields/x/tracing"
	"github.com/iostrovok/kibana-fields/x/url"
	"github.com/iostrovok/kibana-fields/x/user"
	"github.com/iostrovok/kibana-fields/x/user_agent"
	"github.com/iostrovok/kibana-fields/x/vlan"
	"github.com/iostrovok/kibana-fields/x/volume"
	"github.com/iostrovok/kibana-fields/x/vulnerability"
	"github.com/iostrovok/kibana-fields/x/x509"
)

// AllFields includes all fields which are used in the subpackages.
var AllFields []fields.Field

// Check equals the AllFields but is provided as hash for fast checking.
var Check map[string]bool

func init() {
	AllFields = make([]fields.Field, 0)

	AllFields = append(AllFields, agent.Fields...)
	AllFields = append(AllFields, as.Fields...)
	AllFields = append(AllFields, base.Fields...)
	AllFields = append(AllFields, client.Fields...)
	AllFields = append(AllFields, cloud.Fields...)
	AllFields = append(AllFields, code_signature.Fields...)
	AllFields = append(AllFields, container.Fields...)
	AllFields = append(AllFields, data_stream.Fields...)
	AllFields = append(AllFields, destination.Fields...)
	AllFields = append(AllFields, device.Fields...)
	AllFields = append(AllFields, dll.Fields...)
	AllFields = append(AllFields, dns.Fields...)
	AllFields = append(AllFields, ecs.Fields...)
	AllFields = append(AllFields, elf.Fields...)
	AllFields = append(AllFields, email.Fields...)
	AllFields = append(AllFields, error.Fields...)
	AllFields = append(AllFields, event.Fields...)
	AllFields = append(AllFields, faas.Fields...)
	AllFields = append(AllFields, file.Fields...)
	AllFields = append(AllFields, geo.Fields...)
	AllFields = append(AllFields, group.Fields...)
	AllFields = append(AllFields, hash.Fields...)
	AllFields = append(AllFields, host.Fields...)
	AllFields = append(AllFields, http.Fields...)
	AllFields = append(AllFields, iface.Fields...)
	AllFields = append(AllFields, log.Fields...)
	AllFields = append(AllFields, macho.Fields...)
	AllFields = append(AllFields, network.Fields...)
	AllFields = append(AllFields, observer.Fields...)
	AllFields = append(AllFields, orchestrator.Fields...)
	AllFields = append(AllFields, organization.Fields...)
	AllFields = append(AllFields, os.Fields...)
	AllFields = append(AllFields, pkg.Fields...)
	AllFields = append(AllFields, pe.Fields...)
	AllFields = append(AllFields, process.Fields...)
	AllFields = append(AllFields, registry.Fields...)
	AllFields = append(AllFields, related.Fields...)
	AllFields = append(AllFields, risk.Fields...)
	AllFields = append(AllFields, rule.Fields...)
	AllFields = append(AllFields, server.Fields...)
	AllFields = append(AllFields, service.Fields...)
	AllFields = append(AllFields, source.Fields...)
	AllFields = append(AllFields, threat.Fields...)
	AllFields = append(AllFields, tls.Fields...)
	AllFields = append(AllFields, tracing.Fields...)
	AllFields = append(AllFields, url.Fields...)
	AllFields = append(AllFields, user.Fields...)
	AllFields = append(AllFields, user_agent.Fields...)
	AllFields = append(AllFields, vlan.Fields...)
	AllFields = append(AllFields, volume.Fields...)
	AllFields = append(AllFields, vulnerability.Fields...)
	AllFields = append(AllFields, x509.Fields...)

	Check = make(map[string]bool, 0)
	for _, v := range AllFields {
		Check[v.String()] = true
	}
}
