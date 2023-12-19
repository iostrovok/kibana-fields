package fields_test

import (
	"testing"

	_ "github.com/iostrovok/kibana-fields/agent"
	_ "github.com/iostrovok/kibana-fields/as"
	_ "github.com/iostrovok/kibana-fields/base"
	_ "github.com/iostrovok/kibana-fields/client"
	_ "github.com/iostrovok/kibana-fields/cloud"
	_ "github.com/iostrovok/kibana-fields/code_signature"
	_ "github.com/iostrovok/kibana-fields/container"
	_ "github.com/iostrovok/kibana-fields/data_stream"
	_ "github.com/iostrovok/kibana-fields/destination"
	_ "github.com/iostrovok/kibana-fields/device"
	_ "github.com/iostrovok/kibana-fields/dll"
	_ "github.com/iostrovok/kibana-fields/dns"
	_ "github.com/iostrovok/kibana-fields/ecs"
	_ "github.com/iostrovok/kibana-fields/elf"
	_ "github.com/iostrovok/kibana-fields/email"
	_ "github.com/iostrovok/kibana-fields/error"
	_ "github.com/iostrovok/kibana-fields/event"
	_ "github.com/iostrovok/kibana-fields/faas"
	_ "github.com/iostrovok/kibana-fields/file"
	_ "github.com/iostrovok/kibana-fields/geo"
	_ "github.com/iostrovok/kibana-fields/group"
	_ "github.com/iostrovok/kibana-fields/hash"
	_ "github.com/iostrovok/kibana-fields/host"
	_ "github.com/iostrovok/kibana-fields/http"
	_ "github.com/iostrovok/kibana-fields/iface"
	_ "github.com/iostrovok/kibana-fields/log"
	_ "github.com/iostrovok/kibana-fields/macho"
	_ "github.com/iostrovok/kibana-fields/network"
	_ "github.com/iostrovok/kibana-fields/observer"
	_ "github.com/iostrovok/kibana-fields/orchestrator"
	_ "github.com/iostrovok/kibana-fields/organization"
	_ "github.com/iostrovok/kibana-fields/os"
	_ "github.com/iostrovok/kibana-fields/pe"
	_ "github.com/iostrovok/kibana-fields/pkg"
	_ "github.com/iostrovok/kibana-fields/process"
	_ "github.com/iostrovok/kibana-fields/registry"
	_ "github.com/iostrovok/kibana-fields/related"
	_ "github.com/iostrovok/kibana-fields/risk"
	_ "github.com/iostrovok/kibana-fields/rule"
	_ "github.com/iostrovok/kibana-fields/server"
	_ "github.com/iostrovok/kibana-fields/service"
	_ "github.com/iostrovok/kibana-fields/source"
	_ "github.com/iostrovok/kibana-fields/threat"
	_ "github.com/iostrovok/kibana-fields/tls"
	_ "github.com/iostrovok/kibana-fields/tracing"
	_ "github.com/iostrovok/kibana-fields/url"
	_ "github.com/iostrovok/kibana-fields/user"
	_ "github.com/iostrovok/kibana-fields/user_agent"
	_ "github.com/iostrovok/kibana-fields/vlan"
	_ "github.com/iostrovok/kibana-fields/vulnerability"
	_ "github.com/iostrovok/kibana-fields/x509"
)

func TestSyntax(t *testing.T) {
	t.Log("TestSyntax")
}