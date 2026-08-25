package conf_test

import (
	"encoding/json"
	"testing"
	_ "unsafe"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	. "github.com/xtls/xray-core/infra/conf"

	"google.golang.org/protobuf/proto"
)

func TestRouterConfig(t *testing.T) {
	createParser := func() func(string) (proto.Message, error) {
		return func(s string) (proto.Message, error) {
			config := new(RouterConfig)
			if err := json.Unmarshal([]byte(s), config); err != nil {
				return nil, err
			}
			return config.Build()
		}
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"domainStrategy": "AsIs",
				"rules": [
					{
						"domain": [
							"baidu.com",
							"qq.com"
						],
						"outboundTag": "direct"
					},
					{
						"ip": [
							"10.0.0.0/8",
							"::1/128"
						],
						"outboundTag": "test"
					},{
						"port": "53, 443, 1000-2000",
						"outboundTag": "test"
					},{
						"port": 123,
						"outboundTag": "test"
					}
				]
			}`,
			Parser: createParser(),
			Output: &router.Config{
				DomainStrategy: router.Config_AsIs,
				Rule: []*router.RoutingRule{
					{
						Domain: []*geodata.DomainRule{
							{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Substr, Value: "baidu.com"}}},
							{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Substr, Value: "qq.com"}}},
						},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "direct",
						},
					},
					{
						Ip: []*geodata.IPRule{
							{
								Value: &geodata.IPRule_Custom{
									Custom: &geodata.CIDRRule{
										Cidr: &geodata.CIDR{Ip: []byte{10, 0, 0, 0}, Prefix: 8},
									},
								},
							},
							{
								Value: &geodata.IPRule_Custom{
									Custom: &geodata.CIDRRule{
										Cidr: &geodata.CIDR{Ip: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, Prefix: 128},
									},
								},
							},
						},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "test",
						},
					},
					{
						PortList: &net.PortList{
							Range: []*net.PortRange{
								{From: 53, To: 53},
								{From: 443, To: 443},
								{From: 1000, To: 2000},
							},
						},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "test",
						},
					},
					{
						PortList: &net.PortList{
							Range: []*net.PortRange{
								{From: 123, To: 123},
							},
						},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "test",
						},
					},
				},
			},
		},
		{
			Input: `{
				"domainStrategy": "IPIfNonMatch",
				"rules": [
					{
						"domain": [
							"baidu.com",
							"qq.com"
						],
						"outboundTag": "direct"
					},
					{
						"ip": [
							"10.0.0.0/8",
							"::1/128"
						],
						"outboundTag": "test"
					}
				]
			}`,
			Parser: createParser(),
			Output: &router.Config{
				DomainStrategy: router.Config_IpIfNonMatch,
				Rule: []*router.RoutingRule{
					{
						Domain: []*geodata.DomainRule{
							{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Substr, Value: "baidu.com"}}},
							{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Substr, Value: "qq.com"}}},
						},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "direct",
						},
					},
					{
						Ip: []*geodata.IPRule{
							{
								Value: &geodata.IPRule_Custom{
									Custom: &geodata.CIDRRule{
										Cidr: &geodata.CIDR{Ip: []byte{10, 0, 0, 0}, Prefix: 8},
									},
								},
							},
							{
								Value: &geodata.IPRule_Custom{
									Custom: &geodata.CIDRRule{
										Cidr: &geodata.CIDR{Ip: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, Prefix: 128},
									},
								},
							},
						},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "test",
						},
					},
				},
			},
		},
	})
}
