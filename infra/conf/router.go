package conf

import (
	"encoding/json"
	"strings"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/geodata"
)

type RouterConfig struct {
	RuleList       []json.RawMessage `json:"rules"`
	DomainStrategy *string           `json:"domainStrategy"`
}

func (c *RouterConfig) getDomainStrategy() router.Config_DomainStrategy {
	ds := ""
	if c.DomainStrategy != nil {
		ds = *c.DomainStrategy
	}

	switch strings.ToLower(ds) {
	case "ipifnonmatch":
		return router.Config_IpIfNonMatch
	case "ipondemand":
		return router.Config_IpOnDemand
	default:
		return router.Config_AsIs
	}
}

func (c *RouterConfig) Build() (*router.Config, error) {
	config := new(router.Config)
	config.DomainStrategy = c.getDomainStrategy()

	var rawRuleList []json.RawMessage
	if c != nil {
		rawRuleList = c.RuleList
	}
	for _, rawRule := range rawRuleList {
		rule, err := parseRule(rawRule)
		if err != nil {
			return nil, err
		}
		config.Rule = append(config.Rule, rule)
	}

	return config, nil
}

type RouterRule struct {
	RuleTag     string `json:"ruleTag"`
	OutboundTag string `json:"outboundTag"`
	BalancerTag string `json:"balancerTag"`
}

func parseFieldRule(msg json.RawMessage) (*router.RoutingRule, error) {
	type RawFieldRule struct {
		RouterRule
		Domain     *StringList        `json:"domain"`
		Domains    *StringList        `json:"domains"`
		IP         *StringList        `json:"ip"`
		Port       *PortList          `json:"port"`
		Network    *NetworkList       `json:"network"`
		SourceIP   *StringList        `json:"sourceIP"`
		Source     *StringList        `json:"source"`
		SourcePort *PortList          `json:"sourcePort"`
		User       *StringList        `json:"user"`
		VlessRoute *PortList          `json:"vlessRoute"`
		InboundTag *StringList        `json:"inboundTag"`
		Protocols  *StringList        `json:"protocol"`
		Attributes map[string]string  `json:"attrs"`
		LocalIP    *StringList        `json:"localIP"`
		LocalPort  *PortList          `json:"localPort"`
		Process    *StringList        `json:"process"`
		LocalOS    *StringList        `json:"localOS"`
	}
	rawFieldRule := new(RawFieldRule)
	err := json.Unmarshal(msg, rawFieldRule)
	if err != nil {
		return nil, err
	}

	if len(rawFieldRule.BalancerTag) > 0 {
		return nil, errors.New("balancerTag is not supported in this slim build")
	}

	rule := new(router.RoutingRule)
	rule.RuleTag = rawFieldRule.RuleTag
	switch {
	case len(rawFieldRule.OutboundTag) > 0:
		rule.TargetTag = &router.RoutingRule_Tag{
			Tag: rawFieldRule.OutboundTag,
		}
	default:
		return nil, errors.New("outboundTag is not specified in routing rule")
	}

	if rawFieldRule.Domain != nil {
		rules, err := geodata.ParseDomainRules(*rawFieldRule.Domain, geodata.Domain_Substr)
		if err != nil {
			return nil, err
		}
		rule.Domain = rules
	}

	if rawFieldRule.Domains != nil {
		rules, err := geodata.ParseDomainRules(*rawFieldRule.Domains, geodata.Domain_Substr)
		if err != nil {
			return nil, err
		}
		rule.Domain = rules
	}

	if rawFieldRule.IP != nil {
		rules, err := geodata.ParseIPRules(*rawFieldRule.IP)
		if err != nil {
			return nil, err
		}
		rule.Ip = rules
	}

	if rawFieldRule.Port != nil {
		rule.PortList = rawFieldRule.Port.Build()
	}

	if rawFieldRule.Network != nil {
		rule.Networks = rawFieldRule.Network.Build()
	}

	if rawFieldRule.SourceIP == nil {
		rawFieldRule.SourceIP = rawFieldRule.Source
	}

	if rawFieldRule.SourceIP != nil {
		rules, err := geodata.ParseIPRules(*rawFieldRule.SourceIP)
		if err != nil {
			return nil, err
		}
		rule.SourceIp = rules
	}

	if rawFieldRule.SourcePort != nil {
		rule.SourcePortList = rawFieldRule.SourcePort.Build()
	}

	if rawFieldRule.LocalIP != nil {
		rules, err := geodata.ParseIPRules(*rawFieldRule.LocalIP)
		if err != nil {
			return nil, err
		}
		rule.LocalIp = rules
	}

	if rawFieldRule.LocalPort != nil {
		rule.LocalPortList = rawFieldRule.LocalPort.Build()
	}

	if rawFieldRule.User != nil {
		for _, s := range *rawFieldRule.User {
			rule.UserEmail = append(rule.UserEmail, s)
		}
	}

	if rawFieldRule.VlessRoute != nil {
		rule.VlessRouteList = rawFieldRule.VlessRoute.Build()
	}

	if rawFieldRule.InboundTag != nil {
		for _, s := range *rawFieldRule.InboundTag {
			rule.InboundTag = append(rule.InboundTag, s)
		}
	}

	if rawFieldRule.Protocols != nil {
		for _, s := range *rawFieldRule.Protocols {
			rule.Protocol = append(rule.Protocol, s)
		}
	}

	if len(rawFieldRule.Attributes) > 0 {
		rule.Attributes = rawFieldRule.Attributes
	}

	if rawFieldRule.Process != nil && len(*rawFieldRule.Process) > 0 {
		rule.Process = *rawFieldRule.Process
	}

	if rawFieldRule.LocalOS != nil && len(*rawFieldRule.LocalOS) > 0 {
		rule.LocalOs = *rawFieldRule.LocalOS
	}

	return rule, nil
}

func parseRule(msg json.RawMessage) (*router.RoutingRule, error) {
	rawRule := new(RouterRule)
	err := json.Unmarshal(msg, rawRule)
	if err != nil {
		return nil, errors.New("invalid router rule").Base(err)
	}

	fieldrule, err := parseFieldRule(msg)
	if err != nil {
		return nil, errors.New("invalid field rule").Base(err)
	}
	return fieldrule, nil
}
