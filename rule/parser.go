package rules

import (
	"fmt"

	C "github.com/Dreamacro/clash/constant"
)

func ParseRule(tp, payload, target string, params []string) (C.Rule, error) {
	var (
		parseErr error
		parsed   C.Rule
	)

	ruleConfigType := C.RuleTypeString(tp)

	switch ruleConfigType {
	case C.DomainTypeString:
		parsed = NewDomain(payload, target)
	case C.DomainSuffixTypeString:
		parsed = NewDomainSuffix(payload, target)
	case C.DomainKeywordTypeString:
		parsed = NewDomainKeyword(payload, target)
	case C.GeoIPTypeString:
		noResolve := HasNoResolve(params)
		parsed = NewGEOIP(payload, target, noResolve)
	case C.IPCIDRTypeString, C.IPCIDR6TypeString:
		noResolve := HasNoResolve(params)
		parsed, parseErr = NewIPCIDR(payload, target, WithIPCIDRNoResolve(noResolve))
	case C.SrcIPCIDRTypeString:
		parsed, parseErr = NewIPCIDR(payload, target, WithIPCIDRSourceIP(true), WithIPCIDRNoResolve(true))
	case C.SrcPortTypeString:
		parsed, parseErr = NewPort(payload, target, PortTypeSrc)
	case C.DstPortTypeString:
		parsed, parseErr = NewPort(payload, target, PortTypeDest)
	case C.InboundPortTypeString:
		parsed, parseErr = NewPort(payload, target, PortTypeInbound)
	case C.ProcessNameTypeString:
		parsed, parseErr = NewProcess(payload, target, true)
	case C.ProcessPathTypeString:
		parsed, parseErr = NewProcess(payload, target, false)
	case C.IPSetTypeString:
		noResolve := HasNoResolve(params)
		parsed, parseErr = NewIPSet(payload, target, noResolve)
	case C.MatchTypeString:
		parsed = NewMatch(target)
	case C.RuleSetTypeString, C.ScriptTypeString:
		parseErr = fmt.Errorf("unsupported rule type %s", tp)
	default:
		parseErr = fmt.Errorf("unsupported rule type %s", tp)
	}

	return parsed, parseErr
}
