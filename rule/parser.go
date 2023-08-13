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

	ruleConfigType := C.RuleConfigTypeString(tp)

	switch ruleConfigType {
	case C.DomainConfigTypeString:
		parsed = NewDomain(payload, target)
	case C.DomainSuffixConfigTypeString:
		parsed = NewDomainSuffix(payload, target)
	case C.DomainKeywordConfigTypeString:
		parsed = NewDomainKeyword(payload, target)
	case C.GeoIPConfigTypeString:
		noResolve := HasNoResolve(params)
		parsed = NewGEOIP(payload, target, noResolve)
	case C.IPCIDRConfigTypeString, C.IPCIDR6ConfigTypeString:
		noResolve := HasNoResolve(params)
		parsed, parseErr = NewIPCIDR(payload, target, WithIPCIDRNoResolve(noResolve))
	case C.SrcIPCIDRConfigTypeString:
		parsed, parseErr = NewIPCIDR(payload, target, WithIPCIDRSourceIP(true), WithIPCIDRNoResolve(true))
	case C.SrcPortConfigTypeString:
		parsed, parseErr = NewPort(payload, target, PortTypeSrc)
	case C.DstPortConfigTypeString:
		parsed, parseErr = NewPort(payload, target, PortTypeDest)
	case C.InboundPortConfigTypeString:
		parsed, parseErr = NewPort(payload, target, PortTypeInbound)
	case C.ProcessNameConfigTypeString:
		parsed, parseErr = NewProcess(payload, target, true)
	case C.ProcessPathConfigTypeString:
		parsed, parseErr = NewProcess(payload, target, false)
	case C.IPSetConfigTypeString:
		noResolve := HasNoResolve(params)
		parsed, parseErr = NewIPSet(payload, target, noResolve)
	case C.MatchConfigTypeString:
		parsed = NewMatch(target)
	case C.RuleSetConfigTypeString, C.ScriptConfigTypeString:
		parseErr = fmt.Errorf("unsupported rule type %s", tp)
	default:
		parseErr = fmt.Errorf("unsupported rule type %s", tp)
	}

	return parsed, parseErr
}
