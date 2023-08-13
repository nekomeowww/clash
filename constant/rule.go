package constant

// Rule Type String
const (
	DomainString        RuleTypeString = "Domain"
	DomainSuffixString  RuleTypeString = "DomainSuffix"
	DomainKeywordString RuleTypeString = "DomainKeyword"
	GeoIPString         RuleTypeString = "GeoIP"
	IPCIDRString        RuleTypeString = "IPCIDR"
	SrcIPCIDRString     RuleTypeString = "SrcIPCIDR"
	SrcPortString       RuleTypeString = "SrcPort"
	DstPortString       RuleTypeString = "DstPort"
	InboundPortString   RuleTypeString = "InboundPort"
	ProcessString       RuleTypeString = "Process"
	ProcessPathString   RuleTypeString = "ProcessPath"
	IPSetString         RuleTypeString = "IPSet"
	MatchString         RuleTypeString = "Match"
	UnknownString       RuleTypeString = "Unknown"
)

// Rule Type String represents a rule type, if integrating with configuration files, please use RuleConfigTypeString instead.
type RuleTypeString string

const (
	DomainConfigTypeString        RuleConfigTypeString = "DOMAIN"
	DomainSuffixConfigTypeString  RuleConfigTypeString = "DOMAIN-SUFFIX"
	DomainKeywordConfigTypeString RuleConfigTypeString = "DOMAIN-KEYWORD"
	GeoIPConfigTypeString         RuleConfigTypeString = "GEOIP"
	IPCIDRConfigTypeString        RuleConfigTypeString = "IP-CIDR"
	IPCIDR6ConfigTypeString       RuleConfigTypeString = "IP-CIDR6"
	SrcIPCIDRConfigTypeString     RuleConfigTypeString = "SRC-IP-CIDR"
	SrcPortConfigTypeString       RuleConfigTypeString = "SRC-PORT"
	DstPortConfigTypeString       RuleConfigTypeString = "DST-PORT"
	InboundPortConfigTypeString   RuleConfigTypeString = "INBOUND-PORT"
	ProcessNameConfigTypeString   RuleConfigTypeString = "PROCESS-NAME"
	ProcessPathConfigTypeString   RuleConfigTypeString = "PROCESS-PATH"
	IPSetConfigTypeString         RuleConfigTypeString = "IPSET"
	RuleSetConfigTypeString       RuleConfigTypeString = "RULE-SET"
	ScriptConfigTypeString        RuleConfigTypeString = "SCRIPT"
	MatchConfigTypeString         RuleConfigTypeString = "MATCH"
)

// Rule Config Type String represents a rule type in configuration files. Only reference this type instead of RuleTypeString when making integrate and processing with configuration files.
type RuleConfigTypeString string

// Rule Type
const (
	Domain RuleType = iota
	DomainSuffix
	DomainKeyword
	GEOIP
	IPCIDR
	SrcIPCIDR
	SrcPort
	DstPort
	InboundPort
	Process
	ProcessPath
	IPSet
	MATCH
)

type RuleType int

func (rt RuleType) String() string {
	return string(rt.RuleTypeString())
}

func (rts RuleType) RuleTypeString() RuleTypeString {
	switch rts {
	case Domain:
		return DomainString
	case DomainSuffix:
		return DomainSuffixString
	case DomainKeyword:
		return DomainKeywordString
	case GEOIP:
		return GeoIPString
	case IPCIDR:
		return IPCIDRString
	case SrcIPCIDR:
		return SrcIPCIDRString
	case SrcPort:
		return SrcPortString
	case DstPort:
		return DstPortString
	case InboundPort:
		return InboundPortString
	case Process:
		return ProcessString
	case ProcessPath:
		return ProcessPathString
	case IPSet:
		return IPSetString
	case MATCH:
		return MatchString
	default:
		return UnknownString
	}
}

type Rule interface {
	RuleType() RuleType
	RuleTypeString() RuleTypeString
	Match(metadata *Metadata) bool
	Adapter() string
	Payload() string
	ShouldResolveIP() bool
	ShouldFindProcess() bool
}
