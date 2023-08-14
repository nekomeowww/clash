package constant

const (
	DomainTypeString        RuleTypeString = "DOMAIN"
	DomainSuffixTypeString  RuleTypeString = "DOMAIN-SUFFIX"
	DomainKeywordTypeString RuleTypeString = "DOMAIN-KEYWORD"
	GeoIPTypeString         RuleTypeString = "GEOIP"
	IPCIDRTypeString        RuleTypeString = "IP-CIDR"
	IPCIDR6TypeString       RuleTypeString = "IP-CIDR6"
	SrcIPCIDRTypeString     RuleTypeString = "SRC-IP-CIDR"
	SrcPortTypeString       RuleTypeString = "SRC-PORT"
	DstPortTypeString       RuleTypeString = "DST-PORT"
	InboundPortTypeString   RuleTypeString = "INBOUND-PORT"
	ProcessNameTypeString   RuleTypeString = "PROCESS-NAME"
	ProcessPathTypeString   RuleTypeString = "PROCESS-PATH"
	IPSetTypeString         RuleTypeString = "IPSET"
	RuleSetTypeString       RuleTypeString = "RULE-SET"
	ScriptTypeString        RuleTypeString = "SCRIPT"
	MatchTypeString         RuleTypeString = "MATCH"
)

// Rule Config Type String represents a rule type in configuration files.
type RuleTypeString string

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
	switch rt {
	case Domain:
		return "Domain"
	case DomainSuffix:
		return "DomainSuffix"
	case DomainKeyword:
		return "DomainKeyword"
	case GEOIP:
		return "GeoIP"
	case IPCIDR:
		return "IPCIDR"
	case SrcIPCIDR:
		return "SrcIPCIDR"
	case SrcPort:
		return "SrcPort"
	case DstPort:
		return "DstPort"
	case InboundPort:
		return "InboundPort"
	case Process:
		return "Process"
	case ProcessPath:
		return "ProcessPath"
	case IPSet:
		return "IPSet"
	case MATCH:
		return "Match"
	default:
		return "Unknown"
	}
}

type Rule interface {
	RuleType() RuleType
	Match(metadata *Metadata) bool
	Adapter() string
	Payload() string
	ShouldResolveIP() bool
	ShouldFindProcess() bool
}
