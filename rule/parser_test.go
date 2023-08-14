package rules

import (
	"errors"
	"fmt"
	"testing"

	C "github.com/Dreamacro/clash/constant"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRule(t *testing.T) {
	type testCase struct {
		tp            C.RuleTypeString
		payload       string
		target        string
		params        []string
		expectedRule  C.Rule
		expectedError error
	}

	policy := "DIRECT"

	testCases := []testCase{
		{
			tp:           C.DomainTypeString,
			payload:      "example.com",
			target:       policy,
			expectedRule: NewDomain("example.com", policy),
		},
		{
			tp:           C.DomainSuffixTypeString,
			payload:      "example.com",
			target:       policy,
			expectedRule: NewDomainSuffix("example.com", policy),
		},
		{
			tp:           C.DomainKeywordTypeString,
			payload:      "example.com",
			target:       policy,
			expectedRule: NewDomainKeyword("example.com", policy),
		},
		{
			tp:      C.GeoIPTypeString,
			payload: "CN",
			target:  policy, params: []string{noResolve},
			expectedRule: NewGEOIP("CN", policy, true),
		},
		{
			tp:           C.IPCIDRTypeString,
			payload:      "127.0.0.0/8",
			target:       policy,
			expectedRule: lo.Must(NewIPCIDR("127.0.0.0/8", policy, WithIPCIDRNoResolve(false))),
		},
		{
			tp:      C.IPCIDRTypeString,
			payload: "127.0.0.0/8",
			target:  policy, params: []string{noResolve},
			expectedRule: lo.Must(NewIPCIDR("127.0.0.0/8", policy, WithIPCIDRNoResolve(true))),
		},
		{
			tp:           C.IPCIDR6TypeString,
			payload:      "2001:db8::/32",
			target:       policy,
			expectedRule: lo.Must(NewIPCIDR("2001:db8::/32", policy, WithIPCIDRNoResolve(false))),
		},
		{
			tp:      C.IPCIDR6TypeString,
			payload: "2001:db8::/32",
			target:  policy, params: []string{noResolve},
			expectedRule: lo.Must(NewIPCIDR("2001:db8::/32", policy, WithIPCIDRNoResolve(true))),
		},
		{
			tp:           C.SrcIPCIDRTypeString,
			payload:      "192.168.1.201/32",
			target:       policy,
			expectedRule: lo.Must(NewIPCIDR("192.168.1.201/32", policy, WithIPCIDRSourceIP(true), WithIPCIDRNoResolve(true))),
		},
		{
			tp:           C.SrcPortTypeString,
			payload:      "80",
			target:       policy,
			expectedRule: lo.Must(NewPort("80", policy, PortTypeSrc)),
		},
		{
			tp:           C.DstPortTypeString,
			payload:      "80",
			target:       policy,
			expectedRule: lo.Must(NewPort("80", policy, PortTypeDest)),
		},
		{
			tp:           C.InboundPortTypeString,
			payload:      "80",
			target:       policy,
			expectedRule: lo.Must(NewPort("80", policy, PortTypeInbound)),
		},
		{
			tp:           C.ProcessNameTypeString,
			payload:      "example.exe",
			target:       policy,
			expectedRule: lo.Must(NewProcess("example.exe", policy, true)),
		},
		{
			tp:           C.ProcessPathTypeString,
			payload:      "C:\\Program Files\\example.exe",
			target:       policy,
			expectedRule: lo.Must(NewProcess("C:\\Program Files\\example.exe", policy, false)),
		},
		{
			tp:           C.ProcessPathTypeString,
			payload:      "/opt/example/example",
			target:       policy,
			expectedRule: lo.Must(NewProcess("/opt/example/example", policy, false)),
		},
		{
			tp:           C.IPSetTypeString,
			payload:      "example",
			target:       policy,
			expectedRule: lo.Must(NewIPSet("example", policy, true)),
		},
		{
			tp:      C.IPSetTypeString,
			payload: "example",
			target:  policy, params: []string{noResolve},
			expectedRule: lo.Must(NewIPSet("example", policy, false)),
		},
		{
			tp:           C.MatchTypeString,
			payload:      "example",
			target:       policy,
			expectedRule: NewMatch(policy),
		},
		{
			tp:            C.RuleSetTypeString,
			payload:       "example",
			target:        policy,
			expectedError: fmt.Errorf("unsupported rule type %s", C.RuleSetTypeString),
		},
		{
			tp:            C.ScriptTypeString,
			payload:       "example",
			target:        policy,
			expectedError: fmt.Errorf("unsupported rule type %s", C.ScriptTypeString),
		},
		{
			tp:            "UNKNOWN",
			payload:       "example",
			target:        policy,
			expectedError: errors.New("unsupported rule type UNKNOWN"),
		},
		{
			tp:            "ABCD",
			payload:       "example",
			target:        policy,
			expectedError: errors.New("unsupported rule type ABCD"),
		},
	}

	for _, tc := range testCases {
		_, err := ParseRule(string(tc.tp), tc.payload, tc.target, tc.params)
		if tc.expectedError != nil {
			require.Error(t, err)
			assert.EqualError(t, err, tc.expectedError.Error())
		} else {
			require.NoError(t, err)
		}
	}
}
