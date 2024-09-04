package attestation

import (
	"fmt"
	"testing"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	slsav1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDSSEMediaType(t *testing.T) {
	testcases := []struct {
		name     string
		expected string
	}{
		{
			name:     slsav1.PredicateSLSAProvenance,
			expected: "provenance",
		},
		{
			name:     v02.PredicateSLSAProvenance,
			expected: "provenance",
		},
		{
			name:     intoto.PredicateSPDX,
			expected: "spdx",
		},
		{
			name:     VSAPredicateType,
			expected: "verification_summary",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			mt, err := DSSEMediaType(tc.name)
			require.NoError(t, err)
			assert.Equal(t, fmt.Sprintf("application/vnd.in-toto.%s+dsse", tc.expected), mt)
		})
	}
}
