/*
   Copyright 2024 Docker attest authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
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
