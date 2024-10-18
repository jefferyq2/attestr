/*
   Copyright Docker attest authors

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

package attestation_test

import (
	"encoding/base64"
	"testing"

	"github.com/docker/attest/attestation"
	"github.com/docker/attest/internal/test"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	ociv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

func TestValidPayloadType(t *testing.T) {
	testCases := []struct {
		name        string
		payloadType string
		expected    bool
	}{
		{"valid in-toto payload type", intoto.PayloadType, true},
		{"valid oci descriptor payload type", ociv1.MediaTypeDescriptor, true},
		{"invalid payload type", "application/vnd.test.fail", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equalf(t, tc.expected, attestation.ValidPayloadType(tc.payloadType), "expected %v for payload type %s", tc.expected, tc.payloadType)
		})
	}
}

func TestVerifyUnsignedAttestation(t *testing.T) {
	ctx, _ := test.Setup(t)

	payload := []byte("payload")
	env := &attestation.Envelope{
		// no signatures
		Signatures:  []*attestation.Signature{},
		Payload:     base64.StdEncoding.EncodeToString(payload),
		PayloadType: intoto.PayloadType,
	}
	opts := &attestation.VerifyOptions{
		Keys: attestation.Keys{},
	}
	_, err := attestation.VerifyDSSE(ctx, nil, env, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no signatures")
}
