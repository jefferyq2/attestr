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

package attest

import (
	"path/filepath"
	"testing"

	"github.com/docker/attest/attestation"
	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/oci"
	"github.com/docker/attest/policy"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	NoProvenanceImage   = filepath.Join("test", "testdata", "no-provenance-index")
	PassPolicyDir       = filepath.Join("test", "testdata", "local-policy-pass")
	PassMirrorPolicyDir = filepath.Join("test", "testdata", "local-policy-mirror")
	PassNoTLPolicyDir   = filepath.Join("test", "testdata", "local-policy-no-tl")
	FailPolicyDir       = filepath.Join("test", "testdata", "local-policy-fail")
	InputsPolicyDir     = filepath.Join("test", "testdata", "local-policy-inputs")
	EmptyPolicyDir      = filepath.Join("test", "testdata", "local-policy-no-policies")
	TestTempDir         = "attest-sign-test"
)

func TestSignVerifyOCILayout(t *testing.T) {
	ctx, signer := test.Setup(t)

	testCases := []struct {
		name                 string
		TestImage            string
		expectedStatements   int
		expectedAttestations int
		replace              bool
	}{
		{"signed replaced", test.UnsignedTestIndex(), 0, 4, true},
		{"without replace", test.UnsignedTestIndex(), 4, 4, false},
		// image without provenance doesn't fail
		{"no provenance (replace)", NoProvenanceImage, 0, 2, true},
		{"no provenance (no replace)", NoProvenanceImage, 2, 2, false},
	}
	policyOpts := &policy.Options{
		LocalPolicyDir: PassPolicyDir,
		DisableTUF:     true,
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			outputLayout := test.CreateTempDir(t, "", TestTempDir)
			opts := &attestation.SigningOptions{}
			attIdx, err := oci.IndexFromPath(tc.TestImage)
			require.NoError(t, err)
			signedManifests, err := SignStatements(ctx, attIdx.Index, signer, opts)
			require.NoError(t, err)
			signedIndex := attIdx.Index
			signedIndex, err = attestation.UpdateIndexImages(signedIndex, signedManifests, attestation.WithReplacedLayers(tc.replace))
			require.NoError(t, err)
			spec, err := oci.ParseImageSpec(oci.LocalPrefix + outputLayout)
			require.NoError(t, err)
			err = oci.SaveIndex(ctx, []*oci.ImageSpec{spec}, signedIndex, attIdx.Name)
			require.NoError(t, err)
			policy, err := Verify(ctx, spec, policyOpts)
			require.NoError(t, err)
			assert.Equalf(t, OutcomeSuccess, policy.Outcome, "Policy should have been found")

			var allEnvelopes []*attestation.AnnotatedStatement
			for _, predicate := range []string{intoto.PredicateSPDX, v02.PredicateSLSAProvenance, attestation.VSAPredicateType} {
				mt, _ := attestation.DSSEMediaType(predicate)
				statements, err := attestation.ExtractAnnotatedStatements(outputLayout, mt)
				require.NoError(t, err)
				allEnvelopes = append(allEnvelopes, statements...)

				for _, stmt := range statements {
					assert.Equalf(t, predicate, stmt.Annotations[attestation.InTotoPredicateType], "expected predicate-type annotation to be set to %s, got %s", predicate, stmt.Annotations[attestation.InTotoPredicateType])
					assert.Equalf(t, attestation.LifecycleStageExperimental, stmt.Annotations[attestation.InTotoReferenceLifecycleStage], "expected reference lifecycle stage annotation to be set to %s, got %s", attestation.LifecycleStageExperimental, stmt.Annotations[attestation.InTotoReferenceLifecycleStage])
				}
			}
			assert.Equalf(t, tc.expectedAttestations, len(allEnvelopes), "expected %d attestations, got %d", tc.expectedAttestations, len(allEnvelopes))
			statements, err := attestation.ExtractAnnotatedStatements(outputLayout, intoto.PayloadType)
			require.NoError(t, err)
			assert.Equalf(t, tc.expectedStatements, len(statements), "expected %d statement, got %d", tc.expectedStatements, len(statements))
		})
	}
}
