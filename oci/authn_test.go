//go:build e2e

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

package oci_test

import (
	"context"
	"testing"

	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/oci"
	"github.com/stretchr/testify/require"
)

func TestRegistryAuth(t *testing.T) {
	attIdx, err := oci.IndexFromPath(test.UnsignedTestIndex(".."))
	require.NoError(t, err)
	// test cases for ecr, gcr and dockerhub
	testCases := []struct {
		Image string
	}{
		{Image: "175142243308.dkr.ecr.us-east-1.amazonaws.com/e2e-test-image:latest"},
		{Image: "docker/image-signer-verifier-test:latest"},
	}
	ctx := context.Background()
	for _, tc := range testCases {
		t.Run(tc.Image, func(t *testing.T) {
			err := oci.PushIndexToRegistry(ctx, attIdx.Index, tc.Image)
			require.NoError(t, err)
			_, err = oci.IndexFromRemote(ctx, tc.Image)
			require.NoError(t, err)
		})
	}
}
