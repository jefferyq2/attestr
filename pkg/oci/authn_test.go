//go:build e2e

package oci

import (
	"testing"

	"github.com/docker/attest/internal/test"
	"github.com/stretchr/testify/require"
)

func TestRegistryAuth(t *testing.T) {
	attIdx, err := IndexFromPath(test.UnsignedTestImage)
	require.NoError(t, err)
	// test cases for ecr, gcr and dockerhub
	testCases := []struct {
		Image string
	}{
		{Image: "175142243308.dkr.ecr.us-east-1.amazonaws.com/e2e-test-image:latest"},
		{Image: "docker/image-signer-verifier-test:latest"},
	}
	for _, tc := range testCases {
		t.Run(tc.Image, func(t *testing.T) {
			err := PushIndexToRegistry(attIdx.Index, tc.Image)
			require.NoError(t, err)
			_, err = IndexFromRemote(tc.Image)
			require.NoError(t, err)
		})
	}
}
