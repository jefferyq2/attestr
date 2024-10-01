//go:build e2e

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
