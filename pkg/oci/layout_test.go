package oci_test

import (
	"strings"
	"testing"

	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/pkg/attest"
	"github.com/docker/attest/pkg/attestation"
	"github.com/docker/attest/pkg/mirror"
	"github.com/docker/attest/pkg/oci"
	"github.com/docker/attest/pkg/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttestationFromOCILayout(t *testing.T) {
	ctx, signer := test.Setup(t)
	outputLayout := test.CreateTempDir(t, "", "attest-oci-layout")

	opts := &attestation.SigningOptions{}
	attIdx, err := oci.IndexFromPath(oci.UnsignedTestImage)
	require.NoError(t, err)
	signedManifests, err := attest.SignStatements(ctx, attIdx.Index, signer, opts)
	require.NoError(t, err)
	signedIndex := attIdx.Index
	signedIndex, err = attestation.UpdateIndexImages(signedIndex, signedManifests)
	require.NoError(t, err)

	spec, err := oci.ParseImageSpec(oci.LocalPrefix + outputLayout)
	require.NoError(t, err)
	err = mirror.SaveIndex([]*oci.ImageSpec{spec}, signedIndex, outputLayout)
	require.NoError(t, err)

	resolver, err := policy.CreateImageDetailsResolver(spec)
	require.NoError(t, err)
	desc, err := resolver.ImageDescriptor(ctx)
	require.NoError(t, err)
	digest := desc.Digest.String()
	assert.True(t, strings.Contains(digest, "sha256:"))
}
