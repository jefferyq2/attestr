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
package attestation_test

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/docker/attest"
	"github.com/docker/attest/attestation"
	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/oci"
	"github.com/docker/attest/policy"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistry(t *testing.T) {
	ctx, signer := test.Setup(t)
	regServer := test.NewLocalRegistry(ctx, registry.WithReferrersSupport(false))
	defer regServer.Close()
	u, err := url.Parse(regServer.URL)
	require.NoError(t, err)

	opts := &attestation.SigningOptions{}
	attIdx, err := oci.IndexFromPath(test.UnsignedTestIndex(".."))
	require.NoError(t, err)
	signedManifests, err := attest.SignStatements(ctx, attIdx.Index, signer, opts)
	require.NoError(t, err)
	signedIndex := attIdx.Index
	signedIndex, err = attestation.UpdateIndexImages(signedIndex, signedManifests)
	require.NoError(t, err)

	indexName := fmt.Sprintf("%s/repo:root", u.Host)
	require.NoError(t, err)
	err = oci.PushIndexToRegistry(ctx, signedIndex, indexName)
	require.NoError(t, err)

	spec, err := oci.ParseImageSpec(indexName)
	require.NoError(t, err)

	resolver, err := policy.CreateImageDetailsResolver(spec)
	require.NoError(t, err)
	desc, err := resolver.ImageDescriptor(ctx)
	require.NoError(t, err)
	digest := desc.Digest.String()
	assert.True(t, strings.Contains(digest, "sha256:"))

	// resolver also works with platform specific digest
	spec, err = oci.ParseImageSpec(fmt.Sprintf("%s@%s", indexName, digest))
	require.NoError(t, err)

	resolver, err = policy.CreateImageDetailsResolver(spec)
	require.NoError(t, err)
	desc, err = resolver.ImageDescriptor(ctx)
	require.NoError(t, err)
	assert.Equal(t, desc.Digest.String(), digest)
}
