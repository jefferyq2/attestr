//go:build e2e

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
package signerverifier

import (
	"context"
	"crypto/ecdsa"
	"testing"

	"github.com/docker/attest/internal/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const publicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuMswW3iu7PR/rWTQjlhVmUsPK7rF
k2s4SO3XbQ2GG2alm289SUUpmBAuVxvT8muYQ8HC/QzixzyTACTXsBDjQg==
-----END PUBLIC KEY-----`

// to run locally, we need to impersonate the GCP service account
// gcloud auth application-default login --impersonate-service-account attest-kms-test@attest-kms-test.iam.gserviceaccount.com

func TestGCPKMS_Signer(t *testing.T) {
	// create a new signer
	ctx := context.TODO()
	ref := "projects/attest-kms-test/locations/us-west1/keyRings/attest-kms-test/cryptoKeys/test-signing-key/cryptoKeyVersions/1"
	signer, err := GetGCPSigner(ctx, ref)
	require.NoError(t, err)
	msg := []byte("hello world")
	hash := util.SHA256(msg)

	// sign message digest
	sig, err := signer.Sign(ctx, hash)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
	// get Key ID from signer
	keyId, err := signer.KeyID()
	require.NoError(t, err)
	assert.NotEmpty(t, keyId)
	publicKey, err := ParsePublicKey([]byte(publicKeyPEM))
	require.NoError(t, err)
	// verify payload ecdsa signature

	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("Failed to convert publicKey to *ecdsa.PublicKey")
	}
	ok = ecdsa.VerifyASN1(ecdsaPublicKey, hash, sig)
	assert.True(t, ok)

	err = signer.Verify(ctx, msg, sig)
	require.NoError(t, err)
}
