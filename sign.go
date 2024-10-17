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
package attest

import (
	"context"
	"fmt"

	"github.com/docker/attest/attestation"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

// this is only relevant if there are (unsigned) in-toto statements.
func SignStatements(ctx context.Context, idx v1.ImageIndex, signer dsse.SignerVerifier, opts *attestation.SigningOptions) ([]*attestation.Manifest, error) {
	// extract attestation manifests from index
	attestationManifests, err := attestation.ManifestsFromIndex(idx)
	if err != nil {
		return nil, fmt.Errorf("failed to load attestation manifests from index: %w", err)
	}
	// sign every attestation layer in each manifest
	for _, manifest := range attestationManifests {
		for _, layer := range manifest.OriginalLayers {
			// skip layers without statements
			if layer.Statement != nil {
				err = manifest.Add(ctx, signer, layer.Statement, opts)
				if err != nil {
					return nil, fmt.Errorf("failed to sign attestation layer %w", err)
				}
			}
		}
	}
	return attestationManifests, nil
}
