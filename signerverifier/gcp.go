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

package signerverifier

import (
	"context"
	"fmt"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	gcpsigner "github.com/sigstore/sigstore/pkg/signature/kms/gcp"
	"google.golang.org/api/option"
)

// using GCP KMS
// reference should be in the format projects/[PROJECT_ID]/locations/[LOCATION]/keyRings/[KEY_RING]/cryptoKeys/[KEY]/cryptoKeyVersions/[VERSION].
func GetGCPSigner(ctx context.Context, reference string, opts ...option.ClientOption) (dsse.SignerVerifier, error) {
	reference = fmt.Sprintf("gcpkms://%s", reference)
	sv, err := gcpsigner.LoadSignerVerifier(ctx, reference, opts...)
	if err != nil {
		return nil, fmt.Errorf("error loading gcp signer verifier: %w", err)
	}
	cs, _, err := sv.CryptoSigner(ctx, func(_ error) {})
	if err != nil {
		return nil, fmt.Errorf("error getting gcp crypto signer: %w", err)
	}
	return NewECDSASignerVerifier(cs)
}
