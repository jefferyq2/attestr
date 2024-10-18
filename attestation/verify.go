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

package attestation

import (
	"context"
	"crypto"
	"encoding/base64"
	"fmt"

	"github.com/docker/attest/signerverifier"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	ociv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func VerifyDSSE(ctx context.Context, verifier Verifier, env *Envelope, opts *VerifyOptions) ([]byte, error) {
	// enforce payload type
	if !ValidPayloadType(env.PayloadType) {
		return nil, fmt.Errorf("unsupported payload type %s", env.PayloadType)
	}

	if len(env.Signatures) == 0 {
		return nil, fmt.Errorf("no signatures found")
	}

	keys := make(map[string]*KeyMetadata, len(opts.Keys))
	for _, key := range opts.Keys {
		keys[key.ID] = key
	}

	payload, err := base64Encoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("error failed to decode payload: %w", err)
	}

	encPayload := dsse.PAE(env.PayloadType, payload)
	// verify signatures and transparency log entry
	for _, sig := range env.Signatures {
		// resolve public key used to sign
		keyMeta, ok := keys[sig.KeyID]
		if !ok {
			return nil, fmt.Errorf("error key not found: %s", sig.KeyID)
		}

		if keyMeta.Distrust {
			return nil, fmt.Errorf("key %s is distrusted", keyMeta.ID)
		}
		publicKey, err := keyMeta.ParsedKey()
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		// decode signature
		signature, err := base64.StdEncoding.Strict().DecodeString(sig.Sig)
		if err != nil {
			return nil, fmt.Errorf("error failed to decode signature: %w", err)
		}

		err = verifier.VerifySignature(ctx, publicKey, encPayload, signature, opts)
		if err != nil {
			return nil, fmt.Errorf("error failed to verify signature: %w", err)
		}
		if err := verifier.VerifyLog(ctx, keyMeta, encPayload, sig, opts); err != nil {
			return nil, fmt.Errorf("error failed to verify transparency log entry: %w", err)
		}
	}

	return payload, nil
}

func ValidPayloadType(payloadType string) bool {
	return payloadType == intoto.PayloadType || payloadType == ociv1.MediaTypeDescriptor
}

func (km *KeyMetadata) ParsedKey() (crypto.PublicKey, error) {
	if km.publicKey != nil {
		return km.publicKey, nil
	}
	publicKey, err := signerverifier.ParsePublicKey([]byte(km.PEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	km.publicKey = publicKey
	return publicKey, nil
}
