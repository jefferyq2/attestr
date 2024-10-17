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
package attestation

import (
	"context"
	"fmt"

	"github.com/docker/attest/internal/util"
	"github.com/docker/attest/tlog"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

// SignDSSE signs a payload with a given signer and uploads the signature to the transparency log.
func SignDSSE(ctx context.Context, payload []byte, signer dsse.SignerVerifier, opts *SigningOptions) (*Envelope, error) {
	payloadType := intoto.PayloadType
	env := new(Envelope)
	env.Payload = base64Encoding.EncodeToString(payload)
	env.PayloadType = payloadType
	encPayload := dsse.PAE(payloadType, payload)

	// statement message digest
	hash := util.SHA256(encPayload)

	// sign message digest
	sig, err := signer.Sign(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("error signing attestation: %w", err)
	}

	// get Key ID from signer
	keyID, err := signer.KeyID()
	if err != nil {
		return nil, fmt.Errorf("error getting public key ID: %w", err)
	}

	dsseSig := &Signature{
		KeyID: keyID,
		Sig:   base64Encoding.EncodeToString(sig),
	}
	if opts.TransparencyLog != nil {
		ext, err := logSignature(ctx, opts.TransparencyLog, sig, encPayload, signer)
		if err != nil {
			return nil, fmt.Errorf("failed to log signature: %w", err)
		}
		dsseSig.Extension = ext
	}
	// add signature to dsse envelope
	env.Signatures = []*Signature{dsseSig}

	return env, nil
}

// returns a new envelope with the transparency log entry added to the signature extension.
func logSignature(ctx context.Context, t tlog.TransparencyLog, sig []byte, encPayload []byte, signer dsse.SignerVerifier) (*Extension, error) {
	// get Key ID from signer
	keyID, err := signer.KeyID()
	if err != nil {
		return nil, fmt.Errorf("error getting public key ID: %w", err)
	}
	entry, err := t.UploadEntry(ctx, keyID, encPayload, sig, signer)
	if err != nil {
		return nil, fmt.Errorf("error uploading TL entry: %w", err)
	}

	return &Extension{
		Kind: DockerDSSEExtKind,
		Ext: &DockerDSSEExtension{
			TL: entry,
		},
	}, nil
}
