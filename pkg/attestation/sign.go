package attestation

import (
	"context"
	"fmt"

	"github.com/docker/attest/internal/util"
	"github.com/docker/attest/pkg/tlog"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

// SignDSSE signs a payload with a given signer and uploads the signature to the transparency log
func SignDSSE(ctx context.Context, payload []byte, payloadType string, signer dsse.SignerVerifier) (*Envelope, error) {
	t := tlog.GetTL(ctx)

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
	keyId, err := signer.KeyID()
	if err != nil {
		return nil, fmt.Errorf("error getting public key ID: %w", err)
	}

	// upload to TL
	entry, err := t.UploadLogEntry(ctx, keyId, encPayload, sig, signer)
	if err != nil {
		return nil, fmt.Errorf("error uploading TL entry: %w", err)
	}
	entryObj, err := t.UnmarshalEntry(entry)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling tl entry: %w", err)
	}

	// add signature w/ tl extension to dsse envelope
	env.Signatures = append(env.Signatures, Signature{
		KeyID: keyId,
		Sig:   base64Encoding.EncodeToString(sig),
		Extension: Extension{
			Kind: DockerDsseExtKind,
			Ext: DockerDsseExtension{
				Tl: DockerTlExtension{
					Kind: RekorTlExtKind,
					Data: entryObj, // transparency log entry metadata
				},
			},
		},
	})

	return env, nil
}
