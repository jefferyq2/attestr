package signerverifier

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/docker/attest/internal/util"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

type ECDSA256_SignerVerifier struct {
	crypto.Signer
}

// implement keyid function
func (s *ECDSA256_SignerVerifier) KeyID() (string, error) {
	keyid, err := KeyID(s.Signer.Public())
	if err != nil {
		return "", fmt.Errorf("error getting keyid: %w", err)
	}
	return keyid, nil
}

func (s *ECDSA256_SignerVerifier) Public() crypto.PublicKey {
	return s.Signer.Public()
}

func (s *ECDSA256_SignerVerifier) Sign(ctx context.Context, data []byte) ([]byte, error) {
	return s.Signer.Sign(rand.Reader, data, crypto.SHA256)
}

func (s *ECDSA256_SignerVerifier) Verify(ctx context.Context, data []byte, sig []byte) error {
	pub, ok := s.Signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not ecdsa")
	}
	ok = ecdsa.VerifyASN1(pub, util.S256(data), sig)
	if !ok {
		return fmt.Errorf("payload signature is not valid")
	}
	return nil
}

func GenKeyPair() (dsse.SignerVerifier, error) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ECDSA256_SignerVerifier{
		Signer: signer,
	}, nil
}
