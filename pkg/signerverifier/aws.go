package signerverifier

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	awssigner "github.com/sigstore/sigstore/pkg/signature/kms/aws"
)

// using AWS KMS
func GetAWSSigner(ctx context.Context, keyArn string, region string) (dsse.SignerVerifier, error) {
	keypath := fmt.Sprintf("awskms:///%s", keyArn)
	sv, err := awssigner.LoadSignerVerifier(ctx, keypath, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("error loading aws signer verifier: %w", err)
	}
	cs, _, err := sv.CryptoSigner(context.Background(), func(err error) {})
	if err != nil {
		return nil, fmt.Errorf("error getting aws crypto signer: %w", err)
	}
	signer := &ECDSA256_SignerVerifier{
		Signer: cs,
	}
	return signer, nil
}