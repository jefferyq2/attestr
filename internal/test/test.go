package test

import (
	"context"
	"os"
	"testing"

	"github.com/docker/attest/internal/oci"
	"github.com/docker/attest/pkg/policy"
	"github.com/docker/attest/pkg/signerverifier"
	"github.com/docker/attest/pkg/tlog"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

const (
	USE_MOCK_TL     = true
	USE_MOCK_KMS    = true
	USE_MOCK_POLICY = true

	AwsRegion    = "us-east-1"
	AwsKmsKeyArn = "arn:aws:kms:us-east-1:175142243308:alias/doi-signing" // sandbox
)

func CreateTempDir(t *testing.T, dir, pattern string) string {
	// Create a temporary directory for output oci layout
	tempDir, err := os.MkdirTemp(dir, pattern)
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Register a cleanup function to delete the temp directory when the test exits
	t.Cleanup(func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Errorf("Failed to remove temp directory: %v", err)
		}
	})
	return tempDir
}

func Setup(t *testing.T) (context.Context, dsse.SignerVerifier) {
	var tl tlog.TL
	if USE_MOCK_TL {
		tl = tlog.GetMockTL()
	} else {
		tl = &tlog.RekorTL{}
	}

	ctx := tlog.WithTL(context.Background(), tl)

	var policyEvaluator policy.PolicyEvaluator
	if USE_MOCK_POLICY {
		policyEvaluator = GetMockPolicy()
	} else {
		policyEvaluator = policy.NewRegoEvaluator(true)
	}

	ctx = policy.WithPolicyEvaluator(ctx, policyEvaluator)

	var signer dsse.SignerVerifier
	var err error
	if USE_MOCK_KMS {
		signer, err = GetMockSigner(ctx)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		signer, err = signerverifier.GetAWSSigner(ctx, AwsKmsKeyArn, AwsRegion)
		if err != nil {
			t.Fatal(err)
		}
	}

	return ctx, signer
}

func GetMockSigner(ctx context.Context) (dsse.SignerVerifier, error) {
	return signerverifier.GenKeyPair()
}

func GetMockPolicy() policy.PolicyEvaluator {
	return &policy.MockPolicyEvaluator{
		EvaluateFunc: func(ctx context.Context, resolver oci.AttestationResolver, policy []*policy.PolicyFile, input *policy.PolicyInput) error {
			return nil
		},
	}
}
