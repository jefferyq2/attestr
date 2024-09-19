package policy

import (
	"context"
	"testing"

	"github.com/docker/attest/attestation"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/open-policy-agent/opa/tester"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicy(t *testing.T) {
	paths := []string{"testdata/policies/test"}
	modules, store, err := tester.Load(paths, nil)
	require.NoError(t, err)
	resolver := &NullAttestationResolver{}

	opts := NewRegoFunctionOptions(resolver, nil)
	ctx := context.Background()
	ch, err := tester.NewRunner().
		SetStore(store).
		AddCustomBuiltins(RegoFunctions(opts)).
		CapturePrintOutput(true).
		RaiseBuiltinErrors(true).
		EnableTracing(true).
		SetModules(modules).
		RunTests(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, err)
	results := buffer(ch)
	assert.Equalf(t, 1, len(results), "expected 1 results, got %d", len(results))
	assert.Truef(t, results[0].Pass(), "expected result 1 to pass, got %v", results[0])
	assert.True(t, resolver.called)
}

func buffer[T any](ch chan T) []T {
	var out []T
	for v := range ch {
		out = append(out, v)
	}
	return out
}

type NullAttestationResolver struct {
	called bool
}

func (r *NullAttestationResolver) ImageName(_ context.Context) (string, error) {
	return "", nil
}

func (r *NullAttestationResolver) ImagePlatform(_ context.Context) (*v1.Platform, error) {
	return v1.ParsePlatform("")
}

func (r *NullAttestationResolver) ImageDescriptor(_ context.Context) (*v1.Descriptor, error) {
	return nil, nil
}

func (r *NullAttestationResolver) Attestations(_ context.Context, _ string) ([]*attestation.Envelope, error) {
	r.called = true
	return nil, nil
}