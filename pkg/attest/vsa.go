package attest

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/docker/attest/pkg/attestation"
	"github.com/docker/attest/pkg/oci"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

// generateVSA generates a VSA from the attestation manifest
// TODO: remove signing logic and move generateVSA to attestation/vsa.go
func generateVSA(ctx context.Context, manifest attestation.AttestationManifest, signer dsse.SignerVerifier, opts *SigningOptions) (*mutate.Addendum, error) {
	if len(manifest.Attestation.Layers) == 0 {
		return nil, fmt.Errorf("no attestations found to generate VSA from")
	}
	sub := manifest.Attestation.Layers[0].Statement.Subject[0]
	stype := manifest.Attestation.Layers[0].Statement.Type

	uri, err := attestation.ToVSAResourceURI(sub)
	if err != nil {
		return nil, fmt.Errorf("failed to generate VSA resource URI: %w", err)
	}

	inputs := make([]attestation.VSAInputAttestation, 0, len(manifest.Attestation.Layers))
	for _, att := range manifest.Attestation.Layers {
		mt, err := att.Layer.MediaType()
		if err != nil {
			return nil, fmt.Errorf("failed to get layer media type: %w", err)
		}
		if !strings.HasSuffix(string(mt), "+dsse") {
			continue
		}
		dgst, err := att.Layer.Digest()
		if err != nil {
			return nil, fmt.Errorf("failed to get layer digest: %w", err)
		}
		inputs = append(inputs, attestation.VSAInputAttestation{
			Digest:    map[string]string{"sha256": dgst.Hex},
			MediaType: string(mt),
		})
	}
	vsaStatement := &intoto.Statement{
		StatementHeader: intoto.StatementHeader{
			PredicateType: attestation.VSAPredicateType,
			Type:          stype,
			Subject:       manifest.Attestation.Layers[0].Statement.Subject,
		},
		Predicate: attestation.VSAPredicate{
			Verifier: attestation.VSAVerifier{
				ID: opts.VSAOptions.VerifierID,
			},
			TimeVerified:       time.Now().UTC().Format(time.RFC3339),
			ResourceUri:        uri,
			Policy:             attestation.VSAPolicy{URI: opts.VSAOptions.PolicyURI},
			VerificationResult: "PASSED",
			VerifiedLevels:     []string{opts.VSAOptions.BuildLevel},
			InputAttestations:  inputs,
		},
	}
	payload, err := json.Marshal(vsaStatement)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal statement: %w", err)
	}
	env, err := attestation.SignDSSE(ctx, payload, intoto.PayloadType, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to sign statement: %w", err)
	}
	mediaType, err := attestation.DSSEMediaType(vsaStatement.PredicateType)
	if err != nil {
		return nil, fmt.Errorf("failed to get DSSE media type: %w", err)
	}

	data, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal envelope: %w", err)
	}
	mt := types.MediaType(mediaType)
	newLayer := static.NewLayer(data, mt)
	ann := make(map[string]string)
	ann[InTotoReferenceLifecycleStage] = LifecycleStageExperimental
	ann[oci.InTotoPredicateType] = attestation.VSAPredicateType
	withAnnotations := mutate.Addendum{
		Layer:       newLayer,
		Annotations: ann,
	}
	return &withAnnotations, nil
}
