package attest

import (
	"fmt"

	"github.com/docker/attest/pkg/attestation"
)

type envelopeStyle string

const (
	OCIContentDescriptor          envelopeStyle = "oci-content-descriptor"
	EmbeddedDSSE                  envelopeStyle = "embedded-dsse"
	InTotoReferenceLifecycleStage               = "vnd.docker.lifecycle-stage"
	LifecycleStageExperimental                  = "experimental"
)

type SigningOptions struct {
	Replace       bool
	EnvelopeStyle envelopeStyle
	VSAOptions    *attestation.VSAOptions
}

func EnvelopeStyle(style string) (envelopeStyle, error) {
	switch style {
	case string(OCIContentDescriptor):
		return OCIContentDescriptor, nil
	case string(EmbeddedDSSE):
		return EmbeddedDSSE, nil
	default:
		return "", fmt.Errorf("unknown envelope style %q", style)
	}
}
