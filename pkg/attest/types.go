package attest

import (
	"github.com/docker/attest/pkg/attestation"
)

const (
	InTotoReferenceLifecycleStage = "vnd.docker.lifecycle-stage"
	LifecycleStageExperimental    = "experimental"
)

type SigningOptions struct {
	Replace    bool
	VSAOptions *attestation.VSAOptions
}
