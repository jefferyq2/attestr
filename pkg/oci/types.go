package oci

import (
	"fmt"
	"log"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const (
	AttestationManifestType = "attestation-manifest"
	InTotoPredicateType     = "in-toto.io/predicate-type"
	OciReferenceTarget      = "org.opencontainers.image.ref.name"
)

type SubjectIndex struct {
	Index v1.ImageIndex
	Name  string
}

func SubjectIndexFromPath(path string) (*SubjectIndex, error) {
	wrapperIdx, err := layout.ImageIndexFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load image index: %w", err)
	}

	idxm, err := wrapperIdx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get digest: %w", err)
	}
	imageName := idxm.Manifests[0].Annotations[OciReferenceTarget]
	idxDigest := idxm.Manifests[0].Digest

	idx, err := wrapperIdx.ImageIndex(idxDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to extract ImageIndex for digest %s: %w", idxDigest.String(), err)
	}
	return &SubjectIndex{
		Index: idx,
		Name:  imageName,
	}, nil
}

func SubjectIndexFromRemote(image string) (*SubjectIndex, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		log.Fatalf("Failed to parse image name: %v", err)
	}
	// Pull the image from the registry
	idx, err := remote.Index(ref, MultiKeychainOption())
	if err != nil {
		return nil, fmt.Errorf("failed to pull image %s: %w", image, err)
	}
	return &SubjectIndex{
		Index: idx,
		Name:  image,
	}, nil
}
