package tuf

import (
	"os"
	"path/filepath"

	"github.com/docker/attest/internal/embed"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func ExampleTufRegistryClient() {
	// create a tuf client
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	tufOutputPath := filepath.Join(home, ".docker", "tuf")

	// using oci tuf metadata and targets
	metadataURI := "regsitry-1.docker.io/docker/tuf-metadata:latest"
	targetsURI := "regsitry-1.docker.io/docker/tuf-targets"
	registryClient, err := NewTufClient(embed.DefaultRoot, tufOutputPath, metadataURI, targetsURI)
	if err != nil {
		panic(err)
	}

	// get trusted tuf metadata
	trustedMetadata := registryClient.GetMetadata()
	if err != nil {
		panic(err)
	}

	// top-level target files
	targets := trustedMetadata.Targets[metadata.TARGETS].Signed.Targets

	for _, t := range targets {
		// download target files
		_, _, err := registryClient.DownloadTarget(t.Path, filepath.Join(tufOutputPath, "download"))
		if err != nil {
			panic(err)
		}
	}
}
