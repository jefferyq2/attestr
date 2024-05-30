package attest_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/docker/attest/internal/embed"
	"github.com/docker/attest/pkg/attest"
	"github.com/docker/attest/pkg/oci"
	"github.com/docker/attest/pkg/policy"
	"github.com/docker/attest/pkg/tuf"
)

func createTufClient(outputPath string) (*tuf.TufClient, error) {
	// using oci tuf metadata and targets
	metadataURI := "registry-1.docker.io/docker/tuf-metadata:latest"
	targetsURI := "registry-1.docker.io/docker/tuf-targets"
	// example using http tuf metadata and targets
	// metadataURI := "https://docker.github.io/tuf-staging/metadata"
	// targetsURI := "https://docker.github.io/tuf-staging/targets"

	return tuf.NewTufClient(embed.StagingRoot, outputPath, metadataURI, targetsURI, tuf.NewMockVersionChecker())
}

func ExampleVerify_remote() {
	// create a tuf client
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	tufOutputPath := filepath.Join(home, ".docker", "tuf")
	tufClient, err := createTufClient(tufOutputPath)
	if err != nil {
		panic(err)
	}

	// create a resolver for remote attestations
	image := "registry-1.docker.io/library/notary:server"
	platform := "linux/amd64"
	resolver, err := oci.NewRegistryAttestationResolver(
		image,    // path to image index in OCI registry containing image attestations
		platform) // platform of subject image (image that attestations are being verified against)
	if err != nil {
		panic(err)
	}
	// example using a local resolver
	// path := "/myimage"
	// platform := "linux/amd64"
	// resolver := &oci.OCILayoutResolver{
	// 	Path:     path,     // file path to OCI layout containing image attestations
	// 	Platform: platform, // platform of subject image (image that attestations are being verified against)
	// }

	// configure policy options
	opts := &policy.PolicyOptions{
		TufClient:       tufClient,
		LocalTargetsDir: filepath.Join(home, ".docker", "policy"), // location to store policy files downloaded from TUF
		LocalPolicyDir:  "",                                       // overrides TUF policy for local policy files if set
		PolicyId:        "",                                       // set to ignore policy mapping and select a policy by id
	}

	// verify attestations
	result, err := attest.Verify(context.Background(), opts, resolver)
	if err != nil {
		panic(err)
	}
	switch result.Outcome {
	case attest.OutcomeSuccess:
		fmt.Println("policy passed")
	case attest.OutcomeNoPolicy:
		fmt.Println("no policy for image")
	case attest.OutcomeFailure:
		fmt.Println("policy failed")
	}
}
