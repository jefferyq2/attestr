package mirror

import (
	"fmt"
	"log"
	"os"

	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	acr "github.com/chrismellard/docker-credential-acr-env/pkg/credhelper"
	"github.com/docker/attest/internal/embed"
	"github.com/docker/attest/pkg/tuf"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func NewTufMirror(root []byte, tufPath, metadataURL, targetsURL string, versionChecker tuf.VersionChecker) (*TufMirror, error) {
	if root == nil {
		root = embed.DefaultRoot
	}
	tufClient, err := tuf.NewTufClient(root, tufPath, metadataURL, targetsURL, versionChecker)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUF client: %w", err)
	}
	return &TufMirror{TufClient: tufClient, tufPath: tufPath, metadataURL: metadataURL, targetsURL: targetsURL}, nil
}

func PushImageToRegistry(image v1.Image, imageName string) error {
	ref, err := name.ParseReference(imageName)
	if err != nil {
		log.Fatalf("Failed to parse image name: %v", err)
	}
	// Create a multi-keychain that will use the default Docker, Google, ECR or ACR keychain
	keychain := authn.NewMultiKeychain(
		authn.DefaultKeychain,
		google.Keychain,
		authn.NewKeychainFromHelper(ecr.NewECRHelper()),
		authn.NewKeychainFromHelper(acr.NewACRCredentialsHelper()),
	)
	// Push the image to the registry
	return remote.Write(ref, image, remote.WithAuthFromKeychain(keychain))
}

func PushIndexToRegistry(image v1.ImageIndex, imageName string) error {
	// Parse the index name
	ref, err := name.ParseReference(imageName)
	if err != nil {
		log.Fatalf("Failed to parse image name: %v", err)
	}
	// Create a multi-keychain that will use the default Docker, Google, ECR or ACR keychain
	keychain := authn.NewMultiKeychain(
		authn.DefaultKeychain,
		google.Keychain,
		authn.NewKeychainFromHelper(ecr.NewECRHelper()),
		authn.NewKeychainFromHelper(acr.NewACRCredentialsHelper()),
	)
	// Push the index to the registry
	return remote.WriteIndex(ref, image, remote.WithAuthFromKeychain(keychain))
}

func SaveImageAsOCILayout(image v1.Image, path string) error {
	// Save the image to the local filesystem
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	index := empty.Index
	l, err := layout.Write(path, index)
	if err != nil {
		return fmt.Errorf("failed to create index: %w", err)
	}
	return l.AppendImage(image)
}

func SaveIndexAsOCILayout(image v1.ImageIndex, path string) error {
	// Save the index to the local filesystem
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	_, err = layout.Write(path, image)
	if err != nil {
		return fmt.Errorf("failed to create index: %w", err)
	}
	return nil
}
