package mirror

import (
	"fmt"

	"github.com/docker/attest/internal/embed"
	"github.com/docker/attest/pkg/tuf"
)

func NewTUFMirror(root []byte, tufPath, metadataURL, targetsURL string, versionChecker tuf.VersionChecker) (*TUFMirror, error) {
	if root == nil {
		root = embed.RootDefault.Data
	}
	tufClient, err := tuf.NewClient(root, tufPath, metadataURL, targetsURL, versionChecker)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUF client: %w", err)
	}
	return &TUFMirror{TUFClient: tufClient, tufPath: tufPath, metadataURL: metadataURL, targetsURL: targetsURL}, nil
}
