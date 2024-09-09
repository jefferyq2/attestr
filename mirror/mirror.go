package mirror

import (
	"context"
	"fmt"

	"github.com/docker/attest/tuf"
)

func NewTUFMirror(ctx context.Context, root []byte, tufPath, metadataURL, targetsURL string, versionChecker tuf.VersionChecker) (*TUFMirror, error) {
	if root == nil {
		root = tuf.DockerTUFRootDefault.Data
	}
	tufClient, err := tuf.NewClient(ctx, &tuf.ClientOptions{InitialRoot: root, Path: tufPath, MetadataSource: metadataURL, TargetsSource: targetsURL, VersionChecker: versionChecker})
	if err != nil {
		return nil, fmt.Errorf("failed to create TUF client: %w", err)
	}
	return &TUFMirror{TUFClient: tufClient, tufPath: tufPath, metadataURL: metadataURL, targetsURL: targetsURL}, nil
}
