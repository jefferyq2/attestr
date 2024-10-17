package tuf

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/version"
	"github.com/stretchr/testify/assert"
)

const (
	invalidVersion    = "0.0.1"
	validVersion      = "v1.0.0-0"
	versionConstraint = ">=v1.0.0-0"
)

func TestDefaultVersionChecker(t *testing.T) {
	testDir := test.CreateTempDir(t, "", "tuf_temp")
	versionConstraintsPath := filepath.Join(testDir, "version-constraints")
	err := os.WriteFile(versionConstraintsPath, []byte(versionConstraint), 0o600)
	assert.NoError(t, err)
	tufClient := NewMockTufClient(testDir)

	expectedError := fmt.Sprintf("%s version %s does not satisfy constraints %s: %s is less than %s", version.ThisModulePath, invalidVersion, versionConstraint, invalidVersion, validVersion)

	testCases := []struct {
		name          string
		expectedError string
		version       string
	}{
		{name: "version is less than the minimum", expectedError: expectedError, version: "0.0.1"},
		{name: "version is equal to the minimum", version: "1.0.0"},
		{name: "version is greater than the minimum", version: "1.0.1"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			checker := NewDefaultVersionChecker()
			checker.VersionFetcher = &MockVersionFetcher{version: tc.version}
			err := checker.CheckVersion(tufClient)
			if tc.expectedError != "" {
				assert.Error(t, err)
				assert.Equal(t, tc.expectedError, err.Error())
				return
			}
			assert.NoError(t, err)
		})
	}
}

type MockVersionFetcher struct {
	version string
}

func (m *MockVersionFetcher) Get() (*semver.Version, error) {
	return semver.NewVersion(m.version)
}
