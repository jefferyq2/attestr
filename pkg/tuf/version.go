package tuf

import (
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/Masterminds/semver/v3"
)

const ThisModulePath = "github.com/docker/attest"

type VersionChecker interface {
	// CheckVersion checks if the current version of this library meets the constraints from the TUF repo
	CheckVersion(tufClient Downloader) error
}

type InvalidVersionError struct {
	AttestVersion     string
	VersionConstraint string
	Errors            []error
}

func (e *InvalidVersionError) Error() string {
	var errsStr strings.Builder
	for i, err := range e.Errors {
		if i > 0 {
			errsStr.WriteString("; ")
		}
		errsStr.WriteString(err.Error())
	}
	return fmt.Sprintf("%s version %s does not satisfy constraints %s: %s", ThisModulePath, e.AttestVersion, e.VersionConstraint, errsStr.String())
}

func NewDefaultVersionChecker() *DefaultVersionChecker {
	return &DefaultVersionChecker{}
}

type DefaultVersionChecker struct{}

func (vc *DefaultVersionChecker) CheckVersion(client Downloader) error {
	var attestMod *debug.Module
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		// if we can't read the build info, assume we're good. this should only happen if we're not running in a module
		return nil
	}
	if bi.Main.Path == ThisModulePath {
		attestMod = &bi.Main
	} else {
		for _, dep := range bi.Deps {
			if dep.Path == ThisModulePath {
				attestMod = dep
				break
			}
		}
	}
	if attestMod == nil {
		// if we can't find the attest dep, assume we're good. this should only happen in a test
		return nil
	}

	attestVersion, err := semver.NewVersion(attestMod.Version)
	if err != nil {
		return fmt.Errorf("failed to parse version %s: %w", attestMod.Version, err)
	}

	// see https://github.com/Masterminds/semver/blob/v3.2.1/README.md#checking-version-constraints
	// for more information on the expected format of the version constraints in the TUF repo
	_, versionConstraintsBytes, err := client.DownloadTarget("version-constraints", "")
	if err != nil {
		return fmt.Errorf("failed to download version-constraints: %w", err)
	}
	versionConstraints, err := semver.NewConstraint(string(versionConstraintsBytes))
	if err != nil {
		return fmt.Errorf("failed to parse minimum version: %w", err)
	}

	ok, errs := versionConstraints.Validate(attestVersion)
	if !ok {
		return &InvalidVersionError{
			AttestVersion:     attestVersion.String(),
			VersionConstraint: versionConstraints.String(),
			Errors:            errs,
		}
	}

	return nil
}
