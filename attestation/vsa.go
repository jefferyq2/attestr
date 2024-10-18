/*
   Copyright Docker attest authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package attestation

import (
	"fmt"

	"github.com/docker/attest/version"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/package-url/packageurl-go"
)

const (
	VSAPredicateType = "https://slsa.dev/verification_summary/v1"
)

type VSAPredicate struct {
	Verifier           VSAVerifier          `json:"verifier"`
	TimeVerified       string               `json:"timeVerified"`
	ResourceURI        string               `json:"resourceUri"`
	Policy             VSAPolicy            `json:"policy"`
	InputAttestations  []ResourceDescriptor `json:"inputAttestations,omitempty"`
	VerificationResult string               `json:"verificationResult"`
	VerifiedLevels     []string             `json:"verifiedLevels"`
}

type VSAVerifier struct {
	ID      string          `json:"id"`
	Version VerifierVersion `json:"version"`
}

type VerifierVersion map[string]string

type VSAPolicy struct {
	URI              string            `json:"uri,omitempty"`
	Digest           map[string]string `json:"digest"`
	DownloadLocation string            `json:"downloadLocation,omitempty"`
}

func ToVSAResourceURI(sub intoto.Subject) (string, error) {
	// parse purl
	purl, err := packageurl.FromString(sub.Name)
	if err != nil {
		return "", fmt.Errorf("failed to parse package url: %w", err)
	}
	quals := purl.Qualifiers.Map()
	if quals["digest"] == "" {
		quals["digest"] = "sha256:" + sub.Digest["sha256"]
	}
	purl.Qualifiers = packageurl.QualifiersFromMap(quals)
	return purl.String(), nil
}

func GetVerifierVersion(fetcher version.Fetcher) (VerifierVersion, error) {
	attestVersion, err := fetcher.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to get attest version: %w", err)
	}
	if attestVersion == nil {
		return nil, nil
	}
	return VerifierVersion{
		version.ThisModulePath: attestVersion.String(),
	}, nil
}
