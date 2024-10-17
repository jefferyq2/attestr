/*
   Copyright 2024 Docker attest authors

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
package mapping

import (
	"regexp"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type policyMappingsFile struct {
	Version  string            `json:"version"`
	Kind     string            `json:"kind"`
	Policies []*PolicyMapping  `json:"policies"`
	Rules    []*policyRuleFile `json:"rules"`
}

type policyRuleFile struct {
	Pattern     string   `json:"pattern"`
	Platforms   []string `json:"platforms"`
	PolicyID    string   `json:"policy-id"`
	Replacement string   `json:"rewrite"`
}

type PolicyMappings struct {
	Version  string
	Kind     string
	Policies map[string]*PolicyMapping
	Rules    []*PolicyRule
}

type AttestationStyle string

const (
	AttestationStyleAttached  AttestationStyle = "attached"
	AttestationStyleReferrers AttestationStyle = "referrers"
)

type PolicyMapping struct {
	ID           string              `json:"id"`
	Description  string              `json:"description"`
	Files        []PolicyMappingFile `json:"files"`
	Attestations *AttestationConfig  `json:"attestations"`
}

type AttestationConfig struct {
	Style AttestationStyle `json:"style"`
	Repo  string           `json:"repo"`
}

type PolicyMappingFile struct {
	Path string `json:"path"`
}

type PolicyRule struct {
	Pattern     *regexp.Regexp
	PolicyID    string
	Replacement string
	Platforms   []*v1.Platform
}
