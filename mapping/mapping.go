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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/docker/attest/tuf"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"sigs.k8s.io/yaml"
)

const (
	MappingFilename = "mapping.yaml"
)

func validateMappingsFile(mappings *policyMappingsFile) error {
	var validationErrors []error
	if mappings.Kind != "policy-mapping" {
		validationErrors = append(validationErrors, fmt.Errorf("file is not of kind policy-mapping: %s", mappings.Kind))
	}
	if mappings.Version != "v1" {
		validationErrors = append(validationErrors, fmt.Errorf("unsupported policy mapping file version: %s", mappings.Version))
	}
	for _, rule := range mappings.Rules {
		if rule.Pattern == "" {
			validationErrors = append(validationErrors, fmt.Errorf("rule missing pattern: %s", rule))
		}
		if rule.PolicyID == "" && rule.Replacement == "" {
			validationErrors = append(validationErrors, fmt.Errorf("rule must have policy-id or replacement: %s", rule))
		}
		if rule.PolicyID != "" && rule.Replacement != "" {
			validationErrors = append(validationErrors, fmt.Errorf("rule cannot have both policy-id and replacement: %s", rule))
		}
		if rule.Platforms != nil {
			for _, platform := range rule.Platforms {
				if platform == "" {
					validationErrors = append(validationErrors, fmt.Errorf("rule has empty platform: %s", rule))
				}
			}
		}
	}
	for _, policy := range mappings.Policies {
		if policy.ID == "" {
			validationErrors = append(validationErrors, fmt.Errorf("policy missing id: %s", policy.ID))
		}
		if len(policy.Files) == 0 {
			validationErrors = append(validationErrors, fmt.Errorf("policy missing files: %v", policy))
		}
		for _, file := range policy.Files {
			if file.Path == "" {
				validationErrors = append(validationErrors, fmt.Errorf("file missing path: %s", file))
			}
		}
	}

	if len(validationErrors) > 0 {
		return errors.Join(validationErrors...)
	}

	return nil
}

func parsePolicyMappingsFile(data []byte) (*PolicyMappings, error) {
	mappings := &policyMappingsFile{}
	err := yaml.Unmarshal(data, mappings)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy mapping file: %w", err)
	}
	err = validateMappingsFile(mappings)
	if err != nil {
		return nil, fmt.Errorf("invalid policy mapping file: %w", err)
	}
	return expandMappingFile(mappings)
}

func LoadLocalMappings(configDir string) (*PolicyMappings, error) {
	if configDir == "" {
		return nil, nil
	}
	path := filepath.Join(configDir, MappingFilename)
	mappingFile, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read local policy mapping file %s: %w", path, err)
	}
	return parsePolicyMappingsFile(mappingFile)
}

func LoadTUFMappings(tufClient tuf.Downloader, localTargetsDir string) (*PolicyMappings, error) {
	if tufClient == nil {
		return nil, fmt.Errorf("tuf client not set")
	}
	filename := MappingFilename
	file, err := tufClient.DownloadTarget(filename, filepath.Join(localTargetsDir, filename))
	if err != nil {
		return nil, fmt.Errorf("failed to download policy mapping file %s: %w", filename, err)
	}
	return parsePolicyMappingsFile(file.Data)
}

func expandMappingFile(mappingFile *policyMappingsFile) (*PolicyMappings, error) {
	policies := make(map[string]*PolicyMapping)
	for _, policy := range mappingFile.Policies {
		policies[policy.ID] = policy
	}

	var rules []*PolicyRule
	for _, rule := range mappingFile.Rules {
		patternRegex, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, err
		}
		platforms := make([]*v1.Platform, 0, len(rule.Platforms))
		for _, platform := range rule.Platforms {
			parsedPlatform, err := v1.ParsePlatform(platform)
			if err != nil {
				return nil, fmt.Errorf("failed to parse platform %s: %w", platform, err)
			}
			platforms = append(platforms, parsedPlatform)
		}

		rules = append(rules, &PolicyRule{
			Pattern:     patternRegex,
			PolicyID:    rule.PolicyID,
			Replacement: rule.Replacement,
			Platforms:   platforms,
		})
	}

	return &PolicyMappings{
		Version:  mappingFile.Version,
		Kind:     mappingFile.Kind,
		Policies: policies,
		Rules:    rules,
	}, nil
}
