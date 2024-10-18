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

package oci

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// ensure RegistryImageDetailsResolver implements ImageDetailsResolver.
var _ ImageDetailsResolver = &RegistryImageDetailsResolver{}

type RegistryImageDetailsResolver struct {
	*ImageSpec
	descriptor *v1.Descriptor
}

func NewRegistryImageDetailsResolver(src *ImageSpec) (*RegistryImageDetailsResolver, error) {
	return &RegistryImageDetailsResolver{
		ImageSpec: src,
	}, nil
}

func (r *RegistryImageDetailsResolver) ImageName(_ context.Context) (string, error) {
	return r.Identifier, nil
}

func (r *RegistryImageDetailsResolver) ImagePlatform(_ context.Context) (*v1.Platform, error) {
	return r.Platform, nil
}

func (r *RegistryImageDetailsResolver) ImageDescriptor(ctx context.Context) (*v1.Descriptor, error) {
	if r.descriptor == nil {
		subjectRef, err := name.ParseReference(r.Identifier)
		if err != nil {
			return nil, fmt.Errorf("failed to parse reference: %w", err)
		}
		options := WithOptions(ctx, r.Platform)
		image, err := remote.Image(subjectRef, options...)
		if err != nil {
			return nil, fmt.Errorf("failed to get image manifest: %w", err)
		}
		digest, err := image.Digest()
		if err != nil {
			return nil, fmt.Errorf("failed to get image digest: %w", err)
		}
		size, err := image.Size()
		if err != nil {
			return nil, fmt.Errorf("failed to get image size: %w", err)
		}
		mediaType, err := image.MediaType()
		if err != nil {
			return nil, fmt.Errorf("failed to get image media type: %w", err)
		}
		r.descriptor = &v1.Descriptor{
			Digest:    digest,
			Size:      size,
			MediaType: mediaType,
		}
	}
	return r.descriptor, nil
}
