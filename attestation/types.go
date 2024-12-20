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
	"crypto"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/docker/attest/tlog"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	slsav1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	ociv1 "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	DockerReferenceType           = "vnd.docker.reference.type"
	AttestationManifestType       = "attestation-manifest"
	InTotoPredicateType           = "in-toto.io/predicate-type"
	DockerReferenceDigest         = "vnd.docker.reference.digest"
	DockerDSSEExtKind             = "application/vnd.docker.attestation-verification.v1+json"
	OCIDescriptorDSSEMediaType    = ociv1.MediaTypeDescriptor + "+dsse"
	InTotoReferenceLifecycleStage = "vnd.docker.lifecycle-stage"
	LifecycleStageExperimental    = "experimental"
)

var base64Encoding = base64.StdEncoding.Strict()

type Layer struct {
	Statement   *intoto.Statement
	Layer       v1.Layer
	Annotations map[string]string
}

type Manifest struct {
	OriginalDescriptor *v1.Descriptor
	OriginalLayers     []*Layer

	// accumulated during signing
	SignedLayers []*Layer
	// details of subject image
	SubjectName       string
	SubjectDescriptor *v1.Descriptor
}

type ManifestImageOptions struct {
	// how to output the image
	skipSubject   bool
	replaceLayers bool
	laxReferrers  bool
}

// the following types are needed until https://github.com/secure-systems-lab/dsse/pull/61 is merged.
type Envelope struct {
	PayloadType string       `json:"payloadType"`
	Payload     string       `json:"payload"`
	Signatures  []*Signature `json:"signatures"`
}
type Signature struct {
	KeyID     string     `json:"keyid"`
	Sig       string     `json:"sig"`
	Extension *Extension `json:"extension,omitempty"`
}
type Extension struct {
	Kind string               `json:"kind"`
	Ext  *DockerDSSEExtension `json:"ext"`
}

type EnvelopeReference struct {
	*Envelope
	ResourceDescriptor *ResourceDescriptor `json:"resourceDescriptor"`
}

type ResourceDescriptor struct {
	MediaType string            `json:"mediaType"`
	Digest    map[string]string `json:"digest"`
	URI       string            `json:"uri,omitempty"`
}

type AnnotatedStatement struct {
	OCIDescriptor   *v1.Descriptor
	InTotoStatement *intoto.Statement
	Annotations     map[string]string
}

type DockerDSSEExtension struct {
	TL *tlog.DockerTLExtension `json:"tl"`
}

type TransparencyLogKind string

const (
	RekorTransparencyLogKind = "rekor"
)

type VerifyOptions struct {
	Keys            []*KeyMetadata      `json:"keys"`
	SkipTL          bool                `json:"skip_tl"`
	TransparencyLog TransparencyLogKind `json:"tl"`
}

type KeyMetadata struct {
	ID            string     `json:"id"`
	PEM           string     `json:"key"`
	From          time.Time  `json:"from"`
	To            *time.Time `json:"to"`
	Status        string     `json:"status"`
	SigningFormat string     `json:"signing-format"`
	Distrust      bool       `json:"distrust,omitempty"`
	publicKey     crypto.PublicKey
}

type (
	Keys    []*KeyMetadata
	KeysMap map[string]*KeyMetadata
)

type SigningOptions struct {
	// set this in order to log to a transparency log
	TransparencyLog tlog.TransparencyLog
}

type Options struct {
	NoReferrers   bool
	Attach        bool
	ReferrersRepo string
}

func DSSEMediaType(predicateType string) (string, error) {
	var predicateName string
	switch predicateType {
	case slsav1.PredicateSLSAProvenance:
		predicateName = "provenance"
	case v02.PredicateSLSAProvenance:
		predicateName = "provenance"
	case intoto.PredicateSPDX:
		predicateName = "spdx"
	case VSAPredicateType:
		predicateName = "verification_summary"

	default:
		return "", fmt.Errorf("unknown predicate type %q", predicateType)
	}

	return fmt.Sprintf("application/vnd.in-toto.%s+dsse", predicateName), nil
}
