package attestation

import "encoding/base64"

const (
	DockerDsseExtKind = "application/vnd.docker.attestation-verification.v1+json"
	RekorTlExtKind    = "Rekor"
)

var base64Encoding = base64.StdEncoding.Strict()

// the following types are needed until https://github.com/secure-systems-lab/dsse/pull/61 is merged
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}
type Signature struct {
	KeyID     string    `json:"keyid"`
	Sig       string    `json:"sig"`
	Extension Extension `json:"extension"`
}
type Extension struct {
	Kind string              `json:"kind"`
	Ext  DockerDsseExtension `json:"ext"`
}

type DockerDsseExtension struct {
	Tl DockerTlExtension `json:"tl"`
}

type DockerTlExtension struct {
	Kind string `json:"kind"`
	Data any    `json:"data"`
}
