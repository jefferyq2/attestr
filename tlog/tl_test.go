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

package tlog

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/docker/attest/internal/util"
	"github.com/docker/attest/signerverifier"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/stretchr/testify/assert"
)

const (
	// test artifacts.
	TestPayload   = "test"
	TestPublicKey = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAED4V+REhx+aqWH7ylMMDHahNMnMLS\nOJP/9kAm9lp+3mqYTAhURra6OD5Qx8Zbd+euPyPk9y+w/gWGDB9zn/Il1A==\n-----END PUBLIC KEY-----"
)

func TestCreateX509Cert(t *testing.T) {
	// TODO - replace with mock KMS
	// generate test signing keys
	signer, err := signerverifier.GenKeyPair()
	assert.NoError(t, err)

	// create x509 cert
	cert, err := CreateX509Cert("test", signer)
	assert.NoError(t, err)
	p, _ := pem.Decode(cert)
	result, err := x509.ParseCertificate(p.Bytes)
	assert.NoError(t, err)

	// test cert RawSubjectPublicKeyInfo field contains ephemeral public key
	ecPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	assert.NoError(t, err)
	assert.Equalf(t, string(result.RawSubjectPublicKeyInfo), string(ecPub), "certificate raw subject public key info does not match ephemeral public key")

	// test cert common name == subject
	assert.Equalf(t, result.Subject.CommonName, "test", "cert common name does not equal subject id")
}

func TestUploadAndVerifyLogEntry(t *testing.T) {
	// message digest
	payload := []byte("test")
	hash := util.SHA256(payload)

	// generate ephemeral keys to sign message digest
	signer, err := signerverifier.GenKeyPair()
	assert.NoError(t, err)
	sig, err := signer.Sign(context.Background(), hash)
	assert.NoError(t, err)

	var tl TransparencyLog
	if UseMockTL {
		tl = &MockTransparencyLog{
			UploadLogEntryFunc: func(_ context.Context, _ string, _ []byte, _ []byte, _ dsse.SignerVerifier) (*DockerTLExtension, error) {
				return &DockerTLExtension{
					Kind: RekorTLExtKind,
					Data: []byte(TestEntry),
				}, nil
			},
			VerifyLogEntryFunc: func(_ context.Context, _ *DockerTLExtension, _, _ []byte) (time.Time, error) {
				return time.Time{}, nil
			},
		}
	} else {
		assert.NoError(t, err)
	}

	// test upload log entry
	ctx := context.Background()
	entry, err := tl.UploadEntry(ctx, "test", payload, sig, signer)
	assert.NoError(t, err)

	// verify TL entry
	ecPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	assert.NoError(t, err)
	_, err = tl.VerifyEntry(ctx, entry, payload, ecPub)
	assert.NoError(t, err)
}
