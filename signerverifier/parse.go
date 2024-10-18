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

package signerverifier

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const pemType = "PUBLIC KEY"

func ParsePublicKey(pubkeyBytes []byte) (crypto.PublicKey, error) {
	p, _ := pem.Decode(pubkeyBytes)
	if p == nil {
		return nil, fmt.Errorf("pubkey file does not contain any PEM data")
	}
	if p.Type != pemType {
		return nil, fmt.Errorf("pubkey file does not contain a public key")
	}
	return x509.ParsePKIXPublicKey(p.Bytes)
}

func ParseECDSAPublicKey(pubkeyBytes []byte) (*ecdsa.PublicKey, error) {
	pk, err := ParsePublicKey(pubkeyBytes)
	if err != nil {
		return nil, err
	}
	ecdsaPubKey, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("error public key is not an ecdsa key: %w", err)
	}
	return ecdsaPubKey, nil
}

func ConvertToPEM(ecdsaPubKey *ecdsa.PublicKey) ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(ecdsaPubKey)
	if err != nil {
		return nil, fmt.Errorf("error failed to marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: pubKeyBytes}), nil
}
