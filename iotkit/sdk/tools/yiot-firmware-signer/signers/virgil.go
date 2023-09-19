//   Copyright (C) 2015-2019 Virgil Security Inc.
//
//   All rights reserved.
//
//   Redistribution and use in source and binary forms, with or without
//   modification, are permitted provided that the following conditions are
//   met:
//
//       (1) Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//       (2) Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in
//       the documentation and/or other materials provided with the
//       distribution.
//
//       (3) Neither the name of the copyright holder nor the names of its
//       contributors may be used to endorse or promote products derived from
//       this software without specific prior written permission.
//
//   THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//   DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//   IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//   POSSIBILITY OF SUCH DAMAGE.
//
//   Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

package signers

import (
	"fmt"
	"io/ioutil"

	virgil_crypto_go "gopkg.in/virgilsecurity/virgil-crypto-go.v5"

	"../converters"
)

var (
	crypto = virgil_crypto_go.NewVirgilCrypto()
)

func init() {
	crypto.UseSha256Fingerprints = true
}

const (
	// TODO: remove hardcoded EC type after KeyManager support of different EC types
	SIGNER_KEY_EC_TYPE = converters.VS_KEYPAIR_EC_SECP256R1
)

func Sign(data []byte, keyPath string) (signature []byte, err error) {

	fmt.Printf("Signing data by %s\n", keyPath)

	// Read key from file
	keyFileBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key at path %s: %v", keyPath, err)
	}
	privateKey, err := crypto.ImportPrivateKey(keyFileBytes, "")
	if err != nil {
		return nil, fmt.Errorf("failed to import private key %s: %v", keyPath, err)
	}

	// Sign data and get signature in Virgil format
	virgilSignature, err := crypto.Sign(data, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %v", err)
	}

	fmt.Println("Data signed successfully:")

	return virgilSignature, nil
}
