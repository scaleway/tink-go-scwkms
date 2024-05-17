// Copyright 2024 Scaleway
// SPDX-License-Identifier: Apache-2.0

package scwkms

import (
	"github.com/scaleway/scaleway-sdk-go/api/key_manager/v1alpha1"
	"github.com/tink-crypto/tink-go/v2/tink"
)

type scwAEAD struct {
	keyId string
	kms   key_manager.API
}

var _ tink.AEAD = (*scwAEAD)(nil)

func newSCWAEAD(keyId string, kms *key_manager.API) tink.AEAD {
	return &scwAEAD{
		keyId: keyId,
		kms:   *kms,
	}
}

func (s scwAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	req := &key_manager.EncryptRequest{
		KeyID:          s.keyId,
		Plaintext:      plaintext,
		AssociatedData: &associatedData,
	}

	resp, err := s.kms.Encrypt(req)
	if err != nil {
		return nil, err
	}

	return resp.Ciphertext, nil
}

func (s scwAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	req := &key_manager.DecryptRequest{
		KeyID:          s.keyId,
		Ciphertext:     ciphertext,
		AssociatedData: &associatedData,
	}

	resp, err := s.kms.Decrypt(req)
	if err != nil {
		return nil, err
	}

	return resp.Plaintext, nil
}
