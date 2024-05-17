// Copyright 2024 Scaleway
// SPDX-License-Identifier: Apache-2.0

package scwkms_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/scaleway/scaleway-sdk-go/scw"
	"github.com/scaleway/tink-go-scwkms/integration/scwkms"
	"github.com/tink-crypto/tink-go/v2/aead"
)

func TestGetAeadWithEnvelopeAead(t *testing.T) {
	cfg := scw.LoadEnvProfile()

	keyURIPrefix := "scw-kms://regions/" + *cfg.DefaultRegion + "/keys/"
	keyURI := keyURIPrefix + os.Getenv("SCW_KEY_ID")

	scwClient, err := scwkms.NewClientWithOptions(
		keyURIPrefix,
		scw.WithDefaultOrganizationID(*cfg.DefaultOrganizationID),
		scw.WithDefaultProjectID(*cfg.DefaultProjectID),
		scw.WithAuth(*cfg.AccessKey, *cfg.SecretKey),
		scw.WithDefaultRegion(scw.Region(*cfg.DefaultRegion)),
		scw.WithAPIURL(*cfg.APIURL),
	)
	if err != nil {
		t.Fatalf("scwkms.NewClientWithOptions() err = %q, want nil", err)
	}

	kekAEAD, err := scwClient.GetAEAD(keyURI)
	if err != nil {
		t.Fatalf("scwClient.GetAEAD(keyURI) err = %q, want nil", err)
	}

	dekTemplate := aead.AES256GCMKeyTemplate()
	a := aead.NewKMSEnvelopeAEAD2(dekTemplate, kekAEAD)

	plaintext := []byte("message")
	associatedData := []byte("example KMS envelope AEAD encryption")

	ciphertext, err := a.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatalf("a.Encrypt(plaintext, associatedData) err = %q, want nil", err)
	}

	gotPlaintext, err := a.Decrypt(ciphertext, associatedData)
	if err != nil {
		t.Fatalf("a.Decrypt(ciphertext, associatedData) err = %q, want nil", err)
	}

	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Errorf("a.Decrypt() = %q, want %q", gotPlaintext, plaintext)
	}

	_, err = a.Decrypt(ciphertext, []byte("invalid associatedData"))
	if err == nil {
		t.Error("a.Decrypt(ciphertext, []byte(\"invalid associatedData\")) err = nil, want error")
	}
}
