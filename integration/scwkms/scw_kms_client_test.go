// Copyright 2024 Scaleway
// SPDX-License-Identifier: Apache-2.0

package scwkms

import (
	"github.com/scaleway/scaleway-sdk-go/scw"
	"github.com/tink-crypto/tink-go/v2/aead"
	"log"
)

func Example() {
	const keyURIPrefix = "scw-kms://regions/<region>/keys/"
	const keyURI = keyURIPrefix + "<key_id>"

	client, err := NewClientWithOptions(keyURIPrefix,
		scw.WithDefaultOrganizationID("<organization_id>"),
		scw.WithDefaultProjectID("<project_id>"),
		scw.WithAuth("<scw_access_key>", "<scw_secret_key>"),
		scw.WithDefaultRegion("<region>"),
		scw.WithAPIURL("<scw_api_url>"))
	if err != nil {
		log.Fatal(err)
	}

	kekAEAD, err := client.GetAEAD(keyURI)
	if err != nil {
		log.Fatal(err)
	}

	// Get the KMS envelope AEAD primitive.
	dekTemplate := aead.AES256GCMKeyTemplate()
	primitive := aead.NewKMSEnvelopeAEAD2(dekTemplate, kekAEAD)
	if err != nil {
		log.Fatal(err)
	}

	// Use the primitive.
	plaintext := []byte("message")
	associatedData := []byte("example KMS envelope AEAD encryption")

	ciphertext, err := primitive.Encrypt(plaintext, associatedData)
	if err != nil {
		log.Fatal(err)
	}

	_, err = primitive.Decrypt(ciphertext, associatedData)
	if err != nil {
		log.Fatal(err)
	}
}
