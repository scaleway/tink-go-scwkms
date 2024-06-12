package main

import (
	"fmt"
	"log"

	"github.com/scaleway/scaleway-sdk-go/scw"
	"github.com/scaleway/tink-go-scwkms/integration/scwkms"
	"github.com/tink-crypto/tink-go/v2/aead"
)

const (
	keyURIPrefix = "scw-kms://regions/fr-par/keys/"                      // Replace with your region
	keyURI       = keyURIPrefix + "00000000-0000-0000-0000-000000000000" // Replace with your key ID
)

func main() {

	// Setup a scw configuration as usual
	config, err := scw.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}
	profile, err := config.GetActiveProfile()
	if err != nil {
		log.Fatal(err)
	}

	// Create the Tink Scaleway client
	kms, _ := scwkms.NewClientWithOptions(
		keyURIPrefix,
		scw.WithProfile(profile),
		scw.WithEnv(),
	)

	kekAEAD, _ := kms.GetAEAD(keyURI)

	dekTemplate := aead.AES256GCMKeyTemplate() // Your DEK is an AES-256-GCM key
	primitive := aead.NewKMSEnvelopeAEAD2(dekTemplate, kekAEAD)

	// Use the primitive to encrypt and decrypt data
	plaintext := []byte("Hello, World!")
	associatedData := []byte("example KMS envelope AEAD encryption")

	fmt.Println("Plaintext:", string(plaintext))

	ciphertext, err := primitive.Encrypt(plaintext, associatedData)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Ciphertext:", ciphertext)

	plaintextBack, err := primitive.Decrypt(ciphertext, associatedData)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Plaintext again:", string(plaintextBack))

}
