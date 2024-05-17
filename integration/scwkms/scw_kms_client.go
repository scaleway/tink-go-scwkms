// Copyright 2024 Scaleway
// SPDX-License-Identifier: Apache-2.0

package scwkms

import (
	"errors"
	"fmt"
	"strings"

	"github.com/scaleway/scaleway-sdk-go/api/key_manager/v1alpha1"
	"github.com/scaleway/scaleway-sdk-go/scw"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/tink"
)

const (
	scwPrefix     = "scw-kms://"
	tinkUserAgent = "Tink/" + tink.Version
)

type scwClient struct {
	keyURIPrefix string
	kms          *key_manager.API
}

var _ registry.KMSClient = (*scwClient)(nil)

func NewClient(uriPrefix string) (registry.KMSClient, error) {
	return NewClientWithOptions(uriPrefix, scw.WithEnv())
}

func NewClientWithOptions(uriPrefix string, opts ...scw.ClientOption) (registry.KMSClient, error) {
	if !strings.HasPrefix(strings.ToLower(uriPrefix), scwPrefix) {
		return nil, fmt.Errorf("uriPrefix must start with %s", scwPrefix)
	}

	opts = append(opts, scw.WithUserAgent(tinkUserAgent))

	client, err := scw.NewClient(opts...)
	if err != nil {
		return nil, err
	}

	return &scwClient{
		keyURIPrefix: uriPrefix,
		kms:          key_manager.NewAPI(client),
	}, nil
}

func (c *scwClient) Supported(keyURI string) bool {
	return strings.HasPrefix(keyURI, c.keyURIPrefix)
}

func (c *scwClient) GetAEAD(keyURI string) (tink.AEAD, error) {
	if !c.Supported(keyURI) {
		return nil, errors.New("unsupported keyURI")
	}

	keyId := strings.TrimPrefix(keyURI, c.keyURIPrefix)
	return newSCWAEAD(keyId, c.kms), nil
}
