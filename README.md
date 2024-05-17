# Tink Go Scaleway's Key Manager extension

This is an extension to the [Tink Go](https://github.com/tink-crypto/tink-go)
library that provides support for Scaleway's Key Manager.

The official documentation is available at https://developers.google.com/tink.

## Getting Started

1. Create a Key in Scaleway's Key Manager and retrieve its ID.
2. Check the [example](./integration/scwkms/scw_kms_client_test.go) to use the
   extension. Make sure to replace the client fields with your own
   configuration.