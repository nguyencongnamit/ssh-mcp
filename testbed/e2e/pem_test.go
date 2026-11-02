//go:build e2e

package e2e

import "encoding/pem"

func pemEncode(b *pem.Block) []byte { return pem.EncodeToMemory(b) }
