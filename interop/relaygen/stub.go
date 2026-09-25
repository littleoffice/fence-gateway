//go:build relaygen

package main

import "crypto/ed25519"

// The fields of the relay's Server and Config that fence.go reads. If the relay
// renames one, the regeneration fails to compile — which is the point: the
// vectors must come from its fence.go unmodified.
type Config struct{ FencePreamble string }

type Server struct {
	config          Config
	fencePublicKey  ed25519.PublicKey
	fenceSigningKey ed25519.PrivateKey
}
