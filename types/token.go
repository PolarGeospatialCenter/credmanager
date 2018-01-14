package types

// TokenRequest is the type sent by a client when requesting a token
type Request struct {
	ClientID string
}

// TokenResponse returned upon a successful token request
type Response struct {
	SecretID string
}
