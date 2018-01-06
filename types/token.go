package types

// TokenRequest is the type sent by a client when requesting a token
type TokenRequest struct {
	Hostname string
	Policies []string
}

// TokenResponse returned upon a successful token request
type TokenResponse struct {
	Token string
}
