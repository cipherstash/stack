package auth

import (
	"context"
	"errors"

	"golang.org/x/oauth2"
)

// OAuth2TokenSource adapts an existing x/oauth2 provider to OIDCProvider.
// Its AccessToken is read afresh whenever the Rust federation strategy asks.
func OAuth2TokenSource(source oauth2.TokenSource) OIDCProvider {
	return OIDCProviderFunc(func(context.Context) (string, error) {
		if source == nil {
			return "", errors.New("auth: nil oauth2 token source")
		}
		token, err := source.Token()
		if err != nil {
			return "", err
		}
		if token == nil || token.AccessToken == "" {
			return "", errors.New("auth: oauth2 source returned no access token")
		}
		return token.AccessToken, nil
	})
}
