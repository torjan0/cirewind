package githubapi

import (
	"context"
	"errors"
	"os"
	"strings"
)

// TokenSource is the only authentication boundary in this package. Tokens are
// requested immediately before an API request and are never added to result
// DTOs, errors, evidence metadata, redirect requests, or logs.
type TokenSource interface {
	Token(context.Context) (string, error)
}

type TokenSourceFunc func(context.Context) (string, error)

func (f TokenSourceFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

type noTokenSource struct{}

func (noTokenSource) Token(context.Context) (string, error) { return "", nil }

func NoToken() TokenSource { return noTokenSource{} }

// StaticToken is intended for a token already resolved by the CLI. Prefer
// EnvToken for normal use so no token needs to appear in command arguments.
func StaticToken(token string) TokenSource {
	return TokenSourceFunc(func(context.Context) (string, error) { return token, nil })
}

// EnvToken resolves the first non-empty token in the conservative documented
// order. The returned source does not read the environment until a request is
// made, which keeps authentication outside configuration serialization.
func EnvToken() TokenSource {
	return EnvTokenWithLookup(os.LookupEnv)
}

func EnvTokenWithLookup(lookup func(string) (string, bool)) TokenSource {
	return TokenSourceFunc(func(context.Context) (string, error) {
		if lookup == nil {
			return "", errors.New("token environment lookup is unavailable")
		}
		for _, name := range []string{"CIREWIND_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"} {
			if value, ok := lookup(name); ok && strings.TrimSpace(value) != "" {
				return value, nil
			}
		}
		return "", nil
	})
}
