package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"sort"

	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/b64"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/keys"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/verify"
)

// oidcTestIssuers is the spec's known-answer/oidc-test-issuers.json, kept
// byte-equal to testdata/spec by a test.
//
//go:embed oidc-test-issuers.json
var oidcTestIssuers []byte

// trustedTestIssuer is the issuer a fixture trusts when it names none.
const trustedTestIssuer = "https://auth.openai.com"

var errNetworkRefused = errors.New("aitp-verifier-adapter: network access is refused")

// embeddedIssuers resolves the trusted OIDC test issuers' keys. The
// untrusted vector has no issuer and its key is never returned.
func embeddedIssuers() verify.IssuerKeys {
	var doc struct {
		Vectors []struct {
			Role   string `json:"role"`
			Issuer string `json:"issuer"`
			Pubkey string `json:"pubkey_b64url"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(oidcTestIssuers, &doc); err != nil {
		panic("embedded oidc-test-issuers.json: " + err.Error())
	}
	byIssuer := map[string][]*keys.PublicKey{}
	for _, v := range doc.Vectors {
		if v.Role != "trusted" || v.Issuer == "" {
			continue
		}
		raw, err := b64.DecodeLen(v.Pubkey, 32)
		if err != nil {
			panic("embedded oidc-test-issuers.json: " + err.Error())
		}
		k, err := keys.Parse(keys.Ed25519, raw)
		if err != nil {
			panic("embedded oidc-test-issuers.json: " + err.Error())
		}
		byIssuer[v.Issuer] = append(byIssuer[v.Issuer], k)
	}
	return func(issuer string) []*keys.PublicKey { return byIssuer[issuer] }
}

func sortStrings(s []string) { sort.Strings(s) }
