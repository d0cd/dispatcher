package cloudvm

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A secret must redact through every common leak channel (fmt verbs, JSON,
// struct embedding) and only expose the raw value via reveal().
func TestSecret_RedactsEverywhereButReveal(t *testing.T) {
	const raw = "sk-super-secret-api-key-do-not-leak"
	s := secret(raw)

	// Every fmt path that would otherwise print the value. (Surrounding text keeps
	// staticcheck's S1025 from rewriting the bare-%s cases to s.String().)
	for _, got := range []string{
		fmt.Sprintf("k=[%s]", s),
		fmt.Sprintf("k=[%v]", s),
		fmt.Sprintf("k=[%+v]", s),
		fmt.Sprintf("k=[%#v]", s),
		fmt.Sprint(s),
		s.String(),
	} {
		assert.NotContains(t, got, raw, "fmt output must not contain the secret")
		assert.Contains(t, got, redacted)
	}

	// JSON marshaling — direct and embedded in a struct.
	b, err := json.Marshal(s)
	require.NoError(t, err)
	assert.NotContains(t, string(b), raw)

	type holder struct {
		Key secret `json:"key"`
	}
	hb, err := json.Marshal(holder{Key: s})
	require.NoError(t, err)
	assert.NotContains(t, string(hb), raw, "a secret field must not leak when its struct is logged as JSON")
	assert.Contains(t, string(hb), redacted)

	// reveal() is the one path that returns the real value.
	assert.Equal(t, raw, s.reveal())
	assert.False(t, s.empty())
	assert.True(t, secret("").empty())
}

// fmt cannot invoke a secret field's redaction when it's an UNEXPORTED field of a
// struct (reflection can't call methods on unexported fields), so the structs
// that hold a secret must redact themselves. Every fmt verb on the Lambda
// provider/fetcher must stay clear of the raw key.
func TestLambdaStructs_RedactKeyOnFormat(t *testing.T) {
	const raw = "sk-lambda-do-not-leak-999"
	prov := &LambdaProvider{apiKey: secret(raw), defaultRegion: "us-east-1", baseURL: "https://x"}
	fetch := &LambdaFetcher{apiKey: secret(raw), Region: "us-east-1", baseURL: "https://x"}

	for _, got := range []string{
		fmt.Sprintf("%v", prov), fmt.Sprintf("%+v", prov), fmt.Sprintf("%#v", prov), fmt.Sprintf("%v", *prov),
		fmt.Sprintf("%v", fetch), fmt.Sprintf("%+v", fetch), fmt.Sprintf("%#v", fetch), fmt.Sprintf("%v", *fetch),
	} {
		assert.NotContains(t, got, raw, "struct formatting must not leak the API key")
		assert.Contains(t, got, redacted)
	}
}
