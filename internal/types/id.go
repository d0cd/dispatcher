package types

import (
	"crypto/rand"
	"fmt"
	"time"
)

// ShortID generates a random 7-character alphanumeric ID.
func ShortID() string {
	const chars = "0123456789abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, 7)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}
