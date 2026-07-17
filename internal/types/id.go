package types

import (
	"crypto/rand"
	"fmt"
	"time"
)

// ShortID generates a random 7-character alphanumeric ID. It uses rejection
// sampling so every symbol is equally likely — a plain byte%36 would over-
// represent the first four symbols (256 is not a multiple of 36).
func ShortID() string {
	const chars = "0123456789abcdefghijklmnopqrstuvwxyz"
	const maxUnbiased = 256 - (256 % len(chars)) // 252: reject bytes at/above this
	out := make([]byte, 0, 7)
	var buf [1]byte
	for len(out) < 7 {
		if _, err := rand.Read(buf[:]); err != nil {
			return fmt.Sprintf("%x", time.Now().UnixNano())
		}
		if int(buf[0]) >= maxUnbiased {
			continue // would bias the distribution; draw again
		}
		out = append(out, chars[int(buf[0])%len(chars)])
	}
	return string(out)
}
