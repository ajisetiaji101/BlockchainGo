package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// GenerateHMAC generates an HMAC using the key and timestamp
func GenerateHMAC(key string, timestamp int64) string {
	// Combine the key and timestamp
	combinedKey := fmt.Sprintf("%s:%d", key, timestamp)

	// Create a new HMAC using SHA256
	h := hmac.New(sha256.New, []byte(combinedKey))

	// Get the resulting HMAC as a byte slice
	hmacBytes := h.Sum(nil)

	// Convert to hexadecimal string
	return hex.EncodeToString(hmacBytes)
}

// VerifyHMAC verifies the HMAC and checks if the timestamp is within the allowed time window
func VerifyHMAC(key, receivedHMAC string, timestamp int64, allowedSkew int64) error {
	// Get the current timestamp
	currentTimestamp := time.Now().Unix()

	// Check if the timestamp is within the allowed time window
	if timestamp < currentTimestamp-allowedSkew || timestamp > currentTimestamp+allowedSkew {
		return errors.New("timestamp is outside the allowed time window")
	}

	// Recalculate the HMAC using the same logic
	expectedHMAC := GenerateHMAC(key, timestamp)

	// Use hmac.Equal to compare the HMACs securely
	if !hmac.Equal([]byte(expectedHMAC), []byte(receivedHMAC)) {
		return errors.New("HMAC verification failed")
	}

	return nil
}
