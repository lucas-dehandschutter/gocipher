package crypto

import (
	"math"
	"runtime"
)

// ZeroMemory overwrites the given byte slice with zeros to remove sensitive data from memory.
func ZeroMemory(b []byte) {
	if len(b) == 0 {
		return
	}
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// EstimatePasswordStrength estimates the security strength of a password
// based on Shannon entropy. It returns the calculated entropy in bits
// and a colorized string representing the strength classification.
func EstimatePasswordStrength(password []byte) (float64, string) {
	if len(password) == 0 {
		return 0, "\033[31mEmpty\033[0m"
	}

	var hasLower, hasUpper, hasDigit, hasSpecial bool
	for _, char := range password {
		if char >= 'a' && char <= 'z' {
			hasLower = true
		} else if char >= 'A' && char <= 'Z' {
			hasUpper = true
		} else if char >= '0' && char <= '9' {
			hasDigit = true
		} else {
			hasSpecial = true
		}
	}

	poolSize := 0
	if hasLower {
		poolSize += 26
	}
	if hasUpper {
		poolSize += 26
	}
	if hasDigit {
		poolSize += 10
	}
	if hasSpecial {
		poolSize += 33
	}

	entropy := float64(len(password)) * math.Log2(float64(poolSize))

	var label string
	if entropy < 36 {
		label = "\033[31mWeak\033[0m"
	} else if entropy < 60 {
		label = "\033[33mMedium\033[0m"
	} else if entropy < 80 {
		label = "\033[32mStrong\033[0m"
	} else {
		label = "\033[32;1mVery Strong\033[0m"
	}

	return entropy, label
}
