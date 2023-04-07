package PasswordGenerator

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type PasswordPolicy struct {
	Length           int
	IncludeCharGroup []string // ex) ["ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", "0123456789", "!@~#$%^&*()_"]
}

const (
	CharGroupCapital = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	CharGroupLower   = "abcdefghijklmnopqrstuvwxyz"
	CharGroupNumber  = "0123456789"
	CharGroupSymbol  = "!@~#$%^&*()_"
)

func Generate(policy PasswordPolicy) (string, error) {
	var charGroupIndex int
	var password string
	for i := 0; i < policy.Length; i++ {
		charGroup := policy.IncludeCharGroup[charGroupIndex]
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charGroup))))
		if err != nil {
			return "", fmt.Errorf("generate password failed")
		}

		password += string(policy.IncludeCharGroup[charGroupIndex][num.Int64()])
		if charGroupIndex == len(policy.IncludeCharGroup)-1 {
			charGroupIndex = 0
		} else {
			charGroupIndex++
		}
	}

	return password, nil
}
