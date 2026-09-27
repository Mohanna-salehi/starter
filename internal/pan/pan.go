// Package pan implements PAN validation and masking.
//
// The rules live in ../PROJECT.md §3.1. The Luhn algorithm, with worked
// examples, is explained in ../LUHN.md.
package pan

import (
	"errors"
	"strconv"
)

// ErrInvalidPAN is returned by Mask when the input is not 12–19 ASCII digits.
var ErrInvalidPAN = errors.New("pan must be 12-19 digits")

// IsLuhnValid reports whether pan passes the Luhn (mod 10) checksum.
//
// Only digits are accepted; the empty string and non-digits return false.
// Length is not checked here — see LUHN.md "Relation to this project".
//
// TODO: implement per LUHN.md.
func CheckDigit(pan string, i int) bool {
	if pan[i] < '0' || pan[i] > '9' {
		return false
	}
	return true
}

func IsLuhnValid(pan string) bool {
	if pan == "" {
		return false
	}
	sum := 0
	double := false
	for i := len(pan) - 1; i >= 0; i-- {
		if !CheckDigit(pan, i) {
			return false
		}
		num, err := strconv.Atoi(string(pan[i]))
		if err != nil {
			return false
		}
		if double {
			num *= 2
			if num > 9 {
				num -= 9
			}
		}
		sum += num
		double = !double
	}
	return sum%10 == 0
}

// Mask returns pan with every digit between the first 6 and the last 4
// replaced by '*'. The result has the same length as the input.
//
// Mask requires 12–19 ASCII digits but does NOT require Luhn validity —
// invalid-but-well-formed PANs must still be maskable.
//
// TODO: implement; return ErrInvalidPAN for bad input.
func Mask(pan string) (string, error) {
	result := ""
	if len(pan) < 12 || len(pan) > 19 {
		return "", ErrInvalidPAN
	}
	for i := 0; i < len(pan); i++ {
		if !CheckDigit(pan, i) {
			return "", ErrInvalidPAN
		}
		if i >= 6 && i < len(pan)-4 {
			result += "*"
		} else {
			//point
			result += string(pan[i])
		}
	}
	return result, nil
}
