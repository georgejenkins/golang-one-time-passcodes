// Package onetimepasscode provides an implementation of the following IETF RFCs, 
// providing hash based and time based one time passcodes (OTP). 
//
// RFC4226 - HOTP: An HMAC-Based One-Time Password Algorithm
// RFC6238 - TOTP: Time-Based One-Time Password Algorithm
//
// Licensed under Apache License, v2.0
package onetimepasscode

import (
	"crypto/hmac"
	"crypto/sha1"
	"strconv"
)

// Calculates the checksum using the credit card algorithm.
// This algorithm has the advantage that it detects any single
// mistyped digit and any single transposition of
// adjacent digits.
//
// num: the number to calculate the checksum for
// digits: number of significant places in the number
//
// returns the checksum of num
func calcChecksum(num int, digits int) (int) {
	doubleDigits := [...]int { 0, 2, 4, 6, 8, 1, 3, 5, 7, 9 }	 
	doubleDigit := true
	total := 0

	for 0 < digits {
		digits--
		digit := num % 10
		num /= 10
		if (doubleDigit) {
			digit = doubleDigits[digit]
		}
		total += digit
		doubleDigit = !doubleDigit
	}

	result := total % 10
	if (result > 10) {
		result = 10 - result
	}
	return result
}

// This method provides the HMAC-SHA-1 algorithm.
//
// HMAC computes a Hashed Message Authentication Code and
// in this case SHA1 is the hash algorithm used.
//
// keyBytes: the bytes to use for the HMAC-SHA-1 key
// text:  the message or text to be authenticated.
//
// returns the HMAC SHA1 result of 
func hmacSha1(key []byte, text []byte) ([]byte) {
	h := hmac.New(sha1.New, key)
	h.Write(text)
	return h.Sum(nil)
}

// GenerateHOTP returns an hash-based one time passcode.
// This function requires that the moving factor that
// calculates the OTP can be calcualted by both the 
// client and the server. Alternatively, GenerateTOTP
// uses RFC6238 to generate OTP codes based on unix
// times, and is recommended is most circumstances. 
//
// The shared secret is a value that is pre-shared between
// the client and the server, and must be kept secret. 
// This value must also be unique for each client. 
// The moving factor is a value that changes frequently,
// but not necessarily for each authentication request. 
// This must be a random value that both the client and 
// server know how to calculate. The code digits is the 
// length of the OTP to be created. The add 
// checksum flag determines whether a checksum digit is
// to be appended to the OTP. The truncation offset 
// controls the offset into the MAC that truncation 
// will begin at. If this value is out of the range 
// of 0 ... 15, then dynamic truncation will be used.
// Dynamic truncation is when the last 4 bits of the 
// last byte of the MAC are used to determine the start 
// offset.
func GenerateHOTP(secret []byte, movingFactor int, codeDigits int, addChecksum bool, truncationOffset int) (string)  {
	digitsPower := [...]int {1,10,100,1000,10000,100000,1000000,10000000,100000000}

	if (addChecksum) {
		codeDigits++
	}

	// put movingFactor value into text byte array
	text := make([]byte, 8)
	for i := len(text) - 1; i >= 0; i-- {
		text[i] = byte(movingFactor & 0xff)
		movingFactor =  movingFactor >> 8
	} 

	// compute hmac hash
	hash := hmacSha1(secret, text)

	// put selected bytes into result int
	offset := int(hash[len(hash) - 1] & 0xf)
	if ((0 <= truncationOffset) && (truncationOffset < (len(hash) - 4))) {
		offset = truncationOffset
	}

	binary := (int(hash[offset] & 0x7f) << 24) | (int(hash[offset + 1] & 0xff) << 16) | (int(hash[offset + 2] & 0xff) << 8) | int(hash[offset + 3] & 0xff)

	otp := int(binary) % digitsPower[codeDigits]
	if (addChecksum) {
		otp = (otp * 10) + calcChecksum(otp, codeDigits)
	}

	result := strconv.Itoa(otp)
	for (len(result) < codeDigits) {
		result = "0" + result
	}

	return result
}
