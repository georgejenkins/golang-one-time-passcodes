package onetimepasscode

import "crypto/subtle"

// VerifyOTP tests to ensure the two OTP match in a 
// cryptographically safe fashion. It returns true if 
// the OTP match, otherwise false.
func VerifyOTP(clientOTP, serverOTP []byte) (bool) {
	return subtle.ConstantTimeCompare(clientOTP, serverOTP) == 1
}