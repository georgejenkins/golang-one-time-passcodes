package onetimepasscode

import (
	"time"
)

// GenerateTOTP generates an time based OTP value for the
// given set of parameters. The OTP is generated using the
// RFC4226 HOTP implementation as a basis for OTP generation.
//
// The shared secret is a value that is pre-shared between
// the client and the server, and must be kept secret.
// This value must also be unique for each client.
// The time step that each TOTP value is valid for. This
// value is derived from the current unix time. For example,
// a time step of 30 indicates each TOTP value is valid
// for a period of 30 seconds. The code digits is the
// length of the OTP to be created. The add
// checksum flag determines whether a checksum digit is
// to be appended to the OTP. The truncation offset
// controls the offset into the MAC that truncation
// will begin at. If this value is out of the range
// of 0 ... 15, then dynamic truncation will be used.
// Dynamic truncation is when the last 4 bits of the
// last byte of the MAC are used to determine the start
// offset.
func GenerateTOTP(secret []byte, timeStep int, codeDigits int, addChecksum bool, truncationOffset int) string {
	// determine current timeslice based on the mutually agreed timestep factor
	movingFactor := int(time.Now().Unix())
	movingFactor -= movingFactor % timeStep

	return generateTOTP(secret, movingFactor, codeDigits, addChecksum, truncationOffset)
}

func generateTOTP(secret []byte, movingFactor int, codeDigits int, addChecksum bool, truncationOffset int) string {
	return GenerateHOTP(secret, movingFactor, codeDigits, addChecksum, truncationOffset)
}
