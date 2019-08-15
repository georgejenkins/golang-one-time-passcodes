package onetimepasscode

import (
	"time"
)

// GenerateTOTP generates an time based OTP value for the 
// given set of parameters.
//
// secret: the shared secret
// timeStep: the time step that each TOTP value is valid
// for. This value is derived from unix time. For example,
// a time step of 30 indicates each TOTP value is valid
// for a period of 30 seconds. 
// codeDigits: the number of digits in the OTP, not 
// including the checksum, if any.
// addChecksum  a flag that indicates if a checksum digit
// should be appended to the OTP.
// truncationOffset: the offset into the MAC result to
// begin truncation. If this value is out of the range 
// of 0 ... 15, then dynamic truncation will be used.
// Dynamic truncation is when the last 4 bits of the 
// last byte of the MAC are used to determine the start offset.
func GenerateTOTP(secret []byte, timeStep int, codeDigits int, addChecksum bool, truncationOffset int) (string)  {
	// determine current timeslice based on the mutually agreed timestep factor
	movingFactor := int(time.Now().Unix())
	movingFactor -= movingFactor % timeStep

	return generateTOTP(secret, movingFactor, codeDigits, addChecksum, truncationOffset)
}

func generateTOTP(secret []byte, movingFactor int, codeDigits int, addChecksum bool, truncationOffset int) (string)  {
	return GenerateHOTP(secret, movingFactor, codeDigits, addChecksum, truncationOffset)
}