package onetimepasscode

import (
	"fmt"
	"testing"
	"time"
)

func ExampleGenerateTOTP() {
	// Each user needs to have a preshared secret value.
	// This value must be unique per user, and kept secure.
	secret := []byte("12345678901234567890")

	// timestep is the number of seconds that the TOTP value
	// is valid for. This value is used to generate the hash
	// in conjunction with the current unix time. An example
	// of 30 means that every 30 seconds has a unique TOTP
	// value. As time progresses, new TOTP values will be
	// generated.
	timeStep := 30

	// Generate a hash-based one time password
	hotpCode := GenerateHOTP(
		secret,
		timeStep,
		// Generates a 6 digit OTP
		6,
		// Will not add a checksum digit to the end
		false,
		// Sets the truncation offset to 0
		0,
	)

	// Some TOTP code dependent on the time the
	// function is invoked.

	fmt.Println(hotpCode)
	// Output: 243384
}

func Test_GenerateTOTP(t *testing.T) {
	type args struct {
		secret           []byte
		timeStep         int
		codeDigits       int
		addChecksum      bool
		truncationOffset int
	}
	tests := []struct {
		name          string
		args          args
		timesToSample int
	}{
		{
			"test",
			args{
				secret:           testSecret,
				timeStep:         1,
				codeDigits:       6,
				addChecksum:      false,
				truncationOffset: 1284755224,
			},
			3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codes := make([]string, tt.timesToSample)
			for i := 0; i < tt.timesToSample; i++ {
				// generate a TOTP, then wait for the next valid TOTP window
				codes[i] = GenerateTOTP(tt.args.secret, tt.args.timeStep, tt.args.codeDigits, tt.args.addChecksum, tt.args.truncationOffset)
				time.Sleep(1 * time.Second)
			}

			totpMap := make(map[string]bool)
			for i := 0; i < tt.timesToSample; i++ {
				// validate the totp with a unique map lookup
				if totpMap[codes[i]] == true {
					t.Errorf("GenerateHOTP() = duplicate TOTP found: %s", codes[i])
				}
				totpMap[codes[i]] = true
			}
		})
	}
}
