package onetimepasscode

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

var testSecret = []byte("12345678901234567890")

func ExampleGenerateHOTP() {
	// Each user needs to have a preshared secret value.
	// This value must be unique per user, and kept secure.
	secret := []byte("12345678901234567890")

	// movingFactor is a value that 'moves', that is, it
	// is a value that both the client and the server are
	// able to derrive for a specific request.
	movingFactor := 123

	// Generate a hash-based one time password
	hotpCode := GenerateHOTP(
		secret,
		movingFactor,
		6,
		false,
		0,
	)

	fmt.Println(hotpCode)
	// Output: 108787
}

// Verifies HOTP generation, given example secret, movingfactor
// and truncation offset.
// Cases taken from RFC 4226 - HOTP Algorithm - December 2005
// Appendix D - HOTP Algorithm: Test Values
func Test_GenerateHOTP(t *testing.T) {
	type args struct {
		secret           []byte
		movingFactor     int
		codeDigits       int
		addChecksum      bool
		truncationOffset int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			"Case 0",
			args{
				secret:           testSecret,
				movingFactor:     0,
				codeDigits:       6,
				addChecksum:      false,
				truncationOffset: 1284755224,
			},
			"755224",
		},
		{
			"Case 1",
			args{
				secret:           testSecret,
				movingFactor:     1,
				codeDigits:       6,
				addChecksum:      false,
				truncationOffset: 1094287082,
			},
			"287082",
		},
		{
			"Case 2",
			args{
				secret:           testSecret,
				movingFactor:     2,
				codeDigits:       6,
				addChecksum:      false,
				truncationOffset: 137359152,
			},
			"359152",
		},
		{
			"Case 3",
			args{
				secret:           testSecret,
				movingFactor:     3,
				codeDigits:       6,
				addChecksum:      false,
				truncationOffset: 1726969429,
			},
			"969429",
		},
		{
			"Case 4",
			args{
				secret:           testSecret,
				movingFactor:     4,
				codeDigits:       6,
				addChecksum:      false,
				truncationOffset: 1640338314,
			},
			"338314",
		},
		{
			"Case 5",
			args{
				secret:           testSecret,
				movingFactor:     5,
				codeDigits:       6,
				addChecksum:      false,
				truncationOffset: 868254676,
			},
			"254676",
		},
		{
			"Case 6",
			args{
				secret:           testSecret,
				movingFactor:     6,
				codeDigits:       6,
				addChecksum:      false,
				truncationOffset: 1918287922,
			},
			"287922",
		},
		{
			"Case 7",
			args{
				secret:           testSecret,
				movingFactor:     7,
				codeDigits:       6,
				addChecksum:      false,
				truncationOffset: 82162583,
			},
			"162583",
		},
		{
			"Case 8",
			args{
				secret:           testSecret,
				movingFactor:     8,
				codeDigits:       6,
				addChecksum:      false,
				truncationOffset: 673399871,
			},
			"399871",
		},
		{
			"Case 9",
			args{
				secret:           testSecret,
				movingFactor:     9,
				codeDigits:       6,
				addChecksum:      false,
				truncationOffset: 645520489,
			},
			"520489",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GenerateHOTP(tt.args.secret, tt.args.movingFactor, tt.args.codeDigits, tt.args.addChecksum, tt.args.truncationOffset); got != tt.want {
				t.Errorf("GenerateHOTP() = %s, want %s", got, tt.want)
			}
		})
	}
}

// Test the intermediate HMAC value generation
// Cases taken from RFC 4226 - HOTP Algorithm - December 2005
// Appendix D - HOTP Algorithm: Test Values
func Test_hmacSha1(t *testing.T) {
	getHexString := func(src []byte) (text string) {
		dst := make([]byte, hex.EncodedLen(len(src)))
		hex.Encode(dst, src)
		return string(dst)
	}

	generateText := func(movingFactor int) []byte {
		text := make([]byte, 8)
		for i := len(text) - 1; i >= 0; i-- {
			text[i] = byte(movingFactor & 0xff)
			movingFactor >>= 8
		}
		return text
	}

	type args struct {
		key  []byte
		text []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{

			"Case 0",
			args{
				key:  testSecret,
				text: generateText(0),
			},
			"cc93cf18508d94934c64b65d8ba7667fb7cde4b0",
		},
		{

			"Case 1",
			args{
				key:  testSecret,
				text: generateText(1),
			},
			"75a48a19d4cbe100644e8ac1397eea747a2d33ab",
		},
		{

			"Case 2",
			args{
				key:  testSecret,
				text: generateText(2),
			},
			"0bacb7fa082fef30782211938bc1c5e70416ff44",
		},
		{

			"Case 3",
			args{
				key:  testSecret,
				text: generateText(3),
			},
			"66c28227d03a2d5529262ff016a1e6ef76557ece",
		},
		{

			"Case 4",
			args{
				key:  testSecret,
				text: generateText(4),
			},
			"a904c900a64b35909874b33e61c5938a8e15ed1c",
		},
		{

			"Case 5",
			args{
				key:  testSecret,
				text: generateText(5),
			},
			"a37e783d7b7233c083d4f62926c7a25f238d0316",
		},
		{

			"Case 6",
			args{
				key:  testSecret,
				text: generateText(6),
			},
			"bc9cd28561042c83f219324d3c607256c03272ae",
		},
		{

			"Case 7",
			args{
				key:  testSecret,
				text: generateText(7),
			},
			"a4fb960c0bc06e1eabb804e5b397cdc4b45596fa",
		},
		{

			"Case 8",
			args{
				key:  testSecret,
				text: generateText(8),
			},
			"1b3c89f65e6c9e883012052823443f048b4332db",
		},
		{

			"Case 9",
			args{
				key:  testSecret,
				text: generateText(9),
			},
			"1637409809a679dc698207310c8c7fc07290d9e5",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hmacSha1(tt.args.key, tt.args.text); !reflect.DeepEqual(getHexString(got), tt.want) {
				t.Errorf("hmacSha1() = %v, want %v", got, tt.want)
			}
		})
	}
}
