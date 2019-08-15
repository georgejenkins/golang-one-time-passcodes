package onetimepasscode

import "testing"

func TestVerifyOTP(t *testing.T) {
	type args struct {
		clientOTP []byte
		serverOTP []byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			"Valid codes",
			args{
				[]byte("123456"),
				[]byte("123456"),
			},
			true,
		},
		{
			"Invalid codes",
			args{
				[]byte("123456"),
				[]byte("654321"),
			},
			false,
		},
		{
			"No client codes",
			args{
				[]byte(""),
				[]byte("654321"),
			},
			false,
		},
		{
			"No server codes",
			args{
				[]byte("123456"),
				[]byte(""),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerifyOTP(tt.args.clientOTP, tt.args.serverOTP); got != tt.want {
				t.Errorf("VerifyOTP() = %v, want %v", got, tt.want)
			}
		})
	}
}
