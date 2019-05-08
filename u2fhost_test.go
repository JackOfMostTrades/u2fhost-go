package u2fhost

import (
	"crypto/rand"
	"testing"
)

func TestRegisterAndAuthenticate(t *testing.T) {
	u2fh, err := NewU2fh()
	if err != nil {
		t.Fatal(err)
	}
	defer u2fh.Close()

	devices, err := u2fh.GetDevices()
	if err != nil {
		t.Fatal(err)
	}
	defer devices.Close()

	for i := uint(0); i < devices.Count(); i++ {
		desc, err := devices.Describe(i)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(desc)
	}

	challenge := make([]byte, 32)
	_, err = rand.Read(challenge)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := devices.Register(challenge, "https://demo.yubico.com")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(resp.RegistrationData)
	t.Log(resp.ClientData)

	regData, err := ParseRegistrationData(resp.RegistrationData)
	if err != nil {
		t.Fatal(err)
	}

	authRes, err := devices.Authenticate(challenge, "https://demo.yubico.com", regData.KeyHandle)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(authRes.Signature)
}
