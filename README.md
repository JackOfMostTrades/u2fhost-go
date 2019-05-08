u2fhost-go
==========

This library wraps [Yubico's libu2f-host](https://github.com/Yubico/libu2f-host) native library.

Example Usage:

```go
import "github.com/JackOfMostTrades/u2fhost-go"

func main() {
	u2fh, err := u2fhost.New()
	if err != nil {
		panic(err)
	}
	defer u2fh.Close()

	devices, err := u2fh.GetDevices()
	if err != nil {
		panic(err)
	}
	defer devices.Close()

	for i := uint(0); i < devices.Count(); i++ {
		desc, err := devices.Describe(i)
		if err != nil {
			painc(err)
		}
		println(desc)
	}

	challenge := make([]byte, 32)
	_, err = rand.Read(challenge)
	if err != nil {
		panic(err)
	}

	resp, err := devices.Register(challenge, "https://demo.yubico.com")
	if err != nil {
		panic(err)
	}

	regData, err := ParseRegistrationData(resp.RegistrationData)
	if err != nil {
		panic(err)
	}

	authRes, err := devices.Authenticate(challenge, "https://demo.yubico.com", regData.KeyHandle)
	if err != nil {
		panic(err)
	}
	println(authRes.Signature)
}

```
