package u2fhost

/*
#cgo CFLAGS: -I/usr/include/u2f-host
#cgo LDFLAGS: -lu2f-host

#include <stdlib.h>
#include <u2f-host.h>
 */
import "C"
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"unsafe"
)

var _B64 = base64.URLEncoding.WithPadding(base64.NoPadding)

type U2fh struct {}

func New() (*U2fh, error) {
	rc := C.u2fh_global_init(0)
	if rc != C.U2FH_OK {
		return nil, fmt.Errorf("unable to globally initialize u2fh library: %s", rcToStrErr(rc))
	}
	return &U2fh{}, nil
}

func (*U2fh) Close() error {
	C.u2fh_global_done()
	return nil
}

type Devices struct {
	devs *C.u2fh_devs
	count uint
}

func (d *Devices) Close() error {
	C.u2fh_devs_done(d.devs)
	return nil
}

func (*U2fh) GetDevices() (*Devices, error) {
	var devs *C.u2fh_devs
	rc := C.u2fh_devs_init(&devs)
	if rc != C.U2FH_OK {
		return nil, fmt.Errorf("unable to initialize devices structure: %s", rcToStrErr(rc))
	}
	var count C.uint
	rc = C.u2fh_devs_discover(devs, &count)
	if rc != C.U2FH_OK {
		if rc == C.U2FH_NO_U2F_DEVICE {
			count = 0
		} else {
			return nil, fmt.Errorf("unable to discover devices: %s", rcToStrErr(rc))
		}
	}

	return &Devices{
		devs: devs,
		count: uint(count)+1,
	}, nil
}

func (d *Devices) Count() uint {
	return d.count
}

func (d *Devices) Describe(index uint) (string, error) {
	if (index >= d.count) {
		return "", errors.New("index cannot be larger than device count")
	}

	var bufferLen C.size_t
	bufferLen = 4096
	buffer := (*C.char)(C.malloc(bufferLen))
	defer C.free(unsafe.Pointer(buffer))

	rc := C.u2fh_get_device_description(d.devs, C.uint(index), buffer, &bufferLen)
	if rc != C.U2FH_OK {
		return "", fmt.Errorf("unable to get device description: %s", rcToStrErr(rc))
	}
	desc := C.GoString(buffer)
	return desc, nil
}

type RegistrationResponse struct {
	RegistrationData []byte
	ClientData []byte
}

func (d *Devices) Register(challenge []byte, origin string) (*RegistrationResponse, error) {

	var registerReq struct {
		Version string `json:"version"`
		Challenge string `json:"challenge"`
		AppId string `json:"appId"`
	}
	registerReq.Version = "U2F_V2"
	registerReq.Challenge = _B64.EncodeToString(challenge)
	registerReq.AppId = origin

	challengeJson, err := json.Marshal(registerReq)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal registration request: %v", err)
	}

	chal := C.CString(string(challengeJson))
	defer C.free(unsafe.Pointer(chal))
	orig := C.CString(origin)
	defer C.free(unsafe.Pointer(orig))

	var response *C.char
	rc := C.u2fh_register(d.devs, chal, orig, &response, C.U2FH_REQUEST_USER_PRESENCE)
	if rc != C.U2FH_OK {
		return nil, fmt.Errorf("unable to register: %s", rcToStrErr(rc))
	}
	defer C.free(unsafe.Pointer(response))

	var encodedResponse struct {
		RegistrationData string `json:"registrationData"`
		ClientData string `json:"clientData"`
	}
	err = json.Unmarshal([]byte(C.GoString(response)), &encodedResponse)
	if err != nil {
		return nil, fmt.Errorf("unable to decode registration response: %v", err)
	}

	registrationData, err := _B64.DecodeString(encodedResponse.RegistrationData)
	if err != nil {
		return nil, fmt.Errorf("unable to base64 decode registration data: %v", err)
	}
	clientData, err := _B64.DecodeString(encodedResponse.ClientData)
	if err != nil {
		return nil, fmt.Errorf("unable to base64 decode client data: %v", err)
	}

	return &RegistrationResponse{
		RegistrationData: registrationData,
		ClientData: clientData,
	}, nil
}

type AuthenticateResponse struct {
	Signature []byte
	ClientData []byte
}

func (d *Devices) Authenticate(challenge []byte, origin string, keyHandle []byte) (*AuthenticateResponse, error) {
	var authenticateReq struct {
		Version string `json:"version"`
		Challenge string `json:"challenge"`
		AppId string `json:"appId"`
		KeyHandle string `json:"keyHandle"`
	}
	authenticateReq.Version = "U2F_V2"
	authenticateReq.Challenge = _B64.EncodeToString(challenge)
	authenticateReq.AppId = origin
	authenticateReq.KeyHandle = _B64.EncodeToString(keyHandle)

	challengeJson, err := json.Marshal(authenticateReq)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal authentication request: %v", err)
	}

	chal := C.CString(string(challengeJson))
	defer C.free(unsafe.Pointer(chal))
	orig := C.CString(origin)
	defer C.free(unsafe.Pointer(orig))

	var response *C.char
	rc := C.u2fh_authenticate(d.devs, chal, orig, &response, C.U2FH_REQUEST_USER_PRESENCE)
	if rc != C.U2FH_OK {
		return nil, fmt.Errorf("unable to authenticate: %s", rcToStrErr(rc))
	}
	defer C.free(unsafe.Pointer(response))

	var encodedResponse struct {
		SignatureData string `json:"signatureData"`
		ClientData string `json:"clientData"`
	}
	err = json.Unmarshal([]byte(C.GoString(response)), &encodedResponse)
	if err != nil {
		return nil, fmt.Errorf("unable to decode registration response: %v", err)
	}

	signatureData, err := _B64.DecodeString(encodedResponse.SignatureData)
	if err != nil {
		return nil, fmt.Errorf("unable to base64 decode registration data: %v", err)
	}
	clientData, err := _B64.DecodeString(encodedResponse.ClientData)
	if err != nil {
		return nil, fmt.Errorf("unable to base64 decode client data: %v", err)
	}

	return &AuthenticateResponse{
		Signature: signatureData,
		ClientData: clientData,
	}, nil
}

type RegistrationData struct {
	PublicKey *ecdsa.PublicKey
	KeyHandle []byte
	AttestationCertificate *x509.Certificate
	Signature []byte
}

func ParseRegistrationData(registrationData []byte) (*RegistrationData, error) {
	if len(registrationData) < 67 || registrationData[0] != 0x05 {
		return nil, errors.New("invalid registration data")
	}
	if registrationData[1] != 0x04 {
		return nil, errors.New("invalid compressed point header byte")
	}
	x := big.NewInt(0).SetBytes(registrationData[2:34])
	y := big.NewInt(0).SetBytes(registrationData[34:66])
	keyHandleLen := int(registrationData[66])
	if len(registrationData) < 67 + keyHandleLen {
		return nil, errors.New("invalid registration data")
	}
	keyHandle := registrationData[67:67+keyHandleLen]

	certContent := new(asn1.RawValue)
	rest, err := asn1.Unmarshal(registrationData[67+keyHandleLen:], certContent)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal attestation certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certContent.FullBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse attestation certificate: %v", err)
	}
	return &RegistrationData{
		PublicKey: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X: x,
			Y: y,
		},
		KeyHandle: keyHandle,
		AttestationCertificate: cert,
		Signature: rest,
	}, nil
}

func rcToStrErr(rc C.u2fh_rc) string {
	return C.GoString(C.u2fh_strerror(C.int(rc)))
}
