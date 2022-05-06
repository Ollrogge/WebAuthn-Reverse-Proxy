package main

import (
    "fmt"
    "net/http"
    "github.com/gorilla/mux"
    _ "reflect"
    "github.com/fxamacker/cbor/v2"
    _ "errors"
    "encoding/binary"
    "bytes"
)

const (
    MakeCredential = 0x0
    GetAssertion = 0x1
)

type Credential struct {
    Id []byte   `cbor:"id"`
    Type string `cbor:"type"`
}

type CredentialId struct {
    Id [16]byte
    //todo: public key credential source
}

type CredentialPublicKey struct {
    Kty int32     `cbor:"1,keyasint"`
    Alg int32     `cbor:"3,keyasint"`
    Crv int32     `cbor:"-1,keyasint"`
    X [32]byte  `cbor:"-2,keyasint"`
    Y [32]byte  `cbor:"-3,keyasint"`
}

type AttestedCredentialData struct {
    Aaguid [16]byte
    CredentialIdLength [2]byte
    CredentialId CredentialId
    CredentialPublicKey CredentialPublicKey
}

type AuthDataAttest struct {
    /* auth_data_header */
    RpIdHash [32]byte
    Flags uint8
    SignCount uint32
    AttestedCredentialData AttestedCredentialData
}

type AuthDataAssert struct {
    /* auth_data_header */
    RpIdHash [32]byte
    Flags uint8
    SignCount uint32
}

/* packed format */
type AttestationStatement struct {
    Alg int       `cbor:"alg"`
    Sig [72]byte  `cbor:"sig"`
}

type GetAssertionResp struct {
    Credential Credential 
    AuthData AuthDataAssert
    Sig []byte
}

type MakeCredentialResp struct {
    AuthData AuthDataAttest
    Format string
    AttestationStatement AttestationStatement
}

func (p *AuthDataAttest) Unmarshal(data []byte) error {
    return Unmarshal(p, data);
}

func (p *AuthDataAssert) Unmarshal(data []byte) error {
    return Unmarshal(p, data);
}

func Unmarshal[T AuthDataAttest | AuthDataAssert](p *T, data []byte) error {

    r := bytes.NewReader(data);

    return binary.Read(r, binary.LittleEndian, p);
}

func decodeMakeCredentialResp(resp *MakeCredentialResp, data []byte) {
    type _resp struct {
        Format string `cbor:"1,keyasint"`
        AuthData []byte `cbor:"2,keyasint"`
        AttStatement AttestationStatement 
    }

    var v _resp
    if err := cbor.Unmarshal(data, &v); err != nil {
        fmt.Println("error: ", err)
    }

    var a AuthDataAttest
    if err := a.Unmarshal(v.AuthData); err != nil {
        fmt.Println("error: ", err)
    }

    resp.AuthData = a
    resp.Format = v.Format
    resp.AttestationStatement = v.AttStatement
}

func decodeAssertionResp(resp *GetAssertionResp, data []byte) {
    type _resp struct {
        Credential Credential `cbor:"1,keyasint"`
        AuthData []byte `cbor:"2,keyasint"`
        Sig []byte `cbor:"3,keyasint"`
    }

    var v _resp
    if err := cbor.Unmarshal(data, &v); err != nil {
		fmt.Println("error: ", err)
	}

    var a AuthDataAssert
    if err := a.Unmarshal(v.AuthData); err != nil {
        fmt.Println("error: ", err)
    }

    resp.Credential = v.Credential
    resp.AuthData = a
    resp.Sig = v.Sig
}

func fido2Data(w http.ResponseWriter, req *http.Request) {

    vars := mux.Vars(req)
    _ = vars

    switch req.Method {
    case "GET":
        //todo: check first byte
        fmt.Println("Keys: ", req.URL.Query())
    case "POST":
        if err := req.ParseForm(); err != nil {
            fmt.Fprintf(w, "ParseForm() err: %v", err)
			return
        }

        data := []byte(req.PostForm["fidoData"][0])
        switch data[0] {
        case MakeCredential:
            var resp MakeCredentialResp
            decodeMakeCredentialResp(&resp, data[1:])
            fmt.Println("MakeCredential: ", resp);
            break;
        case GetAssertion:
            var resp GetAssertionResp
            decodeAssertionResp(&resp, data[1:])
            fmt.Println("GetAssertion: ", resp);
            break;
        }
    }
    
    fmt.Fprintf(w, "test \n")
}

func main() {

    r := mux.NewRouter()
    r.HandleFunc("/fidodata/{user}", fido2Data)

    fmt.Println("Starting http server")

    http.ListenAndServe(":8000", r)

}

