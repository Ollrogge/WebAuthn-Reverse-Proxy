package main

import (
    "fmt"
    "net/http"
    "github.com/gorilla/mux"
    _ "reflect"
    "github.com/fxamacker/cbor/v2"
    "errors"
    "encoding/binary"
)

const (
    MakeCredential = 0x0
    GetAssertion = 0x1
)

type Credential struct {
    Id []byte `cbor:"id"`
    Type string `cbor:"type"`
}

type AuthData struct {
    /* auth_data_header */
    RpIdHash [32]byte
    Flags uint8
    Counter uint32
    /* attested_cred_data_header */
    Aaguid [16]byte
    CredLenH uint8
    CredLenL uint8
    /* cred_id */
    Id [16]byte // assume we don't send encrypted credentials
}

type AssertionResp struct {
    Credential Credential 
    AuthData AuthData
    Sig []byte
}

func (p* AuthData) Unmarshal(data []byte) error {
    if len(data) < 37 {
        return errors.New("need at least 37 bytes for authData")
    }

    copy(p.RpIdHash[:], data[:32])
    p.Flags = data[32]
    p.Counter = binary.LittleEndian.Uint32(data[33:37])

    return nil 
}


/*
[AttestedCredentialData(aaguid: h'39633239353836356661326333366237', credential_id: h'885d607c7e79801893204c2700ddb4c9', public_key: {1: 2, 3: -7, -1: 1, -2: b'\x93A::\x7fP\xac\x9c\xb0\x0c\x1c\x01\xa8\x02\x84\x13FfgW\xc1\x7f\x97\xc2\x90u\x02uD2j\x00', -3: b'W\xdfd\xa6\xd5\xf4\xb6\xda\xc2u\xe1\x03R8\xacM7\x1b\xbf\x86&V\xba\xf1A\xbbI\xca\x9d\xe2Z\xa2'}]
*/
func decodeMakeCredentialResp() {
    type resp struct {
        Format string `cbor:"1,keyasint"`
        AuthData []byte `cbor:"2,keyasint"`
        AttStatement 
    }
}

func decodeAssertionResp(assertion* AssertionResp, data []byte) {
    type resp struct {
        Credential Credential `cbor:"1,keyasint"`
        AuthData []byte `cbor:"2,keyasint"`
        Sig []byte `cbor:"3,keyasint"`
    }

    var v resp
    if err := cbor.Unmarshal(data, &v); err != nil {
		fmt.Println("error: ", err)
	}

    var a AuthData
    if err := a.Unmarshal(v.AuthData); err != nil {
        fmt.Println("error: ", err)
    }

    assertion.Credential = v.Credential
    assertion.AuthData = a
    assertion.Sig = v.Sig
}

func fido2Data(w http.ResponseWriter, req *http.Request) {

    vars := mux.Vars(req)
    
    fmt.Println("vars: ", vars)

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
            decodeMakeCredentialResp()
            break;
        case GetAssertion:
            var resp AssertionResp
            decodeAssertionResp(&resp, data[1:])
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

