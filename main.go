package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	_ "errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	_ "reflect"
	"strings"

	fidoClient "fido2proxy/client"
	libfido2 "fido2proxy/fido2"

	"github.com/fxamacker/cbor/v2"
	"github.com/gorilla/mux"
)

var pAssertion *libfido2.Assertion
var gClientData CollectedClientData
var gCookieJar cookiejar.Jar

const (
	MakeCredentialBegin     = 0x0
	MakeCredentialFinish    = 0x1
	GetAssertionBegin       = 0x2
	GetAssertionFinish      = 0x3
	BaseUrl                 = "http://localhost:8010"
	MakeCredentialBeginUrl  = "/register/begin"
	MakeCredentialFinishUrl = "/register/begin"
	GetAssertionBeginUrl    = "/login/begin"
	GetAssertionFinishUrl   = "/login/finish"
	DefaultUsername         = "user1"
	Testing                 = false
)

type Credential struct {
	Id   []byte `cbor:"id" json:"id"`
	Type string `cbor:"type" json:"type"`
}

type CredentialId struct {
	Id [16]byte
	//todo: public key credential source
}

type CredentialPublicKey struct {
	Kty int32    `cbor:"1,keyasint"`
	Alg int32    `cbor:"3,keyasint"`
	Crv int32    `cbor:"-1,keyasint"`
	X   [32]byte `cbor:"-2,keyasint"`
	Y   [32]byte `cbor:"-3,keyasint"`
}

type AttestedCredentialData struct {
	Aaguid              [16]byte
	CredentialIdLength  [2]byte
	CredentialId        CredentialId
	CredentialPublicKey CredentialPublicKey
}

type AuthDataAttest struct {
	RpIdHash               [32]byte
	Flags                  uint8
	SignCount              uint32
	AttestedCredentialData AttestedCredentialData
}

/* packed format */
type AttestationStatement struct {
	Alg int      `cbor:"alg"`
	Sig [72]byte `cbor:"sig"`
}

type AuthDataAssert struct {
	RpIdHash  [32]byte
	Flags     uint8
	SignCount uint32
}

/* authenticator -> us */
type GetAssertionResp struct {
	Credential Credential
	AuthData   AuthDataAssert
	Sig        []byte
	UserHandle []byte
}

// https://www.w3.org/TR/webauthn/#authenticatorassertionresponse
type AuthenticatorResponse struct {
	AuthData       string `json:"authenticatorData"`
	ClientDataJson string `json:"clientDataJSON"`
	Sig            string `json:"signature"`
	UserHandle     string `json:"userHandle,omitempty"`
}

/* us -> fido2 server */
type PubKeyCredential struct {
	Id       string                `json:"id"`
	RawId    string                `json:"rawId"`
	Type     string                `json:"type"`
	Response AuthenticatorResponse `json:"response"`
}

type MakeCredentialResp struct {
	AuthData             AuthDataAttest
	Format               string
	AttestationStatement AttestationStatement
}

type PublicKeyCredentialDescriptor struct {
	Type       string   `json:"type" cbor:"type"`
	Id         []byte   `json:"id" cbor:"id"`
	Transports []string `json:"transports,omitempty" cbor:"transports,omitempty"`
	//PublicKey  []byte   `json:"publicKey,omitempty" cbor:"publicKey,omitempty"`
	PublicKey []byte `json:"publicKey,omitempty" cbor:"-"`
}

type PublicKeyCredentialRequestOptions struct {
	Challenge        []byte                          `json:"challenge"`
	Timeout          uint64                          `json:"timeout"`
	RpId             string                          `json:"rpId"`
	AllowCredentials []PublicKeyCredentialDescriptor `json:"allowCredentials,omitempty"`
}

type CredentialRequestOptions struct {
	PublicKey PublicKeyCredentialRequestOptions `json:"publicKey"`
}

type CollectedClientData struct {
	Type         string `json:"type"`
	Challenge    string `json:"challenge"`
	Origin       string `json:"origin"`
	CrossOrigin  bool   `json:"crossOrigin,omitempty"`
	TokenBinding []byte `json:"tokenBinding,omitempty"`
}

// us -> authenticator
type AuthenticatorGetAssertion struct {
	RpId           string                          `cbor:"1,keyasint"`
	ClientDataHash []byte                          `cbor:"2,keyasint"`
	AllowList      []PublicKeyCredentialDescriptor `cbor:"3,keyasint,omitempty"`
}

type Response struct {
	FidoData  []byte `json:"fidoData"`
	PublicKey []byte `json:"publicKey,omitempty"`
}

type State struct {
	CollectedClientData CollectedClientData
}

// https://paulyeo21.medium.com/golang-underscore-struct-field-f0aecabc72ae
type PublicKeyData struct {
	// Decode the results to int by default.
	_struct bool `cbor:",keyasint" json:"public_key"`
	// The type of key created. Should be OKP, EC2, or RSA.
	KeyType int64 `cbor:"1,keyasint" json:"kty"`
	// A COSEAlgorithmIdentifier for the algorithm used to derive the key signature.
	Algorithm int64 `cbor:"3,keyasint" json:"alg"`
}

type EC2PublicKeyData struct {
	PublicKeyData
	// If the key type is EC2, the curve on which we derive the signature from.
	Curve int64 `cbor:"-1,keyasint,omitempty" json:"crv"`
	// A byte string 32 bytes in length that holds the x coordinate of the key.
	XCoord []byte `cbor:"-2,keyasint,omitempty" json:"x"`
	// A byte string 32 bytes in length that holds the y coordinate of the key.
	YCoord []byte `cbor:"-3,keyasint,omitempty" json:"y"`
}

func (p *AuthDataAttest) Unmarshal(data []byte) error {
	return Unmarshal(p, data)
}

func (p *AuthDataAssert) Unmarshal(data []byte) error {
	return Unmarshal(p, data)
}

func (p *AuthDataAttest) Marshal() ([]byte, error) {
	return Marshal(p)
}

func (p *AuthDataAssert) Marshal() ([]byte, error) {
	return Marshal(p)
}

func Marshal[T AuthDataAttest | AuthDataAssert](p *T) ([]byte, error) {
	return json.Marshal(p)
}

func Unmarshal[T AuthDataAttest | AuthDataAssert](p *T, data []byte) error {

	r := bytes.NewReader(data)

	return binary.Read(r, binary.LittleEndian, p)
}

func (p *PubKeyCredential) Unmarshal(
	cred *GetAssertionResp,
	clientData *CollectedClientData) error {

	p.Id = base64.RawURLEncoding.EncodeToString(cred.Credential.Id)
	p.RawId = p.Id
	p.Type = cred.Credential.Type

	var authData bytes.Buffer
	err := binary.Write(&authData, binary.LittleEndian, cred.AuthData.RpIdHash)
	if err != nil {
		return err
	}
	err = binary.Write(&authData, binary.LittleEndian, cred.AuthData.Flags)
	if err != nil {
		return err
	}

	err = binary.Write(&authData, binary.LittleEndian, cred.AuthData.SignCount)
	if err != nil {
		return err
	}

	clientDataJson, err := json.Marshal(clientData)
	if err != nil {
		return err
	}

	p.Response.ClientDataJson = base64.RawURLEncoding.EncodeToString(clientDataJson)
	p.Response.AuthData = base64.RawURLEncoding.EncodeToString(authData.Bytes())
	p.Response.Sig = base64.RawURLEncoding.EncodeToString(cred.Sig)
	p.Response.UserHandle = base64.RawURLEncoding.EncodeToString(cred.UserHandle)

	return nil
}

func (p *PublicKeyCredentialRequestOptions) Unmarshal(data []byte) error {
	return json.Unmarshal(data, p)
}

func (p *CollectedClientData) Unmarshal(data *PublicKeyCredentialRequestOptions) error {
	p.Type = "webauthn.get"
	p.Challenge = base64.RawURLEncoding.EncodeToString(data.Challenge)
	p.Origin = BaseUrl

	return nil
}

func decodeMakeCredentialResp(resp *MakeCredentialResp, data []byte) {
	type _resp struct {
		Format       string `cbor:"1,keyasint"`
		AuthData     []byte `cbor:"2,keyasint"`
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

func (p *GetAssertionResp) Unmarshal(data []byte) error {
	type _user struct {
		Id []byte `cbor:"id"`
	}
	type _resp struct {
		Credential Credential `cbor:"1,keyasint"`
		AuthData   []byte     `cbor:"2,keyasint"`
		Sig        []byte     `cbor:"3,keyasint"`
		UserHandle _user      `cbor:"4,keyasint,omitempty"`
	}

	var v _resp
	if err := cbor.Unmarshal(data, &v); err != nil {
		return err
	}

	var a AuthDataAssert
	if err := a.Unmarshal(v.AuthData); err != nil {
		return err
	}

	p.Credential = v.Credential
	p.AuthData = a
	p.Sig = v.Sig
	p.UserHandle = v.UserHandle.Id

	return nil
}

func (p *GetAssertionResp) UnmarshalTest(data *libfido2.Assertion) error {
	var authData AuthDataAssert
	var v interface{}
	if err := cbor.Unmarshal(data.AuthDataCBOR, &v); err != nil {
		return err
	}

	if err := authData.Unmarshal(v.([]byte)); err != nil {
		return err
	}

	var cred Credential
	cred.Id = data.CredentialId
	cred.Type = "public-key"

	p.AuthData = authData
	p.Credential = cred
	p.Sig = data.Sig

	return nil
}

// https://medium.com/@ayeshajayasankha/making-http-requests-with-go-acbcf6e3f1d4
func handleMakeCredentialBegin() error {
	log.Println("handleMakeCredentialBegin")
	req_url := BaseUrl + MakeCredentialBeginUrl + "/" + DefaultUsername

	params := url.Values{}
	params.Add("attType", "none")
	params.Add("authType", "")
	params.Add("userVerification", "discouraged")
	params.Add("residentKeyRequirement", "false")
	params.Add("txAuthExtension", "")

	cookieJar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: cookieJar,
	}

	req, err := http.NewRequest("GET", req_url, strings.NewReader(params.Encode()))

	if err != nil {
		fmt.Println("error: ", err)
		return err
	}

	_, err = client.Do(req)

	if err != nil {
		fmt.Println("error: ", err)
		return err
	}

	return nil
}

func handleGetAssertionBegin(username string) ([]byte, error) {
	log.Println("handleGetAssertionBegin")
	//TODO: use DevEUI instead of DefaultUsername
	req_url := BaseUrl + GetAssertionBeginUrl + "/" + username

	params := url.Values{}
	params.Add("userVerification", "discouraged")
	params.Add("txAuthExtension", "")

	cookieJar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: cookieJar,
	}

	req, err := http.NewRequest("GET", req_url, strings.NewReader(params.Encode()))

	if err != nil {
		fmt.Println("error: ", err)
		return nil, err
	}

	resp, err := client.Do(req)

	if err != nil {
		fmt.Println("error: ", err)
		return nil, err
	}

	gCookieJar = *cookieJar

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var credentialRequest CredentialRequestOptions

	err = json.Unmarshal(body, &credentialRequest)
	if err != nil {
		return nil, err
	}

	/*
		build clientstate for this authentication flow
	*/
	err = gClientData.Unmarshal(&credentialRequest.PublicKey)
	if err != nil {
		return nil, err
	}

	clientDataJson, err := json.Marshal(gClientData)
	if err != nil {
		return nil, err
	}

	clientDataHash := sha256.Sum256(clientDataJson)

	/*
		if len(credentialRequest.PublicKey.AllowCredentials) == 0x0 {
			return nil, errors.New("AllowCredentials empty")
		} else if len(credentialRequest.PublicKey.AllowCredentials) != 0x1 {
			log.Println("Warning: allow list has more than 1 entry")
		}
	*/

	/*
		Execute a client platform-specific procedure to determine which, if any,
		public key credentials described by options.allowCredentials are bound
		to this authenticator
	*/
	if Testing {
		var credentialIds [][]byte
		for _, cred := range credentialRequest.PublicKey.AllowCredentials {
			credentialIds = append(credentialIds, cred.Id)
		}

		assertion, err := fidoClient.DeviceAssertion(credentialRequest.PublicKey.RpId,
			clientDataHash[:], credentialIds)

		if err != nil {
			return nil, err
		}

		pAssertion = assertion

		handleAssertionFinish(username, nil)
	} else {
		var assert AuthenticatorGetAssertion
		assert.RpId = credentialRequest.PublicKey.RpId
		// In a nutshell, the [:] operator allows you to create a slice from an array
		// array = fixed size, slice = variable size
		assert.ClientDataHash = clientDataHash[:]

		for _, cred := range credentialRequest.PublicKey.AllowCredentials {
			log.Println("credential: ", cred.Type, hex.EncodeToString(cred.Id))
		}

		/*
			TODO: if re-adding it, need to remove all public keys from the struct else
			gets way too big
		*/
		assert.AllowList = credentialRequest.PublicKey.AllowCredentials

		var opts = cbor.CTAP2EncOptions()

		em, err := opts.EncMode()
		if err != nil {
			return nil, err
		}

		b, err := em.Marshal(assert)
		if err != nil {
			return nil, err
		}

		var resp Response
		resp.FidoData = b

		/*
			Since DevEUI is globally unique we assume that there will always be
			just one credential in allow list
		*/

		if len(credentialRequest.PublicKey.AllowCredentials) > 0 {
			var pubKey EC2PublicKeyData
			err = cbor.Unmarshal(credentialRequest.PublicKey.AllowCredentials[0].PublicKey,
				&pubKey)
			if err != nil {
				return nil, err
			}

			resp.PublicKey = append(pubKey.XCoord, pubKey.YCoord...)
		}

		enc, err := json.Marshal(resp)
		if err != nil {
			return nil, err
		}

		return enc, nil
	}

	return nil, nil
}

func handleAssertionFinish(username string, data []byte) ([]byte, error) {
	log.Println("handleAssertionFinish")
	var assertResp GetAssertionResp
	var err error

	if Testing {
		err = assertResp.UnmarshalTest(pAssertion)
	} else {
		err = assertResp.Unmarshal(data)
	}

	if err != nil {
		return nil, err
	}

	log.Println("GetAssertion: ", assertResp)

	var cred PubKeyCredential

	err = cred.Unmarshal(&assertResp, &gClientData)
	if err != nil {
		return nil, err
	}

	enc, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}

	req_url := BaseUrl + GetAssertionFinishUrl + "/" + username

	client := &http.Client{
		Jar: &gCookieJar,
	}

	req, err := http.NewRequest("POST", req_url, bytes.NewBuffer(enc))
	req.Header.Set("Content-Type", "application/json")

	if err != nil {
		fmt.Println("error: ", err)
		return nil, err
	}

	resp, err := client.Do(req)

	if err != nil {
		fmt.Println("error: ", err)
		return nil, err
	}

	fmt.Println("GetAssertion finish resp: ", resp)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, errors.New("get assertion finish error")
	}

	var my_resp Response
	my_resp.FidoData = []byte{}

	enc, err = json.Marshal(my_resp)
	if err != nil {
		return nil, err
	}

	return enc, nil
}

// https://blog.questionable.services/article/http-handler-error-handling-revisited/
func fido2Data(w http.ResponseWriter, req *http.Request) {

	vars := mux.Vars(req)

	var err error
	var res []byte

	switch req.Method {
	case "GET":
		//todo: check first byte
		fmt.Println("Keys: ", req.URL.Query())
	case "POST":
		if err := req.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		//fmt.Println("Postform: ", req.PostForm)

		if len(req.PostForm) == 0 {
			http.Error(w, "Missing post params", http.StatusInternalServerError)
			return
		}

		if _, ok := req.PostForm["fidoData"]; !ok {
			http.Error(w, "Missing fidoData in post params", http.StatusInternalServerError)
			return
		}

		if len(req.PostForm["fidoData"][0]) == 0 {
			http.Error(w, "FidoFata len = 0", http.StatusInternalServerError)
			return
		}

		//log.Println("Postform fidoData: ", req.PostForm["fidoData"])

		data := []byte(req.PostForm["fidoData"][0])
		user := vars["user"]

		switch data[0] {
		case MakeCredentialBegin:
			handleMakeCredentialBegin()
			break
		case MakeCredentialFinish:
			var resp MakeCredentialResp
			decodeMakeCredentialResp(&resp, data[1:])
			fmt.Println("MakeCredential: ", resp)
			break
		case GetAssertionBegin:
			if len(user) == 0 {
				http.Error(w, "GetAssertionBegin: Username missing", http.StatusBadRequest)
				return
			}
			res, err = handleGetAssertionBegin(user)
			break
		case GetAssertionFinish:
			if len(user) == 0 {
				http.Error(w, "GetAssertionBegin: Username missing", http.StatusBadRequest)
				return
			}
			res, err = handleAssertionFinish(user, data[1:])
			break
		default:
			log.Println("Unknown fido command: ", data[0])
			http.Error(w, "Invalid FIDO request code", http.StatusBadRequest)
		}
	}

	if err != nil {
		log.Println("Error: ", err)
		http.Error(w, "Sth went wrong", 500)
	}

	if len(res) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.Write(res)
	} else {
		fmt.Fprintf(w, "Success \n")
	}

	/*
		if len(res) > 0 {
			log.Println("Returning: ", res)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(res)
		} else {
			fmt.Fprintf(w, "Success \n")
		}
	*/
}

// for server: use chromium and domain http://localhost:8080/
func main() {

	r := mux.NewRouter()
	r.HandleFunc("/fidodata/{user}", fido2Data)

	fmt.Println("Starting http server on port 8005")

	http.ListenAndServe(":8005", r)
}

// https://github.com/keys-pub/go-libfido2
