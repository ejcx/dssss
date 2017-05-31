package api

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/ejcx/dssss/auth"
	"github.com/ejcx/dssss/dc"
	"github.com/ejcx/dssss/fs"
	"github.com/gorilla/mux"
)

const (
	Secret     = "/v1/secret/{name:[a-zA-Z0-9]+}"
	FileBase   = "secrets/"
	AuthHeader = "Auth-PKCS7"
)

var (
	SingletonServer *Server
	RouteList       = []*Route{
		&Route{
			Secret,
			SecretHandler,
		},
	}
)

type Server struct {
	FS        *fs.FS
	MasterKey [32]byte
}

type Route struct {
	Endpoint string
	Handle   func(w http.ResponseWriter, r *http.Request)
}

type PutSecretInput struct {
	Secret string
	Roles  []string
}

type GetSecretInput struct {
}

type RouteInfo struct {
	Endpoint    string
	Description string
	Method      string
}

type EncryptedSecret struct {
	Bytes         []byte
	KeyCiphertext []byte
}

type SecretContent struct {
	RoleList         []string
	SecretCiphertext []byte
}

func FetchAuth(r *http.Request) string {
	return r.Header.Get(AuthHeader)
}

func SecretHandler(w http.ResponseWriter, r *http.Request) {
	var (
		putInput PutSecretInput
	)
	switch r.Method {
	case "DELETE":
		vars := mux.Vars(r)
		name := vars["name"]
		if name == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		err := SingletonServer.FS.WriteSecret(name, "")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	case "PUT":
		vars := mux.Vars(r)
		name := vars["name"]
		if name == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		buf, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		err = json.Unmarshal(buf, &putInput)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		enc, err := SealSecret(putInput.Secret, putInput.Roles)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		err = SingletonServer.FS.WriteSecret(name, enc)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	case "GET":
		var e EncryptedSecret
		vars := mux.Vars(r)
		name := vars["name"]
		if name == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		buf, err := SingletonServer.FS.ReadFile("secret/" + name)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		err = json.Unmarshal(buf, &e)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		secret, roles, err := OpenSecret(&e)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		pkcs7raw := FetchAuth(r)
		a, err := auth.AuthUser(pkcs7raw)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		err = a.IsAllowed(roles)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Write([]byte(secret))
	default:
	}
}

// OpenSecret takes an EncryptedSecret as a parameter and will
// verify it has not been tampered with. It will recover
// the secret from encrypted object.
func OpenSecret(e *EncryptedSecret) (string, []string, error) {
	var (
		secretContent SecretContent
	)

	var master [32]byte
	copy(master[:], SingletonServer.MasterKey[:])
	keyBytes, err := dc.Open(&master, e.KeyCiphertext)
	if err != nil {
		return "", nil, err
	}

	var secretKey [32]byte
	copy(secretKey[:], keyBytes[:])
	secretBuf, err := dc.Open(&secretKey, e.Bytes)
	if err != nil {
		return "", nil, err
	}
	err = json.Unmarshal(secretBuf, &secretContent)
	if err != nil {
		return "", nil, err
	}

	secret, err := dc.Open(&secretKey, secretContent.SecretCiphertext)
	if err != nil {
		return "", nil, err
	}
	return string(secret), secretContent.RoleList, nil
}

// SealSecret takes a secret and a slice of roles and creates
// and encrypted secret type that is then stored and secure
// from modification.
func SealSecret(secret string, roles []string) (*EncryptedSecret, error) {
	// Generate the key that will encrypt the secret.
	// This key will be encrypted by the master key.
	key, err := dc.NewKey()
	if err != nil {
		return nil, err
	}

	// Encrypt our new key with the master key.
	var keyBytes [32]byte
	copy(keyBytes[:], key.Bytes[:])
	secretKeyCipher, err := dc.Seal(&SingletonServer.MasterKey, key.Bytes[:])
	if err != nil {
		return nil, err
	}

	secretCipher, err := dc.Seal(&keyBytes, []byte(secret))

	secretContent := &SecretContent{
		RoleList:         roles,
		SecretCiphertext: secretCipher,
	}
	buf, err := json.Marshal(secretContent)
	if err != nil {
		return nil, err
	}

	// Encrypt the secretContent with the new key.
	secretBytes, err := dc.Seal(&keyBytes, buf)
	if err != nil {
		return nil, err
	}

	return &EncryptedSecret{
		Bytes:         secretBytes,
		KeyCiphertext: secretKeyCipher,
	}, nil
}

func (s *Server) RunV1() {
	r := mux.NewRouter()
	for _, route := range RouteList {
		r.HandleFunc(route.Endpoint, route.Handle)
	}
	http.Handle("/", r)
	srv := &http.Server{
		Handler:      r,
		Addr:         "localhost:8000",
		WriteTimeout: 60 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	log.Println("Server started")
	log.Fatal(srv.ListenAndServe())
}

func NewServer(fs *fs.FS, masterKey [32]byte) *Server {
	SingletonServer = &Server{
		FS:        fs,
		MasterKey: masterKey,
	}
	return SingletonServer
}
