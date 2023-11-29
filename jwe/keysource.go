package jwe

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/getsops/sops/v3/logging"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/sirupsen/logrus"
)

var (
	// log is the global logger for any AWS KMS MasterKey.
	log *logrus.Logger
)

const (
	// JWEHeaderRJWK is the header parameter name for the jwk which should be used for the encryption of the response
	JWEHeaderRJWK = "rjwk"
)

func init() {
	log = logging.NewLogger("JWE")
}

type MasterKey struct {
	encryptedKey []byte
	jwkSets      []jwk.Set
	pubKeyJWK    []byte
	privKey      jwk.Key
}

// NewSenderMasterKey creates a new MasterKey for the sender side.
// It is capable of encrypting the data key with the keys contained in the provided JWK sets.
// The publicKey (if provided) will be embedded into the JWE header of the request, so that the receiver
// can use it to encrypt the response. The privateKey is the key which will be used to decrypt the response.
func NewSenderMasterKey(privateKey, publicKey jwk.Key, jwkSets []jwk.Set) (*MasterKey, error) {
	if len(jwkSets) == 0 {
		return nil, fmt.Errorf("no jwk sets provided")
	}

	if (publicKey == nil && privateKey != nil) || (publicKey != nil && privateKey == nil) {
		return nil, fmt.Errorf("sender keys must be either omitted or both public and private key must be provided")
	}

	masterKey := MasterKey{
		jwkSets: jwkSets,
	}

	if publicKey != nil {
		var err error
		masterKey.pubKeyJWK, err = json.Marshal(publicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal sender public key: %w", err)
		}
		masterKey.privKey = privateKey
	}

	return &masterKey, nil
}

// NewReceiverMasterKey creates a new MasterKey for the receiver side.
// It is capable of decrypting the data key with the provided private key. If the response is requested to be encrypted,
// a public key will be provided in the JWE header of the request. This key will be set in the MasterKey instance
// as the jwkSets, so that the next encryption will use this key.
func NewReceiverMasterKey(privateKey jwk.Key) *MasterKey {
	return &MasterKey{
		privKey: privateKey,
	}

}

func (m *MasterKey) Encrypt(dataKey []byte) error {
	encryptionOptions, err := m.getEncryptionOptions()
	if err != nil {
		return err
	}

	encryptedKey, err := jwe.Encrypt(dataKey, encryptionOptions...)
	if err != nil {
		return fmt.Errorf("failed to encrypt dataKey: %w", err)
	}
	m.encryptedKey = encryptedKey
	return nil
}

func (m *MasterKey) EncryptedDataKey() []byte {
	return m.encryptedKey
}

func (m *MasterKey) SetEncryptedDataKey(encryptedKey []byte) {
	m.encryptedKey = encryptedKey
}

func (m *MasterKey) Decrypt() ([]byte, error) {
	var jweMessage jwe.Message
	decrypted, err := jwe.Decrypt(m.encryptedKey,
		jwe.WithKey(m.privKey.Algorithm(), m.privKey),
		jwe.WithMessage(&jweMessage),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt encrypted key: %w", err)
	}
	var rjwk jwk.Key
	if rawRJWK, found := jweMessage.ProtectedHeaders().Get(JWEHeaderRJWK); found {
		log.Info("found RJWK in JWE header, setting it as the new encryption key")
		rjwkJSON := rawRJWK.(string)
		rjwk, err = jwk.ParseKey([]byte(rjwkJSON))
		if err != nil {
			return nil, fmt.Errorf("failed to parse RJWK: %w", err)
		}
		set := jwk.NewSet()
		if err := set.AddKey(rjwk); err != nil {
			return nil, fmt.Errorf("failed to add RJWK to set: %w", err)
		}

		// replace the cached set with the new set containing the RJWK
		// so that the next encryption (which will be the response) will use the RJWK
		m.jwkSets = []jwk.Set{set}
	}
	return decrypted, nil

}

// EncryptIfNeeded encrypts the provided SOPS data key, if it has not been
// encrypted yet.
func (m *MasterKey) EncryptIfNeeded(dataKey []byte) error {
	if len(m.encryptedKey) == 0 {
		return m.Encrypt(dataKey)
	}
	return nil
}

func (m *MasterKey) NeedsRotation() bool {
	return false
}

func (m *MasterKey) ToString() string {
	return string(m.encryptedKey)
}

func (m *MasterKey) ToMap() map[string]interface{} {
	var result map[string]interface{}
	if err := json.Unmarshal(m.encryptedKey, &result); err != nil {
		panic(err)
	}
	return result
}

func getEncryptionKey(keySet jwk.Set) jwk.Key {
	ctx := context.Background()
	for iter := keySet.Keys(ctx); iter.Next(ctx); {
		pair := iter.Pair()
		key, ok := pair.Value.(jwk.Key)
		if !ok {
			continue
		}
		if key.KeyUsage() == string(jwk.ForEncryption) {
			return key
		}
	}
	return nil

}

// getEncryptionOptions has to be called before each encryption, as the keys from the JWKS URLs might change
func (m *MasterKey) getEncryptionOptions() ([]jwe.EncryptOption, error) {
	encryptionOptions := make([]jwe.EncryptOption, 0, len(m.jwkSets))
	for _, jwkSet := range m.jwkSets {
		key := getEncryptionKey(jwkSet)
		if key == nil {
			continue
		}
		encryptionOptions = append(encryptionOptions, jwe.WithKey(key.Algorithm(), key))
	}

	if len(encryptionOptions) == 0 {
		return nil, fmt.Errorf("no encryption keys found")
	}

	encryptionOptions = append(encryptionOptions, jwe.WithJSON())

	if protectedHeaders := m.getProtectedHeaders(); protectedHeaders != nil {
		encryptionOptions = append(encryptionOptions, jwe.WithProtectedHeaders(protectedHeaders))
	}

	return encryptionOptions, nil
}

func (m *MasterKey) getProtectedHeaders() jwe.Headers {
	headers := jwe.NewHeaders()
	headersSet := false
	if len(m.pubKeyJWK) > 0 {
		// Safety: we know that for this private parameter name, the set value is allowed to be a string
		if err := headers.Set(JWEHeaderRJWK, string(m.pubKeyJWK)); err != nil {
			panic(err)
		}

		// Safety: we know for "crit", the set value is allowed to be a []string
		if err := headers.Set(jwe.CriticalKey, []string{JWEHeaderRJWK}); err != nil {
			panic(err)
		}
		headersSet = true
	}

	if headersSet {
		return headers
	}
	return nil
}

func NewCachedSets(ctx context.Context, jwksURLs ...string) ([]jwk.Set, error) {
	cache := jwk.NewCache(ctx)
	var jwkSets []jwk.Set
	for _, jwksURL := range jwksURLs {
		err := cache.Register(jwksURL)
		if err != nil {
			return nil, fmt.Errorf("failed to register JWK Set URL %s: %w", jwksURL, err)
		}
		jwkSet := jwk.NewCachedSet(cache, jwksURL)
		jwkSets = append(jwkSets, jwkSet)
	}

	return jwkSets, nil
}
