package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/getsops/sops/v3/decrypt"
	"github.com/getsops/sops/v3/encrypt"
	"github.com/getsops/sops/v3/jwe"
	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type Order struct {
	OrderID      int    `json:"orderId"`
	CustomerName string `json:"customerName"`
	Items        []Item `json:"items"`
}

type Item struct {
	ItemID int    `json:"itemId"`
	Name   string `json:"name"`
}

func main() {

	order := Order{
		OrderID:      1,
		CustomerName: "John Doe",
		Items: []Item{
			{
				ItemID: 42,
				Name:   "Widget",
			},
		},
	}

	orderJSON, err := json.Marshal(order)
	if err != nil {
		panic(err)
	}

	privKey, pubKey, err := CreateJWKSKeys(nil)
	if err != nil {
		panic(err)
	}

	// var masterKey keys.MasterKey
	// masterKey := kms.NewMasterKeyFromArn(
	// 	"arn:aws:kms:eu-central-1:877902262405:alias/pom-dev-pom-kms-key20230328123310618000000001",
	// 	nil,
	// 	"",
	// )
	sets, err := jwe.NewCachedSets(context.Background(), "http://localhost:8080/jwks")
	if err != nil {
		panic(err)
	}

	masterKey, err := jwe.NewSenderMasterKey(privKey, pubKey, sets)
	if err != nil {
		panic(err)
	}

	keyService := keyservice.NewLocalClient()

	encrypted, err := encrypt.DataWithFormat(
		orderJSON,
		formats.Json,
		encrypt.EncryptOpts{
			Cipher:            aes.Cipher{},
			KeyServices:       []keyservice.KeyServiceClient{keyService},
			UnencryptedSuffix: "",
			EncryptedSuffix:   "",
			UnencryptedRegex:  "",
			EncryptedRegex:    "",
			MACOnlyEncrypted:  false,
			KeyGroups:         []sops.KeyGroup{[]keys.MasterKey{masterKey}},
			GroupThreshold:    0,
		})
	if err != nil {
		panic(err)
	}

	fmt.Println(string(encrypted))

	decrypted, err := decrypt.DataWithFormat(encrypted, formats.Json)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(decrypted))

}

func CreateJWKSKeys(pemKeys *string) (jwk.Key, jwk.Key, error) {

	var rawRSAPrivateKey, rawRSAPublicKey any
	if pemKeys != nil {
		var err error
		rawRSAPrivateKey, rawRSAPublicKey, err = importPEM(*pemKeys)
		if err != nil {
			return nil, nil, err
		}
	} else {
		var err error
		rawRSAPrivateKey, rawRSAPublicKey, err = createNewKeys()
		if err != nil {
			return nil, nil, err
		}
	}

	jwkRSAPrivateKey, err := jwk.FromRaw(rawRSAPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf(`failed to create jwk.Key from RSA private key: %w`, err)
	}

	if err = jwkRSAPrivateKey.Set(jwk.KeyUsageKey, jwk.ForEncryption); err != nil {
		return nil, nil, fmt.Errorf(`failed to set jwk.KeyUsageKey: %w`, err)
	}
	if err = jwkRSAPrivateKey.Set(jwk.AlgorithmKey, jwa.RSA_OAEP); err != nil {
		return nil, nil, fmt.Errorf(`failed to set jwk.KeyUsageKey: %w`, err)
	}
	if err = jwk.AssignKeyID(jwkRSAPrivateKey); err != nil {
		return nil, nil, fmt.Errorf(`failed to assign key ID to jwk.Key: %w`, err)
	}

	jwkRSAPublicKey, err := jwk.FromRaw(rawRSAPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf(`failed to create jwk.Key from RSA public key: %w`, err)
	}

	fmt.Printf("public key algorithm: %s\n", jwkRSAPublicKey.Algorithm())

	if err = jwkRSAPublicKey.Set(jwk.KeyUsageKey, jwk.ForEncryption); err != nil {
		return nil, nil, fmt.Errorf(`failed to set jwk.KeyUsageKey: %w`, err)
	}
	if err = jwkRSAPublicKey.Set(jwk.AlgorithmKey, jwa.RSA_OAEP); err != nil {
		return nil, nil, fmt.Errorf(`failed to set jwk.KeyUsageKey: %w`, err)
	}
	if err = jwk.AssignKeyID(jwkRSAPublicKey); err != nil {
		return nil, nil, fmt.Errorf(`failed to assign key ID to jwk.Key: %w`, err)
	}

	return jwkRSAPrivateKey, jwkRSAPublicKey, nil

}

func createNewKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	// Generate RSA key
	rawRSAPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf(`failed to create RSA private key: %w`, err)
	}

	return rawRSAPrivateKey, &rawRSAPrivateKey.PublicKey, nil
}

func importPEM(pemKeys string) (any, any, error) {
	// Import from PEM
	pemPrivateKey, rest := pem.Decode([]byte(pemKeys))
	if pemPrivateKey == nil {
		return nil, nil, fmt.Errorf(`failed to decode PEM block containing RSA private key`)
	}
	rawRSAPrivateKey, err := x509.ParsePKCS8PrivateKey(pemPrivateKey.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf(`failed to parse RSA private key: %w`, err)
	}

	pemPublicKey, _ := pem.Decode(rest)
	if pemPublicKey == nil {
		return nil, nil, fmt.Errorf(`failed to decode PEM block containing RSA public key`)
	}
	rawRSAPublicKey, err := x509.ParsePKIXPublicKey(pemPublicKey.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf(`failed to parse RSA public key: %w`, err)
	}

	return rawRSAPrivateKey, rawRSAPublicKey, nil

}
