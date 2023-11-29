/*
Package encrypt is the external API other Go programs can use to encrypt SOPS files.
*/
package encrypt // import "github.com/getsops/sops/v3/encrypt"

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/cmd/sops/codes"
	"github.com/getsops/sops/v3/cmd/sops/common" // Re-export
	"github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/version"
)

type EncryptOpts struct {
	Cipher            sops.Cipher
	KeyServices       []keyservice.KeyServiceClient
	UnencryptedSuffix string
	EncryptedSuffix   string
	UnencryptedRegex  string
	EncryptedRegex    string
	MACOnlyEncrypted  bool
	KeyGroups         []sops.KeyGroup
	GroupThreshold    int
	// not exported, use File to use this
	inputPath string
}

// File is a wrapper around Data that reads a local encrypted
// file and returns its cleartext data in an []byte
func File(path string, opts EncryptOpts) (cleartext []byte, err error) {
	// Read the file into an []byte
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %w", path, err)
	}

	opts.inputPath, err = filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	formatFmt := formats.FormatForPathOrString(path, "")
	return DataWithFormat(fileBytes, formatFmt, opts)
}

func hasMetadata(branch sops.TreeBranch) bool {
	for _, b := range branch {
		if b.Key == "sops" {
			return true
		}
	}
	return false
}

// DataWithFormat is a helper that takes encrypted data, and a format enum value,
// decrypts the data and returns its cleartext in an []byte.
func DataWithFormat(data []byte, format formats.Format, opts EncryptOpts) (cleartext []byte, err error) {

	store := common.StoreForFormat(format, config.NewStoresConfig())

	// Load SOPS file and access the data key
	branches, err := store.LoadPlainFile(data)
	if err != nil {
		return nil, err
	}
	if len(branches) < 1 {
		return nil, common.NewExitError("data cannot be completely empty, it must contain at least one document", codes.NeedAtLeastOneDocument)
	}
	if hasMetadata(branches[0]) {
		return nil, common.NewExitError(err, codes.FileAlreadyEncrypted)
	}

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups:         opts.KeyGroups,
			UnencryptedSuffix: opts.UnencryptedSuffix,
			EncryptedSuffix:   opts.EncryptedSuffix,
			UnencryptedRegex:  opts.UnencryptedRegex,
			EncryptedRegex:    opts.EncryptedRegex,
			MACOnlyEncrypted:  opts.MACOnlyEncrypted,
			Version:           version.Version,
			ShamirThreshold:   opts.GroupThreshold,
		},
		FilePath: opts.inputPath,
	}
	dataKey, errs := tree.GenerateDataKeyWithKeyServices(opts.KeyServices)
	if len(errs) > 0 {
		err = fmt.Errorf("could not generate data key: %s", errs)
		return nil, err
	}
	err = common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    &tree,
		Cipher:  opts.Cipher,
	})
	if err != nil {
		return nil, err
	}
	encryptedFile, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return nil, common.NewExitError(fmt.Sprintf("could not marshal tree: %s", err), codes.ErrorDumpingTree)
	}
	return encryptedFile, nil

}

// Data is a helper that takes data and a format string,
// encrypts the data and returns its encryptedData in an []byte.
// The format string can be `json`, `yaml`, `ini`, `dotenv` or `binary`.
// If the format string is empty, binary format is assumed.
func Data(data []byte, format string, opts EncryptOpts) (encryptedData []byte, err error) {
	formatFmt := formats.FormatFromString(format)
	return DataWithFormat(data, formatFmt, opts)
}
