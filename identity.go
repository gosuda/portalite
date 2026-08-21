package portalite

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// Identity is a secp256k1 identity used to authenticate with relays.
// Identity values can only be constructed through the functions in this
// package, which validate and derive all public fields from the private key.
type Identity struct {
	name       string
	address    string
	publicKey  string
	privateKey string
	key        *secp256k1.PrivateKey
}

// GenerateIdentity creates a new identity with the supplied DNS-label name.
func GenerateIdentity(name string) (Identity, error) {
	normalizedName, err := normalizeIdentityName(name)
	if err != nil {
		return Identity{}, err
	}

	key, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return Identity{}, fmt.Errorf("generate secp256k1 private key: %w", err)
	}
	return identityFromKey(normalizedName, key), nil
}

// IdentityFromPrivateKey constructs an identity from a 32-byte secp256k1
// private key encoded as hexadecimal. An optional 0x prefix is accepted.
func IdentityFromPrivateKey(name, privateKeyHex string) (Identity, error) {
	normalizedName, err := normalizeIdentityName(name)
	if err != nil {
		return Identity{}, err
	}

	key, err := parsePrivateKey(privateKeyHex)
	if err != nil {
		return Identity{}, err
	}
	return identityFromKey(normalizedName, key), nil
}

// ParseIdentity parses and validates a persisted identity JSON document.
func ParseIdentity(data []byte) (Identity, error) {
	var identity Identity
	if err := json.Unmarshal(data, &identity); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

// Name returns the normalized identity name.
func (i Identity) Name() string {
	return i.name
}

// Address returns the EIP-55 checksummed Ethereum address for the identity.
func (i Identity) Address() string {
	return i.address
}

// PublicKey returns the compressed SEC1 public key as lowercase hexadecimal.
func (i Identity) PublicKey() string {
	return i.publicKey
}

// MarshalJSON serializes the identity's private-key form. The private key is
// intentionally included so the result can be used as the persisted identity
// file consumed by ParseIdentity.
func (i Identity) MarshalJSON() ([]byte, error) {
	if i.key == nil || i.name == "" || i.address == "" || i.publicKey == "" || i.privateKey == "" {
		return nil, errors.New("cannot marshal an uninitialized identity")
	}

	type persistedIdentity struct {
		Name       string `json:"name"`
		Address    string `json:"address"`
		PublicKey  string `json:"public_key"`
		PrivateKey string `json:"private_key"`
	}
	return json.Marshal(persistedIdentity{
		Name:       i.name,
		Address:    i.address,
		PublicKey:  i.publicKey,
		PrivateKey: i.privateKey,
	})
}

// UnmarshalJSON validates a persisted identity before replacing the receiver.
// Unknown fields from the larger portal identity schema are intentionally
// ignored.
func (i *Identity) UnmarshalJSON(data []byte) error {
	if i == nil {
		return errors.New("cannot unmarshal identity into a nil receiver")
	}

	var stored struct {
		Name       string `json:"name"`
		Address    string `json:"address"`
		PublicKey  string `json:"public_key"`
		PrivateKey string `json:"private_key"`
		Mnemonic   string `json:"mnemonic"`
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		return fmt.Errorf("parse identity JSON: %w", err)
	}
	if strings.TrimSpace(stored.PrivateKey) == "" {
		if strings.TrimSpace(stored.Mnemonic) != "" {
			return errors.New("unsupported identity format: mnemonic without private_key")
		}
		return errors.New("identity private_key is required")
	}

	candidate, err := IdentityFromPrivateKey(stored.Name, stored.PrivateKey)
	if err != nil {
		return err
	}
	if stored.PublicKey != "" {
		publicKey, err := normalizeFixedHex(stored.PublicKey, 33, "identity public_key")
		if err != nil {
			return err
		}
		if publicKey != candidate.publicKey {
			return errors.New("identity public_key does not match private_key")
		}
	}
	if stored.Address != "" {
		address, err := normalizeFixedHex(stored.Address, 20, "identity address")
		if err != nil {
			return err
		}
		if address != strings.ToLower(strings.TrimPrefix(candidate.address, "0x")) {
			return errors.New("identity address does not match private_key")
		}
	}

	*i = candidate
	return nil
}

func normalizeIdentityName(name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if len(name) == 0 {
		return "", errors.New("identity name is required")
	}
	if len(name) > 63 {
		return "", errors.New("identity name must be at most 63 ASCII characters")
	}
	if name[0] == '-' || name[len(name)-1] == '-' {
		return "", errors.New("identity name must not begin or end with a hyphen")
	}
	for _, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' {
			continue
		}
		return "", errors.New("identity name must be a single ASCII DNS label containing only letters, digits, and hyphens")
	}
	return name, nil
}

func parsePrivateKey(raw string) (*secp256k1.PrivateKey, error) {
	normalized := strings.TrimSpace(raw)
	if len(normalized) >= 2 && normalized[0] == '0' && (normalized[1] == 'x' || normalized[1] == 'X') {
		normalized = normalized[2:]
	}
	if len(normalized) != 64 {
		return nil, errors.New("identity private_key must encode exactly 32 bytes")
	}

	serialized, err := hex.DecodeString(normalized)
	if err != nil {
		return nil, fmt.Errorf("identity private_key is not valid hexadecimal: %w", err)
	}
	var scalar secp256k1.ModNScalar
	if overflow := scalar.SetByteSlice(serialized); overflow || scalar.IsZero() {
		return nil, errors.New("identity private_key must be in the secp256k1 scalar range")
	}
	return secp256k1.PrivKeyFromBytes(serialized), nil
}

func identityFromKey(name string, key *secp256k1.PrivateKey) Identity {
	privateKey := hex.EncodeToString(key.Serialize())
	publicKeyBytes := key.PubKey().SerializeCompressed()
	publicKey := hex.EncodeToString(publicKeyBytes)
	return Identity{
		name:       name,
		address:    ethereumAddress(key.PubKey()),
		publicKey:  publicKey,
		privateKey: privateKey,
		key:        key,
	}
}

func ethereumAddress(publicKey *secp256k1.PublicKey) string {
	uncompressed := publicKey.SerializeUncompressed()
	hasher := sha3.NewLegacyKeccak256()
	_, _ = hasher.Write(uncompressed[1:])
	digest := hasher.Sum(nil)
	return checksumEthereumAddress(hex.EncodeToString(digest[len(digest)-20:]))
}

func normalizeEthereumAddress(raw string) (string, error) {
	normalized := strings.TrimSpace(raw)
	if len(normalized) >= 2 && normalized[0] == '0' && (normalized[1] == 'x' || normalized[1] == 'X') {
		normalized = normalized[2:]
	}

	lower, err := normalizeFixedHex(raw, 20, "Ethereum address")
	if err != nil {
		return "", err
	}
	canonical := checksumEthereumAddress(lower)
	if normalized != lower && normalized != strings.ToUpper(lower) && normalized != canonical[2:] {
		return "", errors.New("Ethereum address has an invalid EIP-55 checksum")
	}
	return canonical, nil
}

func checksumEthereumAddress(lower string) string {
	hasher := sha3.NewLegacyKeccak256()
	_, _ = io.WriteString(hasher, lower)
	checksum := hasher.Sum(nil)

	result := []byte(lower)
	for index, char := range result {
		if char < 'a' || char > 'f' {
			continue
		}
		nibble := checksum[index/2]
		if index%2 == 0 {
			nibble >>= 4
		} else {
			nibble &= 0x0f
		}
		if nibble >= 8 {
			result[index] = char - ('a' - 'A')
		}
	}
	return "0x" + string(result)
}

func normalizeFixedHex(raw string, size int, field string) (string, error) {
	normalized := strings.TrimSpace(raw)
	if len(normalized) >= 2 && normalized[0] == '0' && (normalized[1] == 'x' || normalized[1] == 'X') {
		normalized = normalized[2:]
	}
	if len(normalized) != size*2 {
		return "", fmt.Errorf("%s must encode exactly %d bytes", field, size)
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return "", fmt.Errorf("%s is not valid hexadecimal: %w", field, err)
	}
	return strings.ToLower(normalized), nil
}

func (i Identity) signEthereumPersonalMessage(message string) (string, error) {
	if i.key == nil {
		return "", errors.New("cannot sign with an uninitialized identity")
	}

	prefix := "\x19Ethereum Signed Message:\n" + strconv.Itoa(len(message))
	hasher := sha3.NewLegacyKeccak256()
	_, _ = io.WriteString(hasher, prefix)
	_, _ = io.WriteString(hasher, message)
	digest := hasher.Sum(nil)

	compact := ecdsa.SignCompact(i.key, digest, false)
	signature := make([]byte, 65)
	copy(signature[:64], compact[1:])
	signature[64] = compact[0]
	return "0x" + hex.EncodeToString(signature), nil
}
