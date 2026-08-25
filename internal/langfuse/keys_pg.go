package langfuse

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// Key material for a row in Langfuse's `api_keys` table.
//
// The Instance Management API is Enterprise-only, so this provider writes the
// rows itself. That means reproducing Langfuse's own key derivation EXACTLY --
// a key whose hashes disagree with what Langfuse computes at auth time is
// accepted by the database and then rejected on every request, which is the
// worst possible failure mode: silent, and only visible to whoever tries to use
// the credential later.
//
// Every constant below is checked against a live instance, not inferred:
//
//   public_key             "pk-lf-" + randomUUID()
//   secret_key             "sk-lf-" + randomUUID()      (returned once, never stored)
//   display_secret_key     sk[:6] + "..." + sk[len-4:]
//   hashed_secret_key      bcrypt(sk, cost 11)          -> "$2a$11$..." (60 chars)
//   fast_hashed_secret_key sha256(sk || hex(sha256(SALT)))
//
// The last one is why the provider needs SALT. Langfuse's createShaHash()
// hashes the salt, HEX-ENCODES that digest, and appends the resulting TEXT to
// the secret key before the outer hash -- it does not append the raw digest
// bytes, and it does not concatenate the salt directly. Both of those plausible
// readings were tested against a real row and produce the wrong digest.
const (
	publicKeyPrefix = "pk-lf-"
	secretKeyPrefix = "sk-lf-"

	// bcryptjs on the Langfuse side; matches the "$2a$11$" prefix observed in
	// live rows. Changing this does not break existing keys (the cost is
	// encoded in the hash) but does mean new keys verify at a different cost.
	bcryptCost = 11
)

type apiKeyMaterial struct {
	PublicKey           string
	SecretKey           string
	HashedSecretKey     string
	FastHashedSecretKey string
	DisplaySecretKey    string
}

// createShaHash mirrors Langfuse's createShaHash(privateKey, salt).
//
//	createHash("sha256")
//	  .update(privateKey)
//	  .update(createHash("sha256").update(salt, "utf8").digest("hex"))
//	  .digest("hex")
func createShaHash(key, salt string) string {
	saltDigest := sha256.Sum256([]byte(salt))
	outer := sha256.New()
	outer.Write([]byte(key))
	outer.Write([]byte(hex.EncodeToString(saltDigest[:])))
	return hex.EncodeToString(outer.Sum(nil))
}

// displaySecretKey is what the UI shows in place of the secret it can no longer
// read back: first 6 characters (the "sk-lf-" prefix) and the last 4.
func displaySecretKey(secretKey string) string {
	if len(secretKey) < 10 {
		return secretKey
	}
	return secretKey[:6] + "..." + secretKey[len(secretKey)-4:]
}

// randomUUID returns a RFC 4122 version 4 UUID in the canonical dashed form,
// matching Node's crypto.randomUUID() that Langfuse uses to build key bodies.
//
// Hand-rolled rather than pulling in a UUID dependency: this is the only place
// the provider needs one, and the format is fully specified.
func randomUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// newAPIKeyMaterial mints a fresh key pair and every derived column the
// api_keys row needs. The plaintext secret is returned to the caller for
// exactly one trip out to Terraform state; nothing here persists it.
func newAPIKeyMaterial(salt string) (*apiKeyMaterial, error) {
	if salt == "" {
		return nil, fmt.Errorf("salt is required to derive API key hashes; set the provider's `salt` argument to the same value as the Langfuse instance's SALT")
	}

	publicUUID, err := randomUUID()
	if err != nil {
		return nil, err
	}
	secretUUID, err := randomUUID()
	if err != nil {
		return nil, err
	}

	secretKey := secretKeyPrefix + secretUUID

	hashed, err := bcrypt.GenerateFromPassword([]byte(secretKey), bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("failed to bcrypt secret key: %w", err)
	}

	return &apiKeyMaterial{
		PublicKey:           publicKeyPrefix + publicUUID,
		SecretKey:           secretKey,
		HashedSecretKey:     string(hashed),
		FastHashedSecretKey: createShaHash(secretKey, salt),
		DisplaySecretKey:    displaySecretKey(secretKey),
	}, nil
}
