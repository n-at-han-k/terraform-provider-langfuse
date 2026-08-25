package langfuse

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Synthetic values ONLY. The algorithm below was confirmed against a live
// instance, but no real salt or key belongs in a public repository -- these are
// fixed inputs whose expected digest was computed with the same nesting.
const (
	testSalt      = "test-salt-not-a-real-secret"
	testSecretKey = "sk-lf-00000000-0000-4000-8000-000000000000"

	// sha256(secretKey || hex(sha256(salt)))
	wantFastHash = "10ef5f9fa4338a454089564dd7495620aac05ac5fc10f0b5a4096429981d6b75"
)

func TestCreateShaHashMatchesLangfuse(t *testing.T) {
	if got := createShaHash(testSecretKey, testSalt); got != wantFastHash {
		t.Fatalf("createShaHash mismatch:\n got  %s\n want %s", got, wantFastHash)
	}
}

// The two plausible-but-wrong readings of Langfuse's createShaHash. Both were
// tested against a real row and produce a hash Langfuse will never match, so a
// refactor that drifts into either must fail loudly rather than mint keys that
// authenticate as invalid.
func TestCreateShaHashRejectsWrongNestings(t *testing.T) {
	for _, wrong := range []struct {
		name string
		hash string
	}{
		{"raw salt digest bytes instead of hex text", "06773422f9671f994d2623429523dd07d88a2289fe218596d1686b063ded7829"},
		{"naive secret||salt concatenation", "39a2d26a1780ff3b3abb1c965765d15855fe9d9704eee7f7f7fe74ca454e8517"},
	} {
		if got := createShaHash(testSecretKey, testSalt); got == wrong.hash {
			t.Fatalf("createShaHash regressed to the %s form", wrong.name)
		}
	}
}

func TestDisplaySecretKey(t *testing.T) {
	if got, want := displaySecretKey(testSecretKey), "sk-lf-...0000"; got != want {
		t.Fatalf("displaySecretKey = %q, want %q", got, want)
	}
	// Too short to redact: returned as-is rather than panicking on a slice.
	if got := displaySecretKey("abc"); got != "abc" {
		t.Fatalf("displaySecretKey(short) = %q, want %q", got, "abc")
	}
}

func TestNewAPIKeyMaterial(t *testing.T) {
	m, err := newAPIKeyMaterial(testSalt)
	if err != nil {
		t.Fatalf("newAPIKeyMaterial: %v", err)
	}

	if !strings.HasPrefix(m.PublicKey, publicKeyPrefix) {
		t.Errorf("public key %q lacks %q prefix", m.PublicKey, publicKeyPrefix)
	}
	if !strings.HasPrefix(m.SecretKey, secretKeyPrefix) {
		t.Errorf("secret key %q lacks %q prefix", m.SecretKey, secretKeyPrefix)
	}
	// "pk-lf-" + 36-char dashed UUID.
	if len(m.PublicKey) != len(publicKeyPrefix)+36 {
		t.Errorf("public key %q is %d chars, want %d", m.PublicKey, len(m.PublicKey), len(publicKeyPrefix)+36)
	}

	// Langfuse verifies the presented secret against this with bcrypt.
	if err := bcrypt.CompareHashAndPassword([]byte(m.HashedSecretKey), []byte(m.SecretKey)); err != nil {
		t.Errorf("bcrypt hash does not verify against its own secret: %v", err)
	}
	if cost, err := bcrypt.Cost([]byte(m.HashedSecretKey)); err != nil || cost != bcryptCost {
		t.Errorf("bcrypt cost = %d (err %v), want %d", cost, err, bcryptCost)
	}

	if want := createShaHash(m.SecretKey, testSalt); m.FastHashedSecretKey != want {
		t.Errorf("fast hash not derived from the returned secret key")
	}
	if m.DisplaySecretKey != displaySecretKey(m.SecretKey) {
		t.Errorf("display key not derived from the returned secret key")
	}
}

// Without SALT the derived hash is wrong in a way nothing detects until a
// request fails, so an empty salt must be refused up front.
func TestNewAPIKeyMaterialRequiresSalt(t *testing.T) {
	if _, err := newAPIKeyMaterial(""); err == nil {
		t.Fatal("expected an error when salt is empty")
	}
}
