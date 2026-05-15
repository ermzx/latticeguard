package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestKeyManager_GenerateAndSave(t *testing.T) {
	tmpDir := t.TempDir()
	km := NewKeyManager(tmpDir)

	entity, err := km.GenerateKey("Test User", "test@example.com", packet.PubKeyAlgoMldsa65Ed25519)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if err := km.SavePrivateKey(entity, nil); err != nil {
		t.Fatalf("SavePrivateKey failed: %v", err)
	}

	if err := km.SavePublicKey(entity); err != nil {
		t.Fatalf("SavePublicKey failed: %v", err)
	}

	list, err := km.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(list.MyKeys) != 1 {
		t.Fatalf("expected 1 my key, got %d", len(list.MyKeys))
	}

	key := list.MyKeys[0]

	expectedUserID := "Test User <test@example.com>"
	if key.UserID != expectedUserID {
		t.Fatalf("expected UserID %q, got %q", expectedUserID, key.UserID)
	}

	if key.Algorithm != "ML-DSA-65+Ed25519" {
		t.Fatalf("expected Algorithm 'ML-DSA-65+Ed25519', got %q", key.Algorithm)
	}

	if !key.HasPrivate {
		t.Fatalf("expected HasPrivate to be true")
	}

	// Check private key file permissions
	fingerprint := key.Fingerprint
	privPath := filepath.Join(tmpDir, "keys", fingerprint+"_priv.asc")
	fi, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("failed to stat private key file: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("expected private key file permissions 0600, got %04o", fi.Mode().Perm())
	}
}
