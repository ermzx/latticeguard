package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	v2 "github.com/ProtonMail/go-crypto/openpgp/v2"
	"latticeguard/internal/model"
)

type KeyManager struct {
	DataDir string
}

func NewKeyManager(dataDir string) *KeyManager {
	return &KeyManager{DataDir: dataDir}
}

func (km *KeyManager) EnsureDirs() error {
	keysDir := filepath.Join(km.DataDir, "keys")
	pubDir := filepath.Join(keysDir, "pub")
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return err
	}
	return os.MkdirAll(pubDir, 0700)
}

func (km *KeyManager) GenerateKey(name, email string, algo packet.PublicKeyAlgorithm) (*v2.Entity, error) {
	config := &packet.Config{
		V6Keys:    true,
		Algorithm: algo,
	}
	return v2.NewEntity(name, "", email, config)
}

func (km *KeyManager) SavePrivateKey(entity *v2.Entity, passphrase []byte) error {
	if entity.PrimaryKey == nil {
		return fmt.Errorf("entity has no primary key")
	}

	if err := km.EnsureDirs(); err != nil {
		return err
	}

	if len(passphrase) > 0 {
		if entity.PrivateKey == nil {
			return fmt.Errorf("entity has no private key")
		}
		if err := entity.PrivateKey.Encrypt(passphrase); err != nil {
			return err
		}
	}

	fingerprint := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
	path := filepath.Join(km.DataDir, "keys", fingerprint+"_priv.asc")

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	arm, err := armor.Encode(f, "PGP PRIVATE KEY BLOCK", nil)
	if err != nil {
		return err
	}
	defer arm.Close()

	if err := entity.SerializePrivate(arm, &packet.Config{}); err != nil {
		return err
	}

	return nil
}

func (km *KeyManager) SavePublicKey(entity *v2.Entity) error {
	if entity.PrimaryKey == nil {
		return fmt.Errorf("entity has no primary key")
	}

	if err := km.EnsureDirs(); err != nil {
		return err
	}

	fingerprint := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
	path := filepath.Join(km.DataDir, "keys", "pub", fingerprint+"_pub.asc")

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	arm, err := armor.Encode(f, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		return err
	}
	defer arm.Close()

	if err := entity.Serialize(arm); err != nil {
		return err
	}

	return nil
}

func (km *KeyManager) ListKeys() (model.KeyList, error) {
	var list model.KeyList
	myFingerprints := make(map[string]bool)

	keysDir := filepath.Join(km.DataDir, "keys")
	pubDir := filepath.Join(keysDir, "pub")

	entries, err := os.ReadDir(keysDir)
	if err != nil {
		if os.IsNotExist(err) {
			return list, nil
		}
		return list, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, "_priv.asc") {
			continue
		}
		path := filepath.Join(keysDir, name)
		info, err := km.loadKeyInfo(path, true)
		if err != nil {
			continue
		}
		list.MyKeys = append(list.MyKeys, info)
		myFingerprints[info.Fingerprint] = true
	}

	pubEntries, err := os.ReadDir(pubDir)
	if err != nil {
		if os.IsNotExist(err) {
			return list, nil
		}
		return list, err
	}

	for _, entry := range pubEntries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, "_pub.asc") {
			continue
		}
		path := filepath.Join(pubDir, name)
		info, err := km.loadKeyInfo(path, false)
		if err != nil {
			continue
		}
		if !myFingerprints[info.Fingerprint] {
			list.ImportedKeys = append(list.ImportedKeys, info)
		}
	}

	return list, nil
}

func (km *KeyManager) loadKeyInfo(path string, hasPrivate bool) (model.KeyInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return model.KeyInfo{}, err
	}
	defer f.Close()

	block, err := armor.Decode(f)
	if err != nil {
		return model.KeyInfo{}, err
	}

	reader := packet.NewReader(block.Body)
	var info model.KeyInfo
	info.HasPrivate = hasPrivate
	var creationTime time.Time

	for {
		p, err := reader.Next()
		if err != nil {
			break
		}
		switch pkt := p.(type) {
		case *packet.PublicKey:
			if !pkt.IsSubkey {
				info.Fingerprint = fmt.Sprintf("%X", pkt.Fingerprint)
				info.Algorithm = km.algoName(pkt.PubKeyAlgo)
				info.Created = pkt.CreationTime
				creationTime = pkt.CreationTime
			} else if info.SubkeyAlgo == "" {
				info.SubkeyAlgo = km.algoName(pkt.PubKeyAlgo)
			}
		case *packet.PrivateKey:
			pub := &pkt.PublicKey
			if info.Fingerprint == "" {
				info.Fingerprint = fmt.Sprintf("%X", pub.Fingerprint)
				info.Algorithm = km.algoName(pub.PubKeyAlgo)
				info.Created = pub.CreationTime
				creationTime = pub.CreationTime
			} else if info.SubkeyAlgo == "" {
				info.SubkeyAlgo = km.algoName(pub.PubKeyAlgo)
			}
		case *packet.UserId:
			if info.UserID == "" {
				info.UserID = pkt.Id
			}
		case *packet.Signature:
			if info.Expires == nil && pkt.KeyLifetimeSecs != nil && *pkt.KeyLifetimeSecs > 0 &&
				(pkt.SigType == packet.SigTypeDirectSignature || pkt.SigType == packet.SigTypeGenericCert || pkt.SigType == packet.SigTypePositiveCert) {
				expiry := creationTime.Add(time.Duration(*pkt.KeyLifetimeSecs) * time.Second)
				info.Expires = &expiry
			}
		}
	}

	return info, nil
}

func (km *KeyManager) algoName(a packet.PublicKeyAlgorithm) string {
	switch a {
	case packet.PubKeyAlgoMldsa65Ed25519:
		return "ML-DSA-65+Ed25519"
	case packet.PubKeyAlgoMldsa87Ed448:
		return "ML-DSA-87+Ed448"
	case packet.PubKeyAlgoMlkem768X25519:
		return "ML-KEM-768+X25519"
	case packet.PubKeyAlgoMlkem1024X448:
		return "ML-KEM-1024+X448"
	case packet.PubKeyAlgoEd25519:
		return "Ed25519"
	case packet.PubKeyAlgoEd448:
		return "Ed448"
	case packet.PubKeyAlgoRSA:
		return "RSA"
	case packet.PubKeyAlgoECDSA:
		return "ECDSA"
	case packet.PubKeyAlgoECDH:
		return "ECDH"
	case packet.PubKeyAlgoEdDSA:
		return "EdDSA"
	case packet.PubKeyAlgoX25519:
		return "X25519"
	case packet.PubKeyAlgoX448:
		return "X448"
	case packet.PubKeyAlgoElGamal:
		return "ElGamal"
	case packet.PubKeyAlgoDSA:
		return "DSA"
	default:
		return fmt.Sprintf("Unknown(%d)", a)
	}
}
