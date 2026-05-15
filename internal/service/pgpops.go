package service

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	v2 "github.com/ProtonMail/go-crypto/openpgp/v2"
	"latticeguard/internal/model"
)

type PGPOps struct {
	KeyManager *KeyManager
}

func NewPGPOps(km *KeyManager) *PGPOps {
	return &PGPOps{KeyManager: km}
}

func (p *PGPOps) LoadEntity(fingerprint string, needPrivate bool) (*v2.Entity, error) {
	var path string
	if needPrivate {
		path = filepath.Join(p.KeyManager.DataDir, "keys", fingerprint+"_priv.asc")
	} else {
		path = filepath.Join(p.KeyManager.DataDir, "keys", "pub", fingerprint+"_pub.asc")
		if _, err := os.Stat(path); os.IsNotExist(err) {
			path = filepath.Join(p.KeyManager.DataDir, "keys", fingerprint+"_priv.asc")
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	block, err := armor.Decode(f)
	if err != nil {
		return nil, err
	}
	return v2.ReadEntity(packet.NewReader(block.Body))
}

func (p *PGPOps) GetDefaultEntity(keys model.KeyList, defaultKey string) (*v2.Entity, error) {
	fp := defaultKey
	if fp == "" && len(keys.MyKeys) > 0 {
		fp = keys.MyKeys[0].Fingerprint
	}
	if fp == "" {
		return nil, fmt.Errorf("没有可用的默认证书")
	}
	return p.LoadEntity(fp, true)
}

func (p *PGPOps) BuildKeyring(keys []model.KeyInfo, needPrivate bool) v2.EntityList {
	var keyring v2.EntityList
	for _, key := range keys {
		entity, err := p.LoadEntity(key.Fingerprint, needPrivate)
		if err != nil {
			continue
		}
		keyring = append(keyring, entity)
	}
	return keyring
}

func (p *PGPOps) SignFile(inputPath string, signer *v2.Entity, fm *FileManager) (string, error) {
	data, err := fm.ReadFile(inputPath)
	if err != nil {
		return "", err
	}
	outPath := fm.DefaultOutputPath(inputPath, ".sig")
	out, err := os.Create(outPath)
	if err != nil {
		return "", err
	}
	defer out.Close()
	arm, err := armor.Encode(out, "PGP SIGNATURE", nil)
	if err != nil {
		return "", err
	}
	if err := v2.DetachSign(arm, []*v2.Entity{signer}, bytes.NewReader(data), nil); err != nil {
		arm.Close()
		return "", err
	}
	if err := arm.Close(); err != nil {
		return "", err
	}
	return outPath, nil
}

func (p *PGPOps) EncryptFile(inputPath string, recipients []*v2.Entity, signer *v2.Entity, fm *FileManager) (string, error) {
	data, err := fm.ReadFile(inputPath)
	if err != nil {
		return "", err
	}
	outPath := fm.DefaultOutputPath(inputPath, ".asc")
	out, err := os.Create(outPath)
	if err != nil {
		return "", err
	}
	defer out.Close()
	arm, err := armor.Encode(out, "PGP MESSAGE", nil)
	if err != nil {
		return "", err
	}
	var signers []*v2.Entity
	if signer != nil {
		signers = []*v2.Entity{signer}
	}
	plaintext, err := v2.Encrypt(arm, recipients, signers, nil, nil, nil)
	if err != nil {
		arm.Close()
		return "", err
	}
	if _, err := plaintext.Write(data); err != nil {
		plaintext.Close()
		arm.Close()
		return "", err
	}
	if err := plaintext.Close(); err != nil {
		arm.Close()
		return "", err
	}
	if err := arm.Close(); err != nil {
		return "", err
	}
	return outPath, nil
}

func decryptPrompt(passphrase string) func(keys []v2.Key, symmetric bool) ([]byte, error) {
	return func(keys []v2.Key, symmetric bool) ([]byte, error) {
		if symmetric {
			return nil, fmt.Errorf("不支持对称加密")
		}
		if passphrase == "" {
			return nil, fmt.Errorf("私钥已加密，请提供密码")
		}
		return []byte(passphrase), nil
	}
}

func extractSignatureInfo(md *v2.MessageDetails) model.SignatureInfo {
	if md == nil || !md.IsSigned {
		return model.SignatureInfo{}
	}
	info := model.SignatureInfo{
		IsSigned: true,
		Valid:    md.SignatureError == nil,
	}
	if md.SignatureError != nil {
		return info
	}
	if md.SignedBy != nil && md.SignedBy.PublicKey != nil {
		info.SignerFingerprint = fmt.Sprintf("%X", md.SignedBy.PublicKey.Fingerprint)
	}
	return info
}

func (p *PGPOps) DecryptFile(inputPath, passphrase string, keyring v2.EntityList, fm *FileManager) (string, model.SignatureInfo, error) {
	data, err := fm.ReadFile(inputPath)
	if err != nil {
		return "", model.SignatureInfo{}, err
	}
	block, err := armor.Decode(bytes.NewReader(data))
	if err != nil {
		return "", model.SignatureInfo{}, fmt.Errorf("不是有效的 armored 数据: %w", err)
	}
	md, err := v2.ReadMessage(block.Body, keyring, decryptPrompt(passphrase), nil)
	if err != nil {
		return "", model.SignatureInfo{}, fmt.Errorf("解密失败: %w", err)
	}
	decrypted, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", model.SignatureInfo{}, fmt.Errorf("读取明文失败: %w", err)
	}
	sigInfo := extractSignatureInfo(md)
	outPath := fm.DefaultOutputPath(inputPath, ".decrypted")
	if err := fm.WriteFile(outPath, decrypted); err != nil {
		return "", model.SignatureInfo{}, err
	}
	return outPath, sigInfo, nil
}

func (p *PGPOps) VerifyFile(inputPath string, keyring v2.EntityList, fm *FileManager) (string, error) {
	data, err := fm.ReadFile(inputPath)
	if err != nil {
		return "", err
	}

	// Try inline signature first (PGP MESSAGE with embedded signature)
	block, err := armor.Decode(bytes.NewReader(data))
	if err == nil && block.Type == "PGP MESSAGE" {
		prompt := func(keys []v2.Key, symmetric bool) ([]byte, error) {
			if symmetric {
				return nil, fmt.Errorf("不支持对称加密")
			}
			return nil, fmt.Errorf("验证不需要私钥")
		}
		md, err := v2.ReadMessage(block.Body, keyring, prompt, nil)
		if err == nil {
			_, readErr := io.ReadAll(md.UnverifiedBody)
			if readErr != nil {
				return "", fmt.Errorf("读取正文失败: %w", readErr)
			}
			if !md.IsSigned {
				return "", fmt.Errorf("消息未签名")
			}
			if md.SignatureError != nil {
				return "", fmt.Errorf("签名无效: %w", md.SignatureError)
			}
			fp := ""
			if md.SignedBy != nil && md.SignedBy.PublicKey != nil {
				fp = fmt.Sprintf("%X", md.SignedBy.PublicKey.Fingerprint)
			}
			return fmt.Sprintf("内联签名验证成功，签名者指纹: %s", fp), nil
		}
	}

	// Fallback: detached signature (.sig or .asc companion file)
	sigPath := fm.DefaultOutputPath(inputPath, ".sig")
	sigData, err := fm.ReadFile(sigPath)
	if err != nil {
		sigPath = inputPath + ".asc"
		sigData, err = fm.ReadFile(sigPath)
		if err != nil {
			return "", fmt.Errorf("找不到签名文件 (.sig 或 .asc)，且非内联签名消息: %w", err)
		}
	}
	_, signer, err := v2.VerifyArmoredDetachedSignature(keyring, bytes.NewReader(data), bytes.NewReader(sigData), nil)
	if err != nil {
		_, signer, err = v2.VerifyDetachedSignature(keyring, bytes.NewReader(data), bytes.NewReader(sigData), nil)
		if err != nil {
			return "", fmt.Errorf("签名验证失败: %w", err)
		}
	}
	if signer == nil {
		return "", fmt.Errorf("签名验证失败: 找不到签名者")
	}
	fp := fmt.Sprintf("%X", signer.PrimaryKey.Fingerprint)
	return fmt.Sprintf("分离签名验证成功，签名者指纹: %s", fp), nil
}

func (p *PGPOps) SignText(content string, signer *v2.Entity) (string, error) {
	var buf bytes.Buffer
	arm, err := armor.Encode(&buf, "PGP SIGNATURE", nil)
	if err != nil {
		return "", err
	}
	if err := v2.DetachSign(arm, []*v2.Entity{signer}, bytes.NewReader([]byte(content)), nil); err != nil {
		arm.Close()
		return "", err
	}
	if err := arm.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (p *PGPOps) EncryptText(content string, recipients []*v2.Entity, signer *v2.Entity) (string, error) {
	var buf bytes.Buffer
	arm, err := armor.Encode(&buf, "PGP MESSAGE", nil)
	if err != nil {
		return "", err
	}
	var signers []*v2.Entity
	if signer != nil {
		signers = []*v2.Entity{signer}
	}
	plaintext, err := v2.Encrypt(arm, recipients, signers, nil, nil, nil)
	if err != nil {
		arm.Close()
		return "", err
	}
	if _, err := plaintext.Write([]byte(content)); err != nil {
		plaintext.Close()
		arm.Close()
		return "", err
	}
	if err := plaintext.Close(); err != nil {
		arm.Close()
		return "", err
	}
	if err := arm.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (p *PGPOps) DecryptText(content, passphrase string, keyring v2.EntityList) (string, model.SignatureInfo, error) {
	block, err := armor.Decode(bytes.NewReader([]byte(content)))
	if err != nil {
		return "", model.SignatureInfo{}, fmt.Errorf("不是有效的 armored 数据: %w", err)
	}
	md, err := v2.ReadMessage(block.Body, keyring, decryptPrompt(passphrase), nil)
	if err != nil {
		return "", model.SignatureInfo{}, fmt.Errorf("解密失败: %w", err)
	}
	decrypted, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", model.SignatureInfo{}, fmt.Errorf("读取明文失败: %w", err)
	}
	sigInfo := extractSignatureInfo(md)
	return string(decrypted), sigInfo, nil
}

func (p *PGPOps) VerifyText(content string, keyring v2.EntityList) (string, error) {
	block, err := armor.Decode(bytes.NewReader([]byte(content)))
	if err != nil {
		return "", fmt.Errorf("不是有效的 armored 数据: %w", err)
	}

	if block.Type != "PGP MESSAGE" {
		return "", fmt.Errorf("文本验证仅支持内联签名 (PGP MESSAGE)，不支持分离签名")
	}

	prompt := func(keys []v2.Key, symmetric bool) ([]byte, error) {
		if symmetric {
			return nil, fmt.Errorf("不支持对称加密")
		}
		return nil, fmt.Errorf("验证不需要私钥")
	}
	md, err := v2.ReadMessage(block.Body, keyring, prompt, nil)
	if err != nil {
		return "", fmt.Errorf("读取消息失败: %w", err)
	}
	_, readErr := io.ReadAll(md.UnverifiedBody)
	if readErr != nil {
		return "", fmt.Errorf("读取正文失败: %w", readErr)
	}
	if !md.IsSigned {
		return "", fmt.Errorf("消息未签名")
	}
	if md.SignatureError != nil {
		return "", fmt.Errorf("签名无效: %w", md.SignatureError)
	}
	fp := ""
	if md.SignedBy != nil && md.SignedBy.PublicKey != nil {
		fp = fmt.Sprintf("%X", md.SignedBy.PublicKey.Fingerprint)
	}
	return fmt.Sprintf("内联签名验证成功，签名者指纹: %s", fp), nil
}
