package gui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"latticeguard/internal/model"
	"latticeguard/internal/service"
)

type App struct {
	App           fyne.App
	Window        fyne.Window
	Config        model.Config
	KeyManager    *service.KeyManager
	FileManager   *service.FileManager
	TextManager   *service.TextManager
	PGPOps        *service.PGPOps
	Tabs          *container.AppTabs
	onKeysChanged func()
}

func New(cfg model.Config) *App {
	f := app.NewWithID("com.latticeguard.app")
	w := f.NewWindow("LatticeGuard - PGP密钥管理")
	w.Resize(fyne.NewSize(900, 650))

	km := service.NewKeyManager(cfg.DataDir)
	a := &App{
		App:         f,
		Window:      w,
		Config:      cfg,
		KeyManager:  km,
		FileManager: service.NewFileManager(),
		TextManager: service.NewTextManager(cfg.Editor),
		PGPOps:      service.NewPGPOps(km),
	}

	tabs := container.NewAppTabs(
		container.NewTabItem("证书", a.makeKeyTab()),
		container.NewTabItem("文件", a.makeFileTab()),
		container.NewTabItem("文本", a.makeTextTab()),
		container.NewTabItem("设置", a.makeSettingsTab()),
	)
	tabs.SetTabLocation(container.TabLocationTop)
	a.Tabs = tabs

	w.SetOnDropped(func(pos fyne.Position, uris []fyne.URI) {
		if a.Tabs.SelectedIndex() != 0 {
			return
		}
		for _, uri := range uris {
			reader, err := os.Open(uri.Path())
			if err != nil {
				dialog.ShowError(err, w)
				continue
			}
			data, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				dialog.ShowError(err, w)
				continue
			}
			if err := a.importKeyData(data); err != nil {
				dialog.ShowError(err, w)
				continue
			}
		}
		dialog.ShowInformation("成功", "密钥导入成功", w)
		if a.onKeysChanged != nil {
			a.onKeysChanged()
		}
	})

	w.SetContent(tabs)
	return a
}

func (a *App) Run() {
	a.Window.ShowAndRun()
}

func (a *App) importKeyData(data []byte) error {
	block, err := armor.Decode(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("不是有效的PGP密钥文件: %w", err)
	}

	fingerprint := ""
	reader2 := packet.NewReader(block.Body)
	for {
		p, err := reader2.Next()
		if err != nil {
			break
		}
		switch pkt := p.(type) {
		case *packet.PublicKey:
			if !pkt.IsSubkey {
				fingerprint = fmt.Sprintf("%X", pkt.Fingerprint)
			}
		case *packet.PrivateKey:
			if fingerprint == "" {
				fingerprint = fmt.Sprintf("%X", pkt.PublicKey.Fingerprint)
			}
		}
	}

	if fingerprint == "" {
		return fmt.Errorf("无法从文件中提取密钥指纹")
	}

	var destPath string
	if block.Type == "PGP PRIVATE KEY BLOCK" {
		destPath = filepath.Join(a.KeyManager.DataDir, "keys", fingerprint+"_priv.asc")
	} else {
		destPath = filepath.Join(a.KeyManager.DataDir, "keys", "pub", fingerprint+"_pub.asc")
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0700); err != nil {
		return err
	}
	return os.WriteFile(destPath, data, 0600)
}

func (a *App) saveConfig() error {
	if err := os.MkdirAll(a.Config.DataDir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(a.Config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(a.Config.DataDir, "config.json"), data, 0600)
}
