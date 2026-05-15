package gui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"latticeguard/internal/service"
)

func (a *App) makeSettingsTab() fyne.CanvasObject {
	dirEntry := widget.NewEntry()
	dirEntry.SetText(a.Config.DataDir)
	dirBtn := widget.NewButton("浏览...", func() {
		dialog.ShowFolderOpen(func(list fyne.ListableURI, err error) {
			if err != nil || list == nil {
				return
			}
			dirEntry.SetText(list.Path())
		}, a.Window)
	})
	dirRow := container.NewBorder(nil, nil, nil, dirBtn, dirEntry)

	editorSelect := widget.NewSelect([]string{"nano", "vim", "custom"}, nil)
	editorSelect.SetSelected(a.Config.Editor)
	if a.Config.Editor != "nano" && a.Config.Editor != "vim" && a.Config.Editor != "custom" && a.Config.Editor != "" {
		editorSelect.SetSelected("custom")
	} else if a.Config.Editor == "" {
		editorSelect.SetSelected("nano")
	}
	customEditorEntry := widget.NewEntry()
	customEditorEntry.SetPlaceHolder("自定义编辑器路径")
	customEditorEntry.Hide()

	editorSelect.OnChanged = func(val string) {
		if val == "custom" {
			customEditorEntry.Show()
		} else {
			customEditorEntry.Hide()
		}
	}

	algoSelect := widget.NewSelect([]string{"ML-DSA-65+Ed25519", "ML-DSA-87+Ed448", "Ed25519"}, nil)
	switch a.Config.DefaultAlgo {
	case int(packet.PubKeyAlgoMldsa65Ed25519):
		algoSelect.SetSelected("ML-DSA-65+Ed25519")
	case int(packet.PubKeyAlgoMldsa87Ed448):
		algoSelect.SetSelected("ML-DSA-87+Ed448")
	case int(packet.PubKeyAlgoEd25519):
		algoSelect.SetSelected("Ed25519")
	default:
		algoSelect.SetSelected("ML-DSA-65+Ed25519")
	}

	defaultKeyLabel := widget.NewLabel(a.Config.DefaultKey)
	if a.Config.DefaultKey == "" {
		defaultKeyLabel.SetText("(未设置)")
	}

	statusLabel := widget.NewLabel("")

	saveBtn := widget.NewButton("保存设置", func() {
		a.Config.DataDir = dirEntry.Text
		if editorSelect.Selected == "custom" {
			a.Config.Editor = customEditorEntry.Text
		} else {
			a.Config.Editor = editorSelect.Selected
		}

		switch algoSelect.Selected {
		case "ML-DSA-65+Ed25519":
			a.Config.DefaultAlgo = int(packet.PubKeyAlgoMldsa65Ed25519)
		case "ML-DSA-87+Ed448":
			a.Config.DefaultAlgo = int(packet.PubKeyAlgoMldsa87Ed448)
		case "Ed25519":
			a.Config.DefaultAlgo = int(packet.PubKeyAlgoEd25519)
		}

		if err := a.saveConfig(); err != nil {
			dialog.ShowError(err, a.Window)
			return
		}

		// 重新初始化 managers（FileManager 无状态，无需重建）
		a.KeyManager = service.NewKeyManager(a.Config.DataDir)
		a.TextManager = service.NewTextManager(a.Config.Editor)
		a.PGPOps = service.NewPGPOps(a.KeyManager)

		statusLabel.SetText("设置已保存")
	})

	content := container.NewVBox(
		widget.NewLabel("数据目录："),
		dirRow,
		widget.NewLabel("外部编辑器："),
		editorSelect,
		customEditorEntry,
		widget.NewLabel("默认算法："),
		algoSelect,
		widget.NewLabel("默认密钥："),
		defaultKeyLabel,
		saveBtn,
		statusLabel,
	)

	return container.NewScroll(content)
}
