package gui

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	v2 "github.com/ProtonMail/go-crypto/openpgp/v2"
	"latticeguard/internal/service"
)

func (a *App) makeTextTab() fyne.CanvasObject {
	modeSelect := widget.NewSelect([]string{"加密", "解密", "签名", "验证"}, nil)
	modeSelect.SetSelected("加密")

	inputEntry := widget.NewMultiLineEntry()
	inputEntry.SetPlaceHolder("在此输入或粘贴文本...")
	inputEntry.Wrapping = fyne.TextWrapWord

	// 加载所有可用密钥作为接收者
	keys, err := a.KeyManager.ListKeys()
	if err != nil {
		dialog.ShowError(fmt.Errorf("加载密钥列表失败: %w", err), a.Window)
	}
	var recipientOptions []string
	var recipientFPs []string
	for _, k := range keys.MyKeys {
		recipientOptions = append(recipientOptions, "[我的] "+k.UserID+" ("+k.Algorithm+")")
		recipientFPs = append(recipientFPs, k.Fingerprint)
	}
	for _, k := range keys.ImportedKeys {
		recipientOptions = append(recipientOptions, "[导入] "+k.UserID+" ("+k.Algorithm+")")
		recipientFPs = append(recipientFPs, k.Fingerprint)
	}
	recipientCheck := widget.NewCheckGroup(recipientOptions, nil)
	recipientContainer := container.NewVBox(widget.NewLabel("选择接收者："), recipientCheck)

	var signerOptions []string
	var signerFPs []string
	signerOptions = append(signerOptions, "不签名")
	signerFPs = append(signerFPs, "")
	for _, k := range keys.MyKeys {
		signerOptions = append(signerOptions, k.UserID+" ("+k.Algorithm+")")
		signerFPs = append(signerFPs, k.Fingerprint)
	}
	signerSelect := widget.NewSelect(signerOptions, nil)
	signerSelect.SetSelected("不签名")
	signerContainer := container.NewVBox(widget.NewLabel("签名者（同时签名）："), signerSelect)
	signerContainer.Hide()

	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("输入私钥密码（如无密码则留空）")
	passContainer := container.NewVBox(widget.NewLabel("私钥密码："), passEntry)
	passContainer.Hide()

	resultEntry := widget.NewMultiLineEntry()
	resultEntry.SetPlaceHolder("结果将显示在这里...")
	resultEntry.Wrapping = fyne.TextWrapWord
	resultEntry.Disable()

	execBtn := widget.NewButton("开始", func() {
		mode := modeSelect.Selected
		text := inputEntry.Text

		if text == "" {
			dialog.ShowError(fmt.Errorf("请输入文本"), a.Window)
			return
		}

		keys, _ := a.KeyManager.ListKeys()

		switch mode {
		case "加密":
			var recipients []*v2.Entity
			selectedFPs := make(map[string]bool)
			for _, label := range recipientCheck.Selected {
				for i, opt := range recipientOptions {
					if opt == label {
						selectedFPs[recipientFPs[i]] = true
						break
					}
				}
			}
			for fp := range selectedFPs {
				entity, err := a.PGPOps.LoadEntity(fp, false)
				if err != nil {
					dialog.ShowError(fmt.Errorf("加载证书失败: %w", err), a.Window)
					return
				}
				recipients = append(recipients, entity)
			}
			if len(recipients) == 0 {
				dialog.ShowError(fmt.Errorf("请至少选择一个接收者"), a.Window)
				return
			}
			var signer *v2.Entity
			if signerSelect.SelectedIndex() > 0 {
				signerFP := signerFPs[signerSelect.SelectedIndex()]
				entity, err := a.PGPOps.LoadEntity(signerFP, true)
				if err != nil {
					dialog.ShowError(fmt.Errorf("加载签名证书失败: %w", err), a.Window)
					return
				}
				if entity.PrivateKey.Encrypted {
					passphrase := passEntry.Text
					if passphrase == "" {
						dialog.ShowError(fmt.Errorf("签名证书已加密，请输入密码"), a.Window)
						return
					}
					if err := entity.PrivateKey.Decrypt([]byte(passphrase)); err != nil {
						dialog.ShowError(fmt.Errorf("解密签名证书失败: %w", err), a.Window)
						return
					}
				}
				signer = entity
			}
			result, err := a.PGPOps.EncryptText(text, recipients, signer)
			if err != nil {
				dialog.ShowError(err, a.Window)
				return
			}
			resultEntry.SetText(result)
			resultEntry.Enable()

		case "解密":
			keyring := a.PGPOps.BuildKeyring(keys.MyKeys, true)
			if len(keyring) == 0 {
				dialog.ShowError(fmt.Errorf("没有可用的私钥"), a.Window)
				return
			}
			passphrase := passEntry.Text
			result, sigInfo, err := a.PGPOps.DecryptText(text, passphrase, keyring)
			if err != nil {
				dialog.ShowError(err, a.Window)
				return
			}
			var sigText string
			if sigInfo.IsSigned {
				if sigInfo.Valid {
					sigText = fmt.Sprintf("\n\n[签名验证成功] 签名者指纹: %s", sigInfo.SignerFingerprint)
				} else {
					sigText = "\n\n[签名验证失败] 消息已被签名但签名无效或来自未知签名者"
				}
			} else {
				sigText = "\n\n[消息未签名]"
			}
			resultEntry.SetText(result + sigText)
			resultEntry.Enable()

		case "签名":
			var signer *v2.Entity
			if signerSelect.SelectedIndex() > 0 {
				signerFP := signerFPs[signerSelect.SelectedIndex()]
				entity, err := a.PGPOps.LoadEntity(signerFP, true)
				if err != nil {
					dialog.ShowError(fmt.Errorf("加载签名证书失败: %w", err), a.Window)
					return
				}
				if entity.PrivateKey.Encrypted {
					passphrase := passEntry.Text
					if passphrase == "" {
						dialog.ShowError(fmt.Errorf("签名证书已加密，请输入密码"), a.Window)
						return
					}
					if err := entity.PrivateKey.Decrypt([]byte(passphrase)); err != nil {
						dialog.ShowError(fmt.Errorf("解密签名证书失败: %w", err), a.Window)
						return
					}
				}
				signer = entity
			} else {
				var err error
				signer, err = a.PGPOps.GetDefaultEntity(keys, a.Config.DefaultKey)
				if err != nil {
					dialog.ShowError(err, a.Window)
					return
				}
			}
			result, err := a.PGPOps.SignText(text, signer)
			if err != nil {
				dialog.ShowError(err, a.Window)
				return
			}
			resultEntry.SetText(result)
			resultEntry.Enable()

		case "验证":
			allKeys := append(keys.MyKeys, keys.ImportedKeys...)
			keyring := a.PGPOps.BuildKeyring(allKeys, false)
			if len(keyring) == 0 {
				dialog.ShowError(fmt.Errorf("没有可用的公钥"), a.Window)
				return
			}
			result, err := a.PGPOps.VerifyText(text, keyring)
			if err != nil {
				dialog.ShowError(err, a.Window)
				return
			}
			resultEntry.SetText(result)
			resultEntry.Enable()
		}
	})

	copyBtn := widget.NewButton("复制结果", func() {
		if resultEntry.Text == "" {
			return
		}
		a.Window.Clipboard().SetContent(resultEntry.Text)
		dialog.ShowInformation("成功", "已复制到剪贴板", a.Window)
	})

	editBtn := widget.NewButton("外部编辑器", func() {
		editor := a.Config.Editor
		go func() {
			tm := service.NewTextManager(editor)
			result, err := tm.EditWithExternalEditor(inputEntry.Text)
			fyne.Do(func() {
				if err != nil {
					dialog.ShowError(err, a.Window)
				} else {
					inputEntry.SetText(result)
				}
			})
		}()
	})

	clearBtn := widget.NewButton("清空", func() {
		inputEntry.SetText("")
		resultEntry.SetText("")
		resultEntry.Disable()
	})

	modeSelect.OnChanged = func(mode string) {
		switch mode {
		case "加密":
			recipientContainer.Show()
			signerContainer.Show()
			passContainer.Hide()
		case "解密":
			recipientContainer.Hide()
			signerContainer.Hide()
			passContainer.Show()
		case "签名":
			recipientContainer.Hide()
			signerContainer.Show()
			passContainer.Hide()
		case "验证":
			recipientContainer.Hide()
			signerContainer.Hide()
			passContainer.Hide()
		}
	}
	modeSelect.OnChanged("加密")

	signerSelect.OnChanged = func(_ string) {
		if signerSelect.SelectedIndex() > 0 {
			passContainer.Show()
		} else {
			passContainer.Hide()
		}
	}

	content := container.NewVBox(
		widget.NewLabel("操作模式："),
		modeSelect,
		container.NewHBox(execBtn, copyBtn, editBtn, clearBtn),
		widget.NewLabel("输入文本："),
		inputEntry,
		recipientContainer,
		signerContainer,
		passContainer,
		widget.NewLabel("结果："),
		resultEntry,
	)

	return container.NewScroll(content)
}
