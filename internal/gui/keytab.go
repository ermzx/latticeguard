package gui

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"latticeguard/internal/model"
)

func formatFingerprint(fp string) string {
	if len(fp) <= 8 {
		return fp
	}
	var parts []string
	for i := 0; i < len(fp); i += 4 {
		end := i + 4
		if end > len(fp) {
			end = len(fp)
		}
		parts = append(parts, fp[i:end])
	}
	return strings.Join(parts, " ")
}

func (a *App) makeKeyTab() fyne.CanvasObject {
	keys, err := a.KeyManager.ListKeys()
	if err != nil {
		dialog.ShowError(fmt.Errorf("加载密钥列表失败: %w", err), a.Window)
	}
	allKeys := append(keys.MyKeys, keys.ImportedKeys...)
	allKeysPtr := &allKeys

	detailLabel := widget.NewLabel("请选择密钥查看详情")
	detailLabel.Wrapping = fyne.TextWrapWord

	var list *widget.List
	list = widget.NewList(
		func() int { return len(*allKeysPtr) },
		func() fyne.CanvasObject {
			return widget.NewLabel("template")
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			if id < 0 || id >= len(*allKeysPtr) {
				return
			}
			label := item.(*widget.Label)
			k := (*allKeysPtr)[id]
			prefix := "[我的] "
			if !k.HasPrivate {
				prefix = "[导入] "
			}
			label.SetText(prefix + k.UserID + " (" + k.Algorithm + ")")
		},
	)

	updateDetail := func(id widget.ListItemID) {
		if id < 0 || id >= len(*allKeysPtr) {
			detailLabel.SetText("请选择密钥查看详情")
			return
		}
		k := (*allKeysPtr)[id]
		defaultMark := ""
		if k.Fingerprint == a.Config.DefaultKey {
			defaultMark = " [默认]"
		}
		expiryText := "(永不)"
		if k.Expires != nil {
			expiryText = k.Expires.Format("2006-01-02 15:04:05")
		}
		text := fmt.Sprintf(
			"用户ID: %s%s\n指纹: %s\n算法: %s\n子密钥: %s\n创建时间: %s\n过期时间: %s\n",
			k.UserID,
			defaultMark,
			formatFingerprint(k.Fingerprint),
			k.Algorithm,
			k.SubkeyAlgo,
			k.Created.Format("2006-01-02 15:04:05"),
			expiryText,
		)
		detailLabel.SetText(text)
	}

	selectedID := widget.ListItemID(-1)
	list.OnSelected = func(id widget.ListItemID) {
		selectedID = id
		updateDetail(id)
	}

	refreshList := func() {
		keys, _ := a.KeyManager.ListKeys()
		*allKeysPtr = append(keys.MyKeys, keys.ImportedKeys...)
		list.Refresh()
		list.UnselectAll()
		selectedID = -1
		detailLabel.SetText("请选择密钥查看详情")
	}

	genBtn := widget.NewButton("生成新密钥", func() {
		a.showGenerateKeyDialog(refreshList)
	})

	importBtn := widget.NewButton("导入", func() {
		a.showImportKeyDialog(refreshList)
	})

	exportBtn := widget.NewButton("导出", func() {
		if selectedID < 0 || int(selectedID) >= len(*allKeysPtr) {
			dialog.ShowInformation("提示", "请先选择一个密钥", a.Window)
			return
		}
		k := (*allKeysPtr)[selectedID]
		a.showExportKeyDialog(k)
	})

	delBtn := widget.NewButton("删除", func() {
		if selectedID < 0 || int(selectedID) >= len(*allKeysPtr) {
			dialog.ShowInformation("提示", "请先选择一个密钥", a.Window)
			return
		}
		k := (*allKeysPtr)[selectedID]
		dialog.NewConfirm("确认删除", "确定要删除密钥 "+k.UserID+" 吗？", func(confirmed bool) {
			if !confirmed {
				return
			}
			privPath := filepath.Join(a.KeyManager.DataDir, "keys", k.Fingerprint+"_priv.asc")
			pubPath := filepath.Join(a.KeyManager.DataDir, "keys", "pub", k.Fingerprint+"_pub.asc")
			var errs []string
			if err := os.Remove(privPath); err != nil && !os.IsNotExist(err) {
				errs = append(errs, "删除私钥失败: "+err.Error())
			}
			if err := os.Remove(pubPath); err != nil && !os.IsNotExist(err) {
				errs = append(errs, "删除公钥失败: "+err.Error())
			}
			if a.Config.DefaultKey == k.Fingerprint {
				a.Config.DefaultKey = ""
				if err := a.saveConfig(); err != nil {
					errs = append(errs, "保存配置失败: "+err.Error())
				}
			}
			refreshList()
			if len(errs) > 0 {
				dialog.ShowError(fmt.Errorf("密钥删除部分失败:\n%s", strings.Join(errs, "\n")), a.Window)
			} else {
				dialog.ShowInformation("成功", "密钥已删除", a.Window)
			}
		}, a.Window).Show()
	})

	passBtn := widget.NewButton("修改密码", func() {
		if selectedID < 0 || int(selectedID) >= len(*allKeysPtr) {
			dialog.ShowInformation("提示", "请先选择一个密钥", a.Window)
			return
		}
		k := (*allKeysPtr)[selectedID]
		a.showChangePassphraseDialog(k, refreshList)
	})

	defaultBtn := widget.NewButton("设为默认", func() {
		if selectedID < 0 || int(selectedID) >= len(*allKeysPtr) {
			dialog.ShowInformation("提示", "请先选择一个密钥", a.Window)
			return
		}
		k := (*allKeysPtr)[selectedID]
		a.Config.DefaultKey = k.Fingerprint
		if err := a.saveConfig(); err != nil {
			dialog.ShowError(err, a.Window)
			return
		}
		updateDetail(selectedID)
		dialog.ShowInformation("成功", "已设置默认密钥", a.Window)
	})

	a.onKeysChanged = refreshList

	btnBox := container.NewHBox(genBtn, importBtn, exportBtn, delBtn, passBtn, defaultBtn)
	left := container.NewBorder(nil, nil, nil, nil, list)
	right := container.NewBorder(nil, btnBox, nil, nil, detailLabel)

	tabContent := container.NewHSplit(left, right)
	return tabContent
}

func (a *App) showGenerateKeyDialog(onSuccess func()) {
	nameEntry := widget.NewEntry()
	nameEntry.SetPlaceHolder("姓名")
	emailEntry := widget.NewEntry()
	emailEntry.SetPlaceHolder("邮箱")
	algoSelect := widget.NewSelect([]string{"ML-DSA-65+Ed25519", "ML-DSA-87+Ed448", "Ed25519"}, nil)
	algoSelect.SetSelected("ML-DSA-65+Ed25519")
	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("密码（可选）")
	confirmEntry := widget.NewPasswordEntry()
	confirmEntry.SetPlaceHolder("确认密码")

	items := []*widget.FormItem{
		widget.NewFormItem("名称", nameEntry),
		widget.NewFormItem("邮箱", emailEntry),
		widget.NewFormItem("算法", algoSelect),
		widget.NewFormItem("密码", passEntry),
		widget.NewFormItem("确认密码", confirmEntry),
	}

	dialog.ShowForm("生成新密钥", "生成", "取消", items, func(ok bool) {
		if !ok {
			return
		}
		if nameEntry.Text == "" || emailEntry.Text == "" {
			dialog.ShowError(fmt.Errorf("名称和邮箱不能为空"), a.Window)
			return
		}
		if passEntry.Text != confirmEntry.Text {
			dialog.ShowError(fmt.Errorf("两次输入的密码不一致"), a.Window)
			return
		}

		var algo packet.PublicKeyAlgorithm
		switch algoSelect.Selected {
		case "ML-DSA-65+Ed25519":
			algo = packet.PubKeyAlgoMldsa65Ed25519
		case "ML-DSA-87+Ed448":
			algo = packet.PubKeyAlgoMldsa87Ed448
		case "Ed25519":
			algo = packet.PubKeyAlgoEd25519
		default:
			algo = packet.PubKeyAlgoMldsa65Ed25519
		}

		entity, err := a.KeyManager.GenerateKey(nameEntry.Text, emailEntry.Text, algo)
		if err != nil {
			dialog.ShowError(err, a.Window)
			return
		}

		var passphrase []byte
		if passEntry.Text != "" {
			passphrase = []byte(passEntry.Text)
		}

		if err := a.KeyManager.SavePrivateKey(entity, passphrase); err != nil {
			dialog.ShowError(err, a.Window)
			return
		}
		if err := a.KeyManager.SavePublicKey(entity); err != nil {
			dialog.ShowError(err, a.Window)
			return
		}

		onSuccess()
		dialog.ShowInformation("成功", "密钥生成成功", a.Window)
	}, a.Window)
}

func (a *App) showImportKeyDialog(onSuccess func()) {
	dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err != nil {
			dialog.ShowError(err, a.Window)
			return
		}
		if reader == nil {
			return
		}
		defer reader.Close()

		data, err := io.ReadAll(reader)
		if err != nil {
			dialog.ShowError(err, a.Window)
			return
		}

		if err := a.importKeyData(data); err != nil {
			dialog.ShowError(err, a.Window)
			return
		}

		onSuccess()
		dialog.ShowInformation("成功", "密钥导入成功", a.Window)
	}, a.Window)
}

func (a *App) showExportKeyDialog(k model.KeyInfo) {
	var srcPath string
	if k.HasPrivate {
		srcPath = filepath.Join(a.KeyManager.DataDir, "keys", k.Fingerprint+"_priv.asc")
	} else {
		srcPath = filepath.Join(a.KeyManager.DataDir, "keys", "pub", k.Fingerprint+"_pub.asc")
	}

	dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil {
			dialog.ShowError(err, a.Window)
			return
		}
		if writer == nil {
			return
		}
		defer writer.Close()

		data, err := os.ReadFile(srcPath)
		if err != nil {
			dialog.ShowError(err, a.Window)
			return
		}
		if _, err := writer.Write(data); err != nil {
			dialog.ShowError(err, a.Window)
			return
		}
		dialog.ShowInformation("成功", "密钥导出成功", a.Window)
	}, a.Window)
}

func (a *App) showChangePassphraseDialog(k model.KeyInfo, onSuccess func()) {
	oldPass := widget.NewPasswordEntry()
	oldPass.SetPlaceHolder("当前密码（无密码则留空）")
	newPass := widget.NewPasswordEntry()
	newPass.SetPlaceHolder("新密码（留空则删除密码）")
	confirmPass := widget.NewPasswordEntry()
	confirmPass.SetPlaceHolder("确认新密码")

	items := []*widget.FormItem{
		widget.NewFormItem("当前密码", oldPass),
		widget.NewFormItem("新密码", newPass),
		widget.NewFormItem("确认密码", confirmPass),
	}

	dialog.ShowForm("修改密码", "确认", "取消", items, func(ok bool) {
		if !ok {
			return
		}
		if newPass.Text != confirmPass.Text {
			dialog.ShowError(fmt.Errorf("两次输入的新密码不一致"), a.Window)
			return
		}

		entity, err := a.PGPOps.LoadEntity(k.Fingerprint, true)
		if err != nil {
			dialog.ShowError(err, a.Window)
			return
		}

		var oldPhrase []byte
		if oldPass.Text != "" {
			oldPhrase = []byte(oldPass.Text)
			if entity.PrivateKey == nil {
				dialog.ShowError(fmt.Errorf("密钥无私钥组件"), a.Window)
				return
			}
			if !entity.PrivateKey.Encrypted {
				dialog.ShowError(fmt.Errorf("此密钥未加密，无需输入当前密码"), a.Window)
				return
			}
			if err := entity.DecryptPrivateKeys(oldPhrase); err != nil {
				dialog.ShowError(fmt.Errorf("当前密码错误: %w", err), a.Window)
				return
			}
		}

		var newPhrase []byte
		if newPass.Text != "" {
			newPhrase = []byte(newPass.Text)
		}

		if entity.PrivateKey == nil {
			dialog.ShowError(fmt.Errorf("密钥无私钥组件"), a.Window)
			return
		}
		if err := entity.EncryptPrivateKeys(newPhrase, nil); err != nil {
			dialog.ShowError(err, a.Window)
			return
		}

		if err := a.KeyManager.SavePrivateKey(entity, newPhrase); err != nil {
			dialog.ShowError(err, a.Window)
			return
		}

		onSuccess()
		dialog.ShowInformation("成功", "密码修改成功", a.Window)
	}, a.Window)
}
