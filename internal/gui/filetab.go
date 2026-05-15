package gui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	v2 "github.com/ProtonMail/go-crypto/openpgp/v2"
)

type fileItem struct {
	name  string
	path  string
	isDir bool
}

func (a *App) makeFileTab() fyne.CanvasObject {
	modeSelect := widget.NewSelect([]string{"加密", "解密", "签名", "验证"}, nil)
	modeSelect.SetSelected("加密")

	inputEntry := widget.NewEntry()
	inputEntry.SetPlaceHolder("输入文件路径")
	inputBtn := widget.NewButton("浏览...", func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
				return
			}
			defer reader.Close()
			inputEntry.SetText(reader.URI().Path())
		}, a.Window)
	})
	inputRow := container.NewBorder(nil, nil, nil, inputBtn, inputEntry)

	outputEntry := widget.NewEntry()
	outputEntry.SetPlaceHolder("输出文件路径（留空则自动生成）")
	outputBtn := widget.NewButton("浏览...", func() {
		dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil || writer == nil {
				return
			}
			defer writer.Close()
			outputEntry.SetText(writer.URI().Path())
		}, a.Window)
	})
	outputRow := container.NewBorder(nil, nil, nil, outputBtn, outputEntry)

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

	resultLabel := widget.NewLabel("")
	resultLabel.Wrapping = fyne.TextWrapWord

	execBtn := widget.NewButton("开始", func() {
		mode := modeSelect.Selected
		inputPath := inputEntry.Text

		if inputPath == "" {
			dialog.ShowError(fmt.Errorf("请选择输入文件"), a.Window)
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
			outPath := outputEntry.Text
			if outPath == "" {
				outPath = a.FileManager.DefaultOutputPath(inputPath, ".asc")
			}
			result, err := a.PGPOps.EncryptFile(inputPath, recipients, signer, a.FileManager)
			if err != nil {
				dialog.ShowError(err, a.Window)
				return
			}
			resultLabel.SetText("加密成功，输出: " + result)

		case "解密":
			keyring := a.PGPOps.BuildKeyring(keys.MyKeys, true)
			if len(keyring) == 0 {
				dialog.ShowError(fmt.Errorf("没有可用的私钥"), a.Window)
				return
			}
			outPath := outputEntry.Text
			if outPath == "" {
				outPath = a.FileManager.DefaultOutputPath(inputPath, ".decrypted")
			}
			passphrase := passEntry.Text
			result, sigInfo, err := a.PGPOps.DecryptFile(inputPath, passphrase, keyring, a.FileManager)
			if err != nil {
				dialog.ShowError(err, a.Window)
				return
			}
			var sigText string
			if sigInfo.IsSigned {
				if sigInfo.Valid {
					sigText = fmt.Sprintf("，签名验证成功 (签名者: %s)", sigInfo.SignerFingerprint)
				} else {
					sigText = "，消息包含签名但签名无效或来自未知签名者"
				}
			} else {
				sigText = "，消息未签名"
			}
			resultLabel.SetText("解密成功，输出: " + result + sigText)

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
			outPath := outputEntry.Text
			if outPath == "" {
				outPath = a.FileManager.DefaultOutputPath(inputPath, ".sig")
			}
			result, err := a.PGPOps.SignFile(inputPath, signer, a.FileManager)
			if err != nil {
				dialog.ShowError(err, a.Window)
				return
			}
			resultLabel.SetText("签名成功，输出: " + result)

		case "验证":
			allKeys := append(keys.MyKeys, keys.ImportedKeys...)
			keyring := a.PGPOps.BuildKeyring(allKeys, false)
			if len(keyring) == 0 {
				dialog.ShowError(fmt.Errorf("没有可用的公钥"), a.Window)
				return
			}
			result, err := a.PGPOps.VerifyFile(inputPath, keyring, a.FileManager)
			if err != nil {
				dialog.ShowError(err, a.Window)
				return
			}
			resultLabel.SetText(result)
		}
	})

	modeSelect.OnChanged = func(mode string) {
		switch mode {
		case "加密":
			recipientContainer.Show()
			signerContainer.Show()
			passContainer.Hide()
			outputEntry.SetPlaceHolder("输出文件路径（留空则自动生成 .asc）")
		case "解密":
			recipientContainer.Hide()
			signerContainer.Hide()
			passContainer.Show()
			outputEntry.SetPlaceHolder("输出文件路径（留空则自动生成 .decrypted）")
		case "签名":
			recipientContainer.Hide()
			signerContainer.Show()
			passContainer.Hide()
			outputEntry.SetPlaceHolder("输出文件路径（留空则自动生成 .sig）")
		case "验证":
			recipientContainer.Hide()
			signerContainer.Hide()
			passContainer.Hide()
			outputEntry.SetPlaceHolder("(验证不需要输出文件)")
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

	// --- File browser with search ---
	var fileItems []fileItem
	currentDirLabel := widget.NewLabel("")
	fileList := widget.NewList(
		func() int { return len(fileItems) },
		func() fyne.CanvasObject {
			return widget.NewLabel("template")
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			if id < 0 || id >= len(fileItems) {
				return
			}
			label := item.(*widget.Label)
			fi := fileItems[id]
			if fi.isDir {
				label.SetText("📁 " + fi.name)
			} else {
				label.SetText("📄 " + fi.name)
			}
		},
	)

	fileList.OnSelected = func(id widget.ListItemID) {
		if id < 0 || id >= len(fileItems) {
			return
		}
		fi := fileItems[id]
		if fi.isDir {
			inputEntry.SetText("")
		} else {
			inputEntry.SetText(fi.path)
		}
		fileList.UnselectAll()
	}

	searchEntry := widget.NewEntry()
	searchEntry.SetPlaceHolder("搜索文件...")

	refreshFileList := func(dir string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			fileItems = nil
			fileList.Refresh()
			currentDirLabel.SetText(dir + "（无法读取）")
			return
		}
		query := strings.ToLower(searchEntry.Text)
		fileItems = nil
		for _, entry := range entries {
			name := entry.Name()
			if query != "" && !strings.Contains(strings.ToLower(name), query) {
				continue
			}
			fileItems = append(fileItems, fileItem{
				name:  name,
				path:  filepath.Join(dir, name),
				isDir: entry.IsDir(),
			})
		}
		sort.Slice(fileItems, func(i, j int) bool {
			if fileItems[i].isDir != fileItems[j].isDir {
				return fileItems[i].isDir
			}
			return strings.ToLower(fileItems[i].name) < strings.ToLower(fileItems[j].name)
		})
		fileList.Refresh()
	}

	searchEntry.OnChanged = func(_ string) {
		dir := filepath.Dir(inputEntry.Text)
		if dir == "." {
			dir, _ = os.Getwd()
		}
		refreshFileList(dir)
	}

	upBtn := widget.NewButton("上级目录", func() {
		currentDir := currentDirLabel.Text
		if currentDir == "" {
			return
		}
		parent := filepath.Dir(currentDir)
		currentDirLabel.SetText(parent)
		refreshFileList(parent)
	})

	refreshBtn := widget.NewButton("刷新", func() {
		dir := currentDirLabel.Text
		if dir == "" {
			dir, _ = os.Getwd()
			currentDirLabel.SetText(dir)
		}
		refreshFileList(dir)
	})

	setDir := func(path string) {
		dir := filepath.Dir(path)
		if dir == "." {
			dir, _ = os.Getwd()
		}
		currentDirLabel.SetText(dir)
		refreshFileList(dir)
	}

	inputEntry.OnChanged = func(path string) {
		if path != "" {
			setDir(path)
		}
	}

	dir, _ := os.Getwd()
	currentDirLabel.SetText(dir)
	refreshFileList(dir)

	fileBrowser := container.NewBorder(
		container.NewVBox(
			widget.NewLabel("文件浏览器"),
			searchEntry,
			container.NewHBox(upBtn, refreshBtn),
			currentDirLabel,
		),
		nil, nil, nil,
		fileList,
	)
	fileBrowserWrapper := container.NewMax(fileBrowser)

	// Right side: operation controls
	controls := container.NewVBox(
		widget.NewLabel("操作模式："),
		modeSelect,
		widget.NewLabel("输入文件："),
		inputRow,
		widget.NewLabel("输出文件："),
		outputRow,
		recipientContainer,
		signerContainer,
		passContainer,
		execBtn,
		widget.NewLabel("结果："),
		resultLabel,
	)

	split := container.NewHSplit(fileBrowserWrapper, container.NewScroll(controls))
	split.SetOffset(0.35)

	return split
}
