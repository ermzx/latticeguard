package service

import (
	"os"
	"os/exec"
)

type TextManager struct {
	Editor string
}

func NewTextManager(editor string) *TextManager {
	if editor == "" {
		editor = "nano"
	}
	return &TextManager{Editor: editor}
}

// EditWithExternalEditor 调用外部编辑器编辑文本
// 1. CreateTemp 创建临时文件，前缀 "latticeguard-*.txt"
// 2. 写入初始文本，关闭文件
// 3. os.Chmod(tmpPath, 0600)
// 4. exec.Command(editor, tmpPath)，绑定 Stdin/Stdout/Stderr
// 5. cmd.Run() 等待退出
// 6. os.ReadFile 读取编辑后内容
// 7. defer os.Remove(tmpPath)
func (tm *TextManager) EditWithExternalEditor(initialText string) (string, error) {
	tmpFile, err := os.CreateTemp("", "latticeguard-*.txt")
	if err != nil {
		return "", err
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.WriteString(initialText); err != nil {
		tmpFile.Close()
		return "", err
	}
	if err := tmpFile.Close(); err != nil {
		return "", err
	}

	if err := os.Chmod(tmpPath, 0600); err != nil {
		return "", err
	}

	cmd := exec.Command(tm.Editor, tmpPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", err
	}

	content, err := os.ReadFile(tmpPath)
	if err != nil {
		return "", err
	}

	return string(content), nil
}
