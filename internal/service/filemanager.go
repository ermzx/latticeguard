package service

import (
	"os"
	"path/filepath"
)

type FileManager struct{}

func NewFileManager() *FileManager { return &FileManager{} }
func (fm *FileManager) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
func (fm *FileManager) WriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}
func (fm *FileManager) FileInfo(path string) (os.FileInfo, error) {
	return os.Stat(path)
}
func (fm *FileManager) DefaultOutputPath(inputPath, suffix string) string {
	base := inputPath
	if ext := filepath.Ext(inputPath); ext != "" {
		base = inputPath[:len(inputPath)-len(ext)]
	}
	return base + suffix
}
