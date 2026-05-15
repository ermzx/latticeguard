package service

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileManager_ReadWrite(t *testing.T) {
	fm := NewFileManager()
	dir := t.TempDir()

	path := filepath.Join(dir, "test.txt")
	data := []byte("hello world")
	if err := fm.WriteFile(path, data); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	read, err := fm.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(read) != string(data) {
		t.Fatalf("ReadFile content mismatch: got %q, want %q", string(read), string(data))
	}

	fi, err := fm.FileInfo(path)
	if err != nil {
		t.Fatalf("FileInfo failed: %v", err)
	}
	if fi.Size() != int64(len(data)) {
		t.Fatalf("FileInfo size mismatch: got %d, want %d", fi.Size(), len(data))
	}
}

func TestFileManager_DefaultOutputPath(t *testing.T) {
	fm := NewFileManager()

	tests := []struct {
		input  string
		suffix string
		want   string
	}{
		{"/tmp/file.txt", ".asc", "/tmp/file.asc"},
		{"/tmp/file.txt", ".sig", "/tmp/file.sig"},
		{"/tmp/file.txt", ".decrypted", "/tmp/file.decrypted"},
		{"/tmp/file.tar.gz", ".asc", "/tmp/file.tar.asc"},
		{"/tmp/noext", ".sig", "/tmp/noext.sig"},
	}

	for _, tt := range tests {
		got := fm.DefaultOutputPath(tt.input, tt.suffix)
		if got != tt.want {
			t.Errorf("DefaultOutputPath(%q, %q) = %q, want %q", tt.input, tt.suffix, got, tt.want)
		}
	}
}

func TestFileManager_ReadNonExistent(t *testing.T) {
	fm := NewFileManager()
	_, err := fm.ReadFile("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
	if !os.IsNotExist(err) {
		t.Fatalf("expected IsNotExist error, got %v", err)
	}
}

func TestFileManager_FileInfoNonExistent(t *testing.T) {
	fm := NewFileManager()
	_, err := fm.FileInfo("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}
