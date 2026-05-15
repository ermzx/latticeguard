package service

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestNewTextManager(t *testing.T) {
	tm := NewTextManager("vim")
	if tm.Editor != "vim" {
		t.Fatalf("expected editor 'vim', got %q", tm.Editor)
	}
}

func TestNewTextManager_Default(t *testing.T) {
	tm := NewTextManager("")
	if tm.Editor != "nano" {
		t.Fatalf("expected default editor 'nano', got %q", tm.Editor)
	}
}

func TestEditWithExternalEditor(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping external editor test in short mode")
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "cat"
	}
	if _, err := exec.LookPath(editor); err != nil {
		t.Skipf("editor %q not available", editor)
	}

	tm := NewTextManager(editor)
	// Using "cat" as editor should echo input back unchanged
	result, err := tm.EditWithExternalEditor("test content")
	if err != nil {
		t.Fatalf("EditWithExternalEditor failed: %v", err)
	}
	if result != "test content" {
		t.Fatalf("expected 'test content', got %q", result)
	}
}

func TestEditWithExternalEditor_CreatesTempFile(t *testing.T) {
	tm := NewTextManager("cat")
	_, err := tm.EditWithExternalEditor("hello")
	if err != nil {
		t.Fatalf("EditWithExternalEditor failed: %v", err)
	}

	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if matched, _ := filepath.Match("latticeguard-*.txt", entry.Name()); matched {
			t.Fatalf("temp file %s was not cleaned up", entry.Name())
		}
	}
}
