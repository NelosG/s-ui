package cronjob

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendLineRotates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	for i := 0; i < 3; i++ {
		if err := appendLine(path, []byte(`{"n":1}`), 20); err != nil {
			t.Fatal(err)
		}
	}
	current, _ := os.ReadFile(path)
	old, _ := os.ReadFile(path + ".1")
	if strings.Count(string(current), "\n") != 1 || strings.Count(string(old), "\n") != 2 {
		t.Fatalf("expected the third line to start a new file: current %q, old %q", current, old)
	}
}
