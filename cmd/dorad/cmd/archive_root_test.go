package cmd

import (
	"os"
	"os/exec"
	"testing"
)

// CLI construction seals the global SDK config. Isolate it from tests which
// intentionally configure that singleton, as the actual executable does.
func TestArchiveRootConstruction(t *testing.T) {
	if os.Getenv("VOTA_ARCHIVE_ROOT_CHILD") == "1" {
		root, _ := NewRootCmd()
		if root == nil {
			t.Fatal("missing root command")
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestArchiveRootConstruction$")
	cmd.Env = append(os.Environ(), "VOTA_ARCHIVE_ROOT_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("root construction failed: %v\n%s", err, out)
	}
}
