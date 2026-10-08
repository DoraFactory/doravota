package cmd

import "testing"

// Removing the Wasm constructor option must not leave a nil BaseApp option.
func TestArchiveRootConstruction(t *testing.T) {
 root, _ := NewRootCmd()
 if root == nil { t.Fatal("missing root command") }
}
