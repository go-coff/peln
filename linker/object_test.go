package linker

import (
	"bytes"
	"os"
	"testing"
)

// TestReadObject_Local parses one of the COFF .o files our cloud-boot
// pipeline already produces (TinyGo arm64 output) if it happens to be
// present, and exercises the basic shape assertions. It is t.Skip()'d on
// hosts where the file isn't laying around — this is a developer smoke
// test, not a CI fixture (a checked-in COFF fixture is a follow-up).
func TestReadObject_Local(t *testing.T) {
	const path = "../../../go-coff/stub/main-arm64.o"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("no local stub object at %s — run `task link-arm64` in go-coff/stub", path)
	}
	o, err := ReadObject(bytes.NewReader(data), path)
	if err != nil {
		t.Fatal(err)
	}
	// arm64 COFF: IMAGE_FILE_MACHINE_ARM64 == 0xaa64
	if o.Machine != 0xaa64 {
		t.Errorf("Machine = 0x%x, want 0xaa64", o.Machine)
	}
	if len(o.Sections) == 0 {
		t.Error("no sections parsed")
	}
	// Every TinyGo-emitted UEFI .o defines _start (the PE entry symbol).
	var sawStart bool
	for _, s := range o.Symbols {
		if s.Name == "_start" && s.Kind == SymDefined {
			sawStart = true
			break
		}
	}
	if !sawStart {
		t.Error("symbol _start not found / not defined")
	}
}

func TestReadObject_RejectsLinkedPE(t *testing.T) {
	const path = "../../../go-coff/stub/BOOTAA64.EFI"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skip("no local stub binary")
	}
	if _, err := ReadObject(bytes.NewReader(data), path); err == nil {
		t.Fatal("ReadObject accepted a linked PE; should have rejected")
	}
}
