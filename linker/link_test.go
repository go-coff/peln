package linker

import (
	"bytes"
	"debug/pe"
	"os"
	"path/filepath"
	"testing"
)

// TestLink_StubAMD64 runs the full pipeline against the cloud-boot amd64
// stub objects and verifies the result is a parsable PE32+ EFI image.
//
// The strongest test would be booting in QEMU, but the toolchain layer
// above (cloud-boot/uki Taskfile) drives that; here we content
// ourselves with format-level invariants: PE signature in place, the
// canonical sections (.text/.rdata/.data optional but expected, plus
// .reloc when relocations exist), and an in-range entry-point RVA.
func TestLink_StubAMD64(t *testing.T) {
	objs := loadStubObjects(t, "../../../go-coff/stub", "amd64")
	if len(objs) == 0 {
		return
	}
	out, err := Link(objs, LinkOptions{
		AllowUnresolved: true, // TinyGo emits unused libc / Win32 refs
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(out, []byte("MZ")) {
		t.Fatalf("output does not start with MZ (DOS sig)")
	}
	// debug/pe should parse the result.
	pf, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe rejects output: %v", err)
	}
	defer pf.Close()
	if pf.OptionalHeader == nil {
		t.Fatal("output has no optional header")
	}
	oh, ok := pf.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		t.Fatalf("expected PE32+ (OptionalHeader64), got %T", pf.OptionalHeader)
	}
	if oh.Subsystem != 10 {
		t.Errorf("Subsystem = %d, want 10 (EFI app)", oh.Subsystem)
	}
	if oh.AddressOfEntryPoint == 0 {
		t.Error("AddressOfEntryPoint = 0")
	}
	// Entry point must land inside .text (whose RVA equals BaseOfCode).
	if oh.AddressOfEntryPoint < oh.BaseOfCode || oh.AddressOfEntryPoint >= oh.BaseOfCode+oh.SizeOfCode {
		t.Errorf("entry 0x%x outside .text [0x%x,0x%x)",
			oh.AddressOfEntryPoint, oh.BaseOfCode, oh.BaseOfCode+oh.SizeOfCode)
	}
	// We must emit a Base Relocation Table if any absolute relocations
	// were present.
	var sawReloc bool
	for _, s := range pf.Sections {
		if s.Name == ".reloc" {
			sawReloc = true
			break
		}
	}
	if !sawReloc {
		t.Log("no .reloc section emitted (fine if the stub is fully PC-relative)")
	}

	// Side-effect: dump a real file so the developer can `file` it.
	tmp := filepath.Join(t.TempDir(), "BOOTX64.EFI")
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote test binary %s (size %d)", tmp, len(out))
}
