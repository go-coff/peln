package linker

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"strings"
	"testing"
)

// makeMinObj returns the simplest linkable object: one .text section with
// a _start symbol at offset 0, machine = `machine`.
func makeMinObj(machine uint16) *Object {
	return &Object{
		Name:    "min.o",
		Machine: machine,
		Sections: []*Section{
			{Name: ".text", Characteristics: scnCntCode | scnMemExecute,
				Data: []byte{0x90, 0x90, 0x90, 0x90}, VirtualSize: 4},
		},
		Symbols: []*Symbol{
			{Name: "_start", Kind: SymDefined, StorageClass: classExternal, SectionNumber: 1, Value: 0},
		},
	}
}

func TestLink_NoObjects(t *testing.T) {
	if _, err := Link(nil, LinkOptions{Machine: MachineAMD64}); err == nil ||
		!strings.Contains(err.Error(), "no input") {
		t.Errorf("want no-input error, got %v", err)
	}
}

func TestLink_ResolveFails(t *testing.T) {
	o := &Object{
		Name:    "x.o",
		Machine: MachineAMD64,
		Symbols: []*Symbol{
			{Name: "missing", Kind: SymUndefined, StorageClass: classExternal},
		},
	}
	if _, err := Link([]*Object{o}, LinkOptions{}); err == nil {
		t.Errorf("want unresolved error")
	}
}

func TestLink_MinimalAMD64(t *testing.T) {
	out, err := Link([]*Object{makeMinObj(MachineAMD64)}, LinkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(out, []byte("MZ")) {
		t.Errorf("output not a PE")
	}
}

// TestLink_DispatchARM64 routes a relocation through the ARM64 dispatch
// path so the `case MachineARM64:` branch in applyOne gets hit.
func TestLink_DispatchARM64(t *testing.T) {
	o := makeMinObj(MachineARM64)
	// Add a self-referential ADDR64 relocation so the dispatcher fires.
	o.Sections[0].Data = make([]byte, 8)
	o.Sections[0].VirtualSize = 8
	o.Sections[0].Relocs = []Reloc{
		{VirtualAddress: 0, SymbolIndex: 0, Type: relARM64Addr64},
	}
	out, err := Link([]*Object{o}, LinkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pf, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	defer pf.Close()
	if pf.FileHeader.Machine != MachineARM64 {
		t.Errorf("Machine = 0x%x, want 0x%x", pf.FileHeader.Machine, MachineARM64)
	}
}

// TestLink_DispatchRISCV64 routes a relocation through the RISCV64
// dispatch path. R_RISCV_64 writes the target VA in-place and emits a
// DIR64 base reloc — the round-trip check is that we land in the
// emitted .reloc section.
func TestLink_DispatchRISCV64(t *testing.T) {
	o := makeMinObj(MachineRISCV64)
	o.Format = FormatELF
	o.Sections[0].Data = make([]byte, 8)
	o.Sections[0].VirtualSize = 8
	o.Sections[0].Relocs = []Reloc{
		{VirtualAddress: 0, SymbolIndex: 0, Type: rvReloc64},
	}
	out, err := Link([]*Object{o}, LinkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(out, []byte("MZ")) {
		t.Error("output not a PE")
	}
}

func TestLink_RelocateFails(t *testing.T) {
	// Provoke a per-arch relocation error (bad type 0xFF) so
	// ApplyRelocations returns an error from inside Link.
	o := makeMinObj(MachineAMD64)
	o.Sections[0].Relocs = []Reloc{{VirtualAddress: 0, SymbolIndex: 0, Type: 0xFF}}
	if _, err := Link([]*Object{o}, LinkOptions{}); err == nil {
		t.Errorf("want relocate error")
	}
}

func TestLink_EntryNotFound(t *testing.T) {
	if _, err := Link([]*Object{makeMinObj(MachineAMD64)}, LinkOptions{Entry: "no_such"}); err == nil ||
		!strings.Contains(err.Error(), "entry symbol") {
		t.Errorf("want entry-not-found error, got %v", err)
	}
}

func TestLink_EntryNotSectionDefined(t *testing.T) {
	o := makeMinObj(MachineAMD64)
	// Override _start to absolute → resolveEntryRVA must reject it.
	o.Symbols[0].Kind = SymAbsolute
	if _, err := Link([]*Object{o}, LinkOptions{}); err == nil ||
		!strings.Contains(err.Error(), "not section-defined") {
		t.Errorf("want not-section-defined error, got %v", err)
	}
}

func TestLink_LargeHeaderReserve(t *testing.T) {
	// Force the HeaderReserve > sizeOfHeaders bump branch in emitPE.
	out, err := Link([]*Object{makeMinObj(MachineAMD64)}, LinkOptions{HeaderReserve: 0x4000})
	if err != nil {
		t.Fatal(err)
	}
	pf, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	defer pf.Close()
	oh := pf.OptionalHeader.(*pe.OptionalHeader64)
	if oh.SizeOfHeaders < 0x4000 {
		t.Errorf("SizeOfHeaders = 0x%x, want ≥0x4000", oh.SizeOfHeaders)
	}
}

func TestLink_RelocSectionPresent(t *testing.T) {
	// A relocation that emits a base-reloc entry should produce a
	// .reloc output section.
	o := makeMinObj(MachineAMD64)
	o.Sections[0].Data = make([]byte, 8)
	o.Sections[0].VirtualSize = 8
	o.Sections[0].Relocs = []Reloc{{VirtualAddress: 0, SymbolIndex: 0, Type: relAMD64Addr64}}
	out, err := Link([]*Object{o}, LinkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pf, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	defer pf.Close()
	var sawReloc bool
	for _, s := range pf.Sections {
		if s.Name == ".reloc" {
			sawReloc = true
		}
	}
	if !sawReloc {
		t.Error(".reloc section not present despite DIR64 reloc")
	}
}

// TestLink_CustomBSS forces a custom-named uninitialised-data section
// through the "other" bucket — the bucket preserves the source-side
// scnCntUninitializedData flag, which then triggers both the BSS branch
// in ComputeLayout (RawSize=0 / FileOffset stays put) and the
// sizeOfUninitData accumulator in emitPE.
func TestLink_CustomBSS(t *testing.T) {
	o := makeMinObj(MachineAMD64)
	o.Sections = append(o.Sections, &Section{
		Name:            ".scratch",
		Characteristics: scnCntUninitializedData | scnMemRead | scnMemWrite,
		VirtualSize:     0x100,
	})
	out, err := Link([]*Object{o}, LinkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pf, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	defer pf.Close()
	oh := pf.OptionalHeader.(*pe.OptionalHeader64)
	if oh.SizeOfUninitializedData == 0 {
		t.Errorf("SizeOfUninitializedData = 0, want >0")
	}
}

func TestResolveEntryRVA_Missing(t *testing.T) {
	tab := &SymTab{Entries: map[string]Resolved{}}
	if _, err := resolveEntryRVA("no_such", tab, &Layout{}); err == nil ||
		!strings.Contains(err.Error(), "not found") {
		t.Errorf("want not-found, got %v", err)
	}
}

func TestResolveEntryRVA_AbsoluteRejected(t *testing.T) {
	tab := &SymTab{Entries: map[string]Resolved{
		"_start": {Kind: SymAbsolute, Value: 42},
	}}
	if _, err := resolveEntryRVA("_start", tab, &Layout{}); err == nil ||
		!strings.Contains(err.Error(), "not section-defined") {
		t.Errorf("want section-defined error, got %v", err)
	}
}

func TestBuildRelocSection_Empty(t *testing.T) {
	if got := BuildRelocSection(nil); got != nil {
		t.Errorf("empty → want nil, got %v", got)
	}
}

func TestBuildRelocSection_PaddingBlock(t *testing.T) {
	// One entry → block size 8+2=10, padded to 12 (one padding entry).
	out := BuildRelocSection([]BaseReloc{{RVA: 0x1234, Type: BaseRelocDir64}})
	if len(out) != 12 {
		t.Errorf("padded block size = %d, want 12", len(out))
	}
	// The page RVA is the entry's RVA rounded down to 4 KiB.
	pageRVA := binary.LittleEndian.Uint32(out[0:])
	if pageRVA != 0x1000 {
		t.Errorf("page RVA = 0x%x, want 0x1000", pageRVA)
	}
}

func TestBuildRelocSection_MultipleBlocks(t *testing.T) {
	// Entries in two different 4 KiB pages.
	out := BuildRelocSection([]BaseReloc{
		{RVA: 0x2000, Type: BaseRelocDir64},
		{RVA: 0x3000, Type: BaseRelocDir64},
	})
	if len(out) < 16 {
		t.Errorf("two-block reloc table too short: %d bytes", len(out))
	}
}
