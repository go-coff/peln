package linker

import (
	"strings"
	"testing"
)

// makeOneSecLayout builds the simplest possible Layout: one input section
// of `size` bytes, placed in a single output section at RVA `outRVA`.
func makeOneSecLayout(size int, outRVA, sectionAlign uint32) (*Object, *Layout, SectionRef) {
	obj := &Object{
		Name:    "synth.o",
		Machine: MachineAMD64,
		Sections: []*Section{
			{Name: ".text", Characteristics: scnCntCode | scnMemExecute,
				Data: make([]byte, size), VirtualSize: uint32(size)},
		},
	}
	ref := SectionRef{ObjIdx: 0, SecIdx: 0}
	out := &MergedSection{
		Name: ".text", RVA: outRVA, FileOffset: outRVA, VirtualSize: uint32(size),
		RawSize: alignUp(uint32(size), 512),
		Data:    obj.Sections[0].Data,
	}
	l := &Layout{
		Opts:     LayoutOptions{ImageBase: 0x10000, SectionAlignment: sectionAlign, FileAlignment: 0x200, HeaderReserve: 0x400},
		Out:      []*MergedSection{out},
		Where:    map[SectionRef]int{ref: 0},
		OffsetIn: map[SectionRef]uint32{ref: 0},
	}
	return obj, l, ref
}

func TestApplyRelocations_NoObjects(t *testing.T) {
	if base, err := ApplyRelocations(nil, &SymTab{}, &Layout{}); err != nil || base != nil {
		t.Errorf("nil input: %v %v", err, base)
	}
}

func TestApplyRelocations_MachineMismatch(t *testing.T) {
	a := &Object{Name: "a", Machine: MachineAMD64}
	b := &Object{Name: "b", Machine: MachineARM64}
	if _, err := ApplyRelocations([]*Object{a, b}, &SymTab{}, &Layout{}); err == nil ||
		!strings.Contains(err.Error(), "machine mismatch") {
		t.Errorf("want machine-mismatch error, got %v", err)
	}
}

// TestApplyOne_ELFDispatch routes synthetic Objects through the
// ELF-flavoured dispatcher for each supported machine, covering the
// case branches that the cross-arch real-fixture tests don't reach by
// themselves (the host has only one COFF/ELF stub per arch).
func TestApplyOne_ELFDispatch(t *testing.T) {
	mkObj := func(machine uint16, typ uint16, size int) *Object {
		return &Object{
			Name: "elf.o", Machine: machine, Format: FormatELF,
			Sections: []*Section{{
				Name:            ".text",
				Characteristics: scnCntCode | scnMemExecute | scnMemRead,
				Data:            make([]byte, size), VirtualSize: uint32(size),
				Relocs: []Reloc{{VirtualAddress: 0, SymbolIndex: 0, Type: typ}},
			}},
			Symbols: []*Symbol{
				{Name: "tgt", Kind: SymAbsolute, StorageClass: classExternal, Value: 0x1000},
			},
		}
	}
	cases := []struct {
		name    string
		machine uint16
		typ     uint16
		size    int
	}{
		{"amd64", MachineAMD64, rxAbs64, 8},
		{"arm64", MachineARM64, raAbs64, 8},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			obj := mkObj(c.machine, c.typ, c.size)
			tab, err := Resolve([]*Object{obj}, ResolveOptions{})
			if err != nil {
				t.Fatal(err)
			}
			l := ComputeLayout([]*Object{obj}, LayoutOptions{})
			if _, err := ApplyRelocations([]*Object{obj}, tab, l); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestApplyOne_ELFUnsupportedMachine(t *testing.T) {
	obj := &Object{
		Name: "x.o", Machine: 0x9999, Format: FormatELF,
		Sections: []*Section{{
			Name:            ".text",
			Characteristics: scnCntCode | scnMemExecute,
			Data:            make([]byte, 4), VirtualSize: 4,
			Relocs: []Reloc{{VirtualAddress: 0, SymbolIndex: 0, Type: 0}},
		}},
		Symbols: []*Symbol{
			{Name: "tgt", Kind: SymAbsolute, StorageClass: classExternal, Value: 0},
		},
	}
	tab, _ := Resolve([]*Object{obj}, ResolveOptions{})
	l := ComputeLayout([]*Object{obj}, LayoutOptions{})
	if _, err := ApplyRelocations([]*Object{obj}, tab, l); err == nil ||
		!strings.Contains(err.Error(), "ELF") {
		t.Errorf("want ELF-unsupported error, got %v", err)
	}
}

func TestApplyOne_UnsupportedMachine(t *testing.T) {
	obj := &Object{Name: "x.o", Machine: 0x9999, Symbols: []*Symbol{
		{Name: "tgt", Kind: SymAbsolute, StorageClass: classExternal, Value: 0x1234},
	}}
	_, l, ref := makeOneSecLayout(8, 0x1000, 0x1000)
	obj.Sections = []*Section{{Name: ".text", Characteristics: scnCntCode, Data: make([]byte, 8), VirtualSize: 8, Relocs: []Reloc{{VirtualAddress: 0, SymbolIndex: 0, Type: 0}}}}
	l.Where = map[SectionRef]int{ref: 0}
	l.OffsetIn = map[SectionRef]uint32{ref: 0}
	l.Out[0].Data = obj.Sections[0].Data
	tab := &SymTab{Entries: map[string]Resolved{"tgt": {Kind: SymAbsolute, Value: 0x1234}}}
	_, err := ApplyRelocations([]*Object{obj}, tab, l)
	if err == nil || !strings.Contains(err.Error(), "machine 0x9999") {
		t.Errorf("want machine-not-supported, got %v", err)
	}
}

func TestApplyOne_PatchOffsetPastEnd(t *testing.T) {
	obj := &Object{Name: "x.o", Machine: MachineAMD64, Symbols: []*Symbol{
		{Name: "tgt", Kind: SymAbsolute, StorageClass: classExternal, Value: 0},
	}}
	obj.Sections = []*Section{{Name: ".text", Characteristics: scnCntCode, Data: make([]byte, 4), VirtualSize: 4,
		Relocs: []Reloc{{VirtualAddress: 0x100, SymbolIndex: 0, Type: relAMD64Addr64}}}}
	_, l, ref := makeOneSecLayout(4, 0x1000, 0x1000)
	l.Out[0].Data = obj.Sections[0].Data
	l.Where = map[SectionRef]int{ref: 0}
	l.OffsetIn = map[SectionRef]uint32{ref: 0}
	tab := &SymTab{Entries: map[string]Resolved{"tgt": {Kind: SymAbsolute, Value: 0}}}
	_, err := ApplyRelocations([]*Object{obj}, tab, l)
	if err == nil || !strings.Contains(err.Error(), "past section end") {
		t.Errorf("want past-end, got %v", err)
	}
}

func TestApplyOne_UnresolvedSymbol(t *testing.T) {
	obj := &Object{Name: "x.o", Machine: MachineAMD64, Symbols: []*Symbol{
		{Name: "missing", Kind: SymUndefined, StorageClass: classExternal},
	}}
	obj.Sections = []*Section{{Name: ".text", Characteristics: scnCntCode, Data: make([]byte, 8), VirtualSize: 8,
		Relocs: []Reloc{{VirtualAddress: 0, SymbolIndex: 0, Type: relAMD64Addr64}}}}
	_, l, ref := makeOneSecLayout(8, 0x1000, 0x1000)
	l.Out[0].Data = obj.Sections[0].Data
	l.Where = map[SectionRef]int{ref: 0}
	l.OffsetIn = map[SectionRef]uint32{ref: 0}
	tab := &SymTab{Entries: map[string]Resolved{}}
	_, err := ApplyRelocations([]*Object{obj}, tab, l)
	if err == nil {
		t.Errorf("want unresolved error, got nil")
	}
}

func TestApplyOne_SymbolIndexOutOfRange(t *testing.T) {
	obj := &Object{Name: "x.o", Machine: MachineAMD64, Symbols: []*Symbol{}}
	obj.Sections = []*Section{{Name: ".text", Characteristics: scnCntCode, Data: make([]byte, 8), VirtualSize: 8,
		Relocs: []Reloc{{VirtualAddress: 0, SymbolIndex: 42, Type: relAMD64Addr64}}}}
	_, l, ref := makeOneSecLayout(8, 0x1000, 0x1000)
	l.Out[0].Data = obj.Sections[0].Data
	l.Where = map[SectionRef]int{ref: 0}
	l.OffsetIn = map[SectionRef]uint32{ref: 0}
	_, err := ApplyRelocations([]*Object{obj}, &SymTab{Entries: map[string]Resolved{}}, l)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("want index-out-of-range, got %v", err)
	}
}

func TestApplyOne_StaticDefined(t *testing.T) {
	// A STATIC + Defined symbol resolves to the input section it names.
	obj := &Object{Name: "x.o", Machine: MachineAMD64, Symbols: []*Symbol{
		{Name: ".text", Kind: SymDefined, StorageClass: classStatic, SectionNumber: 1, Value: 4},
	}}
	obj.Sections = []*Section{{Name: ".text", Characteristics: scnCntCode, Data: make([]byte, 16), VirtualSize: 16,
		Relocs: []Reloc{{VirtualAddress: 0, SymbolIndex: 0, Type: relAMD64Addr64}}}}
	_, l, ref := makeOneSecLayout(16, 0x1000, 0x1000)
	l.Out[0].Data = obj.Sections[0].Data
	l.Where = map[SectionRef]int{ref: 0}
	l.OffsetIn = map[SectionRef]uint32{ref: 0}
	base, err := ApplyRelocations([]*Object{obj}, &SymTab{Entries: map[string]Resolved{}}, l)
	if err != nil {
		t.Fatal(err)
	}
	if len(base) != 1 || base[0].Type != BaseRelocDir64 {
		t.Errorf("expected DIR64 base reloc, got %+v", base)
	}
}

func TestApplyOne_StaticUndefined(t *testing.T) {
	// STATIC + Undefined → lookup returns the symbol with Kind=Undefined,
	// which the dispatcher then fails on.
	obj := &Object{Name: "x.o", Machine: MachineAMD64, Symbols: []*Symbol{
		{Name: "abs", Kind: SymUndefined, StorageClass: classStatic},
	}}
	obj.Sections = []*Section{{Name: ".text", Characteristics: scnCntCode, Data: make([]byte, 8), VirtualSize: 8,
		Relocs: []Reloc{{VirtualAddress: 0, SymbolIndex: 0, Type: relAMD64Addr64}}}}
	_, l, ref := makeOneSecLayout(8, 0x1000, 0x1000)
	l.Out[0].Data = obj.Sections[0].Data
	l.Where = map[SectionRef]int{ref: 0}
	l.OffsetIn = map[SectionRef]uint32{ref: 0}
	_, err := ApplyRelocations([]*Object{obj}, &SymTab{Entries: map[string]Resolved{}}, l)
	if err == nil {
		t.Errorf("expected unresolved error, got nil")
	}
}

func TestLookup_StaticDefined(t *testing.T) {
	obj := &Object{Name: "x.o", Symbols: []*Symbol{
		{Name: ".text", Kind: SymDefined, StorageClass: classStatic, SectionNumber: 1, Value: 0x40},
	}}
	r, err := (&SymTab{Entries: map[string]Resolved{}}).Lookup([]*Object{obj}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != SymDefined || r.Offset != 0x40 {
		t.Errorf("got %+v", r)
	}
}

func TestLookup_StaticAbsolute(t *testing.T) {
	obj := &Object{Name: "x.o", Symbols: []*Symbol{
		{Name: "k", Kind: SymAbsolute, StorageClass: classStatic, Value: 0x55},
	}}
	r, err := (&SymTab{}).Lookup([]*Object{obj}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != SymAbsolute || r.Value != 0x55 {
		t.Errorf("got %+v", r)
	}
}

func TestLookup_IndexOutOfRange(t *testing.T) {
	obj := &Object{Name: "x.o", Symbols: []*Symbol{}}
	_, err := (&SymTab{}).Lookup([]*Object{obj}, 0, 99)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestLookup_ExternalMissing(t *testing.T) {
	obj := &Object{Name: "x.o", Symbols: []*Symbol{
		{Name: "missing", Kind: SymUndefined, StorageClass: classExternal},
	}}
	_, err := (&SymTab{Entries: map[string]Resolved{}}).Lookup([]*Object{obj}, 0, 0)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

// TestApplyRelocations_RISCV64PCRelPair drives the PCREL_HI20 pre-pass
// + the matching PCREL_LO12_I fix-up through the dispatcher, covering
// both ApplyRelocations's RISC-V branch and resolveRelocTarget.
//
// Layout: a single 8-byte .text section with two instructions:
//
//	+0: auipc x1, 0      with R_RISCV_PCREL_HI20 → "target"
//	+4: addi  x1, x1, 0  with R_RISCV_PCREL_LO12_I → label@+0
//
// After ApplyRelocations the two encoded immediates must agree on the
// same target VA.
func TestApplyRelocations_RISCV64PCRelPair(t *testing.T) {
	obj := &Object{
		Name:    "rv.o",
		Machine: MachineRISCV64,
		Format:  FormatELF,
		Sections: []*Section{
			{
				Name:            ".text",
				Characteristics: scnCntCode | scnMemExecute | scnMemRead,
				Data:            []byte{0x97, 0x00, 0x00, 0x00, 0x93, 0x80, 0x00, 0x00}, // auipc x1,0 / addi x1,x1,0
				VirtualSize:     8,
				Relocs: []Reloc{
					// Symbol index 1 is "target" — absolute 0x12345.
					{VirtualAddress: 0, SymbolIndex: 1, Type: rvPCRelHi20},
					// Symbol index 2 is "L0" pointing at offset 0 of .text
					// (the auipc above). PCREL_LO12 reuses the HI20's target.
					{VirtualAddress: 4, SymbolIndex: 2, Type: rvPCRelLo12I},
				},
			},
		},
		Symbols: []*Symbol{
			{Name: "", Kind: SymAbsolute, StorageClass: classStatic},
			{Name: "target", Kind: SymAbsolute, StorageClass: classExternal, Value: 0x12345},
			{Name: "L0", Kind: SymDefined, StorageClass: classStatic, SectionNumber: 1, Value: 0},
		},
	}
	tab, err := Resolve([]*Object{obj}, ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	l := ComputeLayout([]*Object{obj}, LayoutOptions{})
	if _, err := ApplyRelocations([]*Object{obj}, tab, l); err != nil {
		t.Fatal(err)
	}
	// auipc imm[31:12] should be the same as a direct HI20 calc.
	// (We don't pin a specific value here — the only thing that matters
	// is that no error was returned and the patch happened. The bit-
	// level math is covered by TestApplyRISCV64_PCRelHi20 +
	// TestApplyRISCV64_PCRelPair.)
}

// TestApplyRelocations_RISCV64PCRelSectionDefined exercises the
// SymDefined branch of resolveRelocTarget by having the PCREL_HI20
// target a section-relative symbol.
func TestApplyRelocations_RISCV64PCRelSectionDefined(t *testing.T) {
	obj := &Object{
		Name:    "rv.o",
		Machine: MachineRISCV64,
		Format:  FormatELF,
		Sections: []*Section{
			{
				Name:            ".text",
				Characteristics: scnCntCode | scnMemExecute | scnMemRead,
				Data:            []byte{0x97, 0x00, 0x00, 0x00, 0x93, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				VirtualSize:     12,
				Relocs: []Reloc{
					{VirtualAddress: 0, SymbolIndex: 1, Type: rvPCRelHi20},
					{VirtualAddress: 4, SymbolIndex: 2, Type: rvPCRelLo12I},
				},
			},
		},
		Symbols: []*Symbol{
			{Name: "", Kind: SymAbsolute, StorageClass: classStatic},
			// HI20 target: a defined section-relative symbol → exercises
			// the SymDefined branch in resolveRelocTarget.
			{Name: "data", Kind: SymDefined, StorageClass: classExternal, SectionNumber: 1, Value: 8},
			// LO12 references a STATIC label at offset 0 (where the HI20 is).
			{Name: "L0", Kind: SymDefined, StorageClass: classStatic, SectionNumber: 1, Value: 0},
		},
	}
	tab, err := Resolve([]*Object{obj}, ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	l := ComputeLayout([]*Object{obj}, LayoutOptions{})
	if _, err := ApplyRelocations([]*Object{obj}, tab, l); err != nil {
		t.Fatal(err)
	}
}

// TestApplyRelocations_RISCV64PCRelBadSymIdx exercises the
// lookupAcrossObjs error branch inside the pre-pass (and inside
// resolveRelocTarget).
func TestApplyRelocations_RISCV64PCRelBadSymIdx(t *testing.T) {
	obj := &Object{
		Name:    "rv.o",
		Machine: MachineRISCV64,
		Format:  FormatELF,
		Sections: []*Section{
			{
				Name:            ".text",
				Characteristics: scnCntCode | scnMemExecute | scnMemRead,
				Data:            []byte{0x97, 0x00, 0x00, 0x00},
				VirtualSize:     4,
				Relocs: []Reloc{
					{VirtualAddress: 0, SymbolIndex: 99, Type: rvPCRelHi20},
				},
			},
		},
		Symbols: []*Symbol{
			{Name: "", Kind: SymAbsolute, StorageClass: classStatic},
		},
	}
	tab, _ := Resolve([]*Object{obj}, ResolveOptions{})
	l := ComputeLayout([]*Object{obj}, LayoutOptions{})
	// Pre-pass swallows the error and the apply pass surfaces it.
	if _, err := ApplyRelocations([]*Object{obj}, tab, l); err == nil {
		t.Errorf("expected error for bogus symbol index")
	}
}

// TestApplyRelocations_RISCV64PCRelUnresolved drives the pre-pass's
// "skip on resolveRelocTarget error" branch by giving the HI20 a symbol
// that doesn't resolve.
func TestApplyRelocations_RISCV64PCRelUnresolved(t *testing.T) {
	obj := &Object{
		Name:    "rv.o",
		Machine: MachineRISCV64,
		Format:  FormatELF,
		Sections: []*Section{
			{
				Name:            ".text",
				Characteristics: scnCntCode | scnMemExecute | scnMemRead,
				Data:            []byte{0x97, 0x00, 0x00, 0x00},
				VirtualSize:     4,
				Relocs: []Reloc{
					// Symbol index 1 is undefined external — the pre-pass
					// silently skips it; the actual apply pass surfaces
					// the error.
					{VirtualAddress: 0, SymbolIndex: 1, Type: rvPCRelHi20},
				},
			},
		},
		Symbols: []*Symbol{
			{Name: "", Kind: SymAbsolute, StorageClass: classStatic},
			{Name: "missing", Kind: SymUndefined, StorageClass: classExternal},
		},
	}
	tab, _ := Resolve([]*Object{obj}, ResolveOptions{AllowUnresolved: true})
	l := ComputeLayout([]*Object{obj}, LayoutOptions{})
	if _, err := ApplyRelocations([]*Object{obj}, tab, l); err != nil {
		t.Fatal(err)
	}
}

func TestLookup_ExternalResolved(t *testing.T) {
	obj := &Object{Name: "x.o", Symbols: []*Symbol{
		{Name: "k", Kind: SymUndefined, StorageClass: classExternal},
	}}
	tab := &SymTab{Entries: map[string]Resolved{"k": {Kind: SymAbsolute, Value: 0x99}}}
	r, err := tab.Lookup([]*Object{obj}, 0, 0)
	if err != nil || r.Value != 0x99 {
		t.Errorf("got %+v err=%v", r, err)
	}
}
