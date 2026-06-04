package linker

import (
	"testing"
)

// TestApplyRelocations_DiscardedSectionSkipped builds an AMD64 object with
// two sections: a placed .text and a .drectve directive section that
// ComputeLayout always discards. Both carry relocations. ApplyRelocations
// must skip the discarded section via the `!placed continue` at
// relocate.go:91-92 while still patching the placed one.
func TestApplyRelocations_DiscardedSectionSkipped(t *testing.T) {
	obj := &Object{
		Name:    "x.o",
		Machine: MachineAMD64,
		Sections: []*Section{
			{
				Name:            ".text",
				Characteristics: scnCntCode | scnMemExecute | scnMemRead,
				Data:            make([]byte, 8),
				VirtualSize:     8,
				Relocs:          []Reloc{{VirtualAddress: 0, SymbolIndex: 1, Type: relAMD64Addr64}},
			},
			{
				// .drectve is dropped by ComputeLayout (never enters Where).
				// Its reloc must therefore never reach applyOne.
				Name:            ".drectve",
				Characteristics: scnMemDiscardable,
				Data:            []byte("/sym"),
				VirtualSize:     4,
				Relocs:          []Reloc{{VirtualAddress: 0, SymbolIndex: 1, Type: relAMD64Addr64}},
			},
		},
		Symbols: []*Symbol{
			{Name: "", Kind: SymAbsolute, StorageClass: classStatic},
			{Name: "tgt", Kind: SymAbsolute, StorageClass: classExternal, Value: 0x4321},
		},
	}
	tab, err := Resolve([]*Object{obj}, ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	l := ComputeLayout([]*Object{obj}, LayoutOptions{})
	// Sanity: .drectve must have been discarded by layout.
	if _, placed := l.Where[SectionRef{ObjIdx: 0, SecIdx: 1}]; placed {
		t.Fatal(".drectve was unexpectedly placed by ComputeLayout")
	}
	if _, placed := l.Where[SectionRef{ObjIdx: 0, SecIdx: 0}]; !placed {
		t.Fatal(".text was not placed by ComputeLayout")
	}
	if _, err := ApplyRelocations([]*Object{obj}, tab, l); err != nil {
		t.Fatalf("ApplyRelocations: %v", err)
	}
}

// TestApplyRelocations_RISCV64DiscardedInPrepass builds a RISCV64 object
// with a placed .text carrying a PCREL_HI20/LO12 pair AND a discarded
// .drectve section that also carries relocations. The RISC-V PCREL_HI20
// pre-pass must skip the discarded section via the `!placed continue` at
// relocate.go:64-65 while still building the side table for the placed one.
func TestApplyRelocations_RISCV64DiscardedInPrepass(t *testing.T) {
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
					{VirtualAddress: 0, SymbolIndex: 1, Type: rvPCRelHi20},
					{VirtualAddress: 4, SymbolIndex: 2, Type: rvPCRelLo12I},
				},
			},
			{
				// Discarded by ComputeLayout. Carries a PCREL_HI20 reloc so
				// the pre-pass loop body would run if it were placed.
				Name:            ".drectve",
				Characteristics: scnMemDiscardable,
				Data:            []byte{0x97, 0x00, 0x00, 0x00},
				VirtualSize:     4,
				Relocs:          []Reloc{{VirtualAddress: 0, SymbolIndex: 1, Type: rvPCRelHi20}},
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
	if _, placed := l.Where[SectionRef{ObjIdx: 0, SecIdx: 1}]; placed {
		t.Fatal(".drectve was unexpectedly placed by ComputeLayout")
	}
	if _, err := ApplyRelocations([]*Object{obj}, tab, l); err != nil {
		t.Fatalf("ApplyRelocations: %v", err)
	}
}
