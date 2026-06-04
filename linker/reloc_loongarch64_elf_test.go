package linker

import (
	"encoding/binary"
	"testing"
)

// TestApplyRelocations_LoongArch64Abs64 drives a minimal LoongArch64 ELF
// object through the full ApplyRelocations pipeline so the
// `case MachineLoongArch64: return applyLoongArch64(...)` dispatch arm in
// applyOne is exercised. The object has one SHF_ALLOC .data section and one
// R_LARCH_64 (laAbs64) relocation pointing at an absolute symbol.
func TestApplyRelocations_LoongArch64Abs64(t *testing.T) {
	obj := &Object{
		Name:    "loong.o",
		Machine: MachineLoongArch64,
		Format:  FormatELF,
		Sections: []*Section{
			{
				Name:            ".data",
				Characteristics: scnCntInitializedData | scnMemRead | scnMemWrite,
				Data:            make([]byte, 8),
				VirtualSize:     8,
				Relocs: []Reloc{
					// Symbol index 1 ("target") is absolute 0x12345.
					{VirtualAddress: 0, SymbolIndex: 1, Type: laAbs64, Addend: 0},
				},
			},
		},
		Symbols: []*Symbol{
			{Name: "", Kind: SymAbsolute, StorageClass: classStatic},
			{Name: "target", Kind: SymAbsolute, StorageClass: classExternal, Value: 0x12345},
		},
	}
	tab, err := Resolve([]*Object{obj}, ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	l := ComputeLayout([]*Object{obj}, LayoutOptions{})
	base, err := ApplyRelocations([]*Object{obj}, tab, l)
	if err != nil {
		t.Fatalf("ApplyRelocations: %v", err)
	}
	// R_LARCH_64 writes the absolute target VA and emits a DIR64 base reloc.
	out := l.Out[l.Where[SectionRef{ObjIdx: 0, SecIdx: 0}]]
	if got := binary.LittleEndian.Uint64(out.Data); got != 0x12345 {
		t.Errorf("patched value = 0x%x, want 0x12345", got)
	}
	found := false
	for _, b := range base {
		if b.Type == BaseRelocDir64 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a DIR64 base reloc, got %+v", base)
	}
}
