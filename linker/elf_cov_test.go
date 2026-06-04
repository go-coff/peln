package linker

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"testing"
)

// elf64Sym encodes one 24-byte ELF64 symbol-table entry:
//
//	name(u32) info(u8) other(u8) shndx(u16) value(u64) size(u64)
func elf64Sym(nameOff uint32, info, other uint8, shndx uint16, value, size uint64) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b[0:], nameOff)
	b[4] = info
	b[5] = other
	binary.LittleEndian.PutUint16(b[6:], shndx)
	binary.LittleEndian.PutUint64(b[8:], value)
	binary.LittleEndian.PutUint64(b[16:], size)
	return b
}

// elf64Rela encodes one 24-byte SHT_RELA entry: offset(u64) info(u64) addend(i64).
func elf64Rela(off uint64, sym uint32, typ uint32, addend int64) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint64(b[0:], off)
	info := (uint64(sym) << 32) | uint64(typ)
	binary.LittleEndian.PutUint64(b[8:], info)
	binary.LittleEndian.PutUint64(b[16:], uint64(addend))
	return b
}

// TestReadELFObject_SymtabAndRela builds a complete synthetic ELF64
// relocatable that carries BOTH a populated .symtab/.strtab pair AND a
// .rela.text section whose sh_info points at the allocated .text. This
// exercises:
//
//   - elf.go:84 — attaching parseRELA's result to the target section
//   - elf.go:101-103 — the symbol-conversion loop body
//   - elf_rela.go:38-45 — parseRELA's success path
func TestReadELFObject_SymtabAndRela(t *testing.T) {
	// .strtab content: index 0 must be NUL; "g" starts at offset 1.
	strtab := []byte{0, 'g', 0}
	const gNameOff = 1

	// .symtab: index 0 is the mandatory NULL symbol, then one GLOBAL symbol
	// "g" bound to section 1 (.text). debug/elf drops the index-0 entry, so
	// ef.Symbols() returns exactly one symbol — enough to run the loop body.
	symtab := append(
		elf64Sym(0, 0, 0, 0, 0, 0), // STN_UNDEF
		elf64Sym(gNameOff, byte(elf.ST_INFO(elf.STB_GLOBAL, elf.STT_FUNC)), 0, 1, 0, 4)...,
	)

	// .rela.text: one R_X86_64_64 against symbol index 1, addend 7.
	rela := elf64Rela(0, 1, uint32(elf.R_X86_64_64), 7)

	// Section table (index 0 is the implicit SHT_NULL the builder adds):
	//   1 = .text       (SHF_ALLOC|EXECINSTR)
	//   2 = .rela.text   (info=1 → .text, link=4 → .symtab)
	//   3 = .strtab
	//   4 = .symtab      (link=3 → .strtab, info=1 → first global index)
	b := elfBuilder{
		machine: elf.EM_X86_64,
		sections: []elfBuilderSec{
			{name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, data: []byte{0x90, 0x90, 0x90, 0x90}},
			{name: ".rela.text", typ: elf.SHT_RELA, info: 1, link: 4, entsize: 24, data: rela},
			{name: ".strtab", typ: elf.SHT_STRTAB, data: strtab},
			{name: ".symtab", typ: elf.SHT_SYMTAB, link: 3, info: 1, entsize: 24, data: symtab},
		},
	}
	buf := b.build(t)
	o, err := ReadObject(bytes.NewReader(buf), "symrela.o")
	if err != nil {
		t.Fatal(err)
	}

	// elf.go:101-103 — the synthetic symbol "g" must be present (in addition
	// to the prepended SHN_UNDEF placeholder at index 0).
	var sawG bool
	for _, s := range o.Symbols {
		if s.Name == "g" {
			sawG = true
			if s.Kind != SymDefined {
				t.Errorf("symbol g Kind = %v, want SymDefined", s.Kind)
			}
			if s.SectionNumber != 1 {
				t.Errorf("symbol g SectionNumber = %d, want 1", s.SectionNumber)
			}
			if s.StorageClass != classExternal {
				t.Errorf("symbol g StorageClass = %d, want classExternal", s.StorageClass)
			}
		}
	}
	if !sawG {
		t.Fatalf("symbol %q not converted; symbols=%+v", "g", o.Symbols)
	}

	// elf.go:84 + elf_rela.go:38-45 — the .rela.text relocation must be
	// attached to section index 1 (.text) and decoded faithfully.
	textRelocs := o.Sections[1].Relocs
	if len(textRelocs) != 1 {
		t.Fatalf(".text Relocs = %d, want 1 (%+v)", len(textRelocs), textRelocs)
	}
	r := textRelocs[0]
	if r.VirtualAddress != 0 || r.SymbolIndex != 1 || r.Type != uint16(elf.R_X86_64_64) || r.Addend != 7 {
		t.Errorf("reloc = %+v, want {VA:0 Sym:1 Type:%d Addend:7}", r, elf.R_X86_64_64)
	}
}
