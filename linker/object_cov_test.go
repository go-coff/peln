package linker

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildCOFFWithReloc produces a minimal COFF/AMD64 relocatable with a
// single .text section that carries one section-level COFF relocation
// record. ReadObject must surface it as Section.Relocs[0], exercising the
// object.go:217-223 reloc-conversion loop.
func buildCOFFWithReloc(t *testing.T) []byte {
	t.Helper()
	const (
		hdrSize = 20
		secSize = 40
		nSec    = 1
		symSize = 18
		relSize = 10
		minRead = 96
	)
	textBytes := []byte{0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0} // movabs rax, imm64 (target patched by reloc)

	dataStart := hdrSize + secSize*nSec
	relStart := dataStart + len(textBytes)
	symStart := relStart + relSize
	bufSize := symStart + symSize + 4 // + 4-byte string-table size
	if bufSize < minRead {
		bufSize = minRead
	}
	buf := make([]byte, bufSize)

	// COFF file header.
	binary.LittleEndian.PutUint16(buf[0:], 0x8664) // Machine = AMD64
	binary.LittleEndian.PutUint16(buf[2:], nSec)
	binary.LittleEndian.PutUint32(buf[8:], uint32(symStart)) // PointerToSymbolTable
	binary.LittleEndian.PutUint32(buf[12:], 1)               // NumberOfSymbols
	binary.LittleEndian.PutUint16(buf[16:], 0)               // SizeOfOptionalHeader

	// Section header: .text.
	sec1 := hdrSize
	copy(buf[sec1:sec1+8], []byte(".text"))
	binary.LittleEndian.PutUint32(buf[sec1+16:], uint32(len(textBytes))) // SizeOfRawData
	binary.LittleEndian.PutUint32(buf[sec1+20:], uint32(dataStart))      // PointerToRawData
	binary.LittleEndian.PutUint32(buf[sec1+24:], uint32(relStart))       // PointerToRelocations
	binary.LittleEndian.PutUint16(buf[sec1+32:], 1)                      // NumberOfRelocations
	binary.LittleEndian.PutUint32(buf[sec1+36:], 0x60000020)             // CODE|EXECUTE|READ

	// Section data.
	copy(buf[dataStart:], textBytes)

	// One COFF relocation: VirtualAddress(u32) SymbolTableIndex(u32) Type(u16).
	binary.LittleEndian.PutUint32(buf[relStart:], 2)   // VirtualAddress = patch site
	binary.LittleEndian.PutUint32(buf[relStart+4:], 0) // SymbolTableIndex = 0
	binary.LittleEndian.PutUint16(buf[relStart+8:], 1) // Type = IMAGE_REL_AMD64_ADDR64

	// One symbol: an absolute "tgt" so the relocation has a referent.
	copy(buf[symStart:symStart+8], []byte("tgt"))
	binary.LittleEndian.PutUint32(buf[symStart+8:], 0x1000)  // Value
	binary.LittleEndian.PutUint16(buf[symStart+12:], 0xFFFE) // SectionNumber = IMAGE_SYM_ABSOLUTE
	binary.LittleEndian.PutUint16(buf[symStart+14:], 0)
	buf[symStart+16] = 3 // STORAGE_CLASS_STATIC
	buf[symStart+17] = 0

	// String table size (4 bytes, value = 4 = just the length field itself).
	binary.LittleEndian.PutUint32(buf[symStart+symSize:], 4)
	return buf
}

// TestReadObject_COFFReloc verifies that a section-level COFF relocation
// is parsed into Section.Relocs (object.go:217-223).
func TestReadObject_COFFReloc(t *testing.T) {
	obj, err := ReadObject(bytes.NewReader(buildCOFFWithReloc(t)), "rel.o")
	if err != nil {
		t.Fatal(err)
	}
	var text *Section
	for _, s := range obj.Sections {
		if s.Name == ".text" {
			text = s
		}
	}
	if text == nil {
		t.Fatal(".text section not parsed")
	}
	if len(text.Relocs) != 1 {
		t.Fatalf(".text Relocs = %d, want 1 (%+v)", len(text.Relocs), text.Relocs)
	}
	r := text.Relocs[0]
	if r.VirtualAddress != 2 || r.SymbolIndex != 0 || r.Type != 1 {
		t.Errorf("reloc = %+v, want {VA:2 Sym:0 Type:1}", r)
	}
}
