package linker

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"testing"
)

// buildCOFFWithBSS produces a minimal COFF relocatable that includes a
// pure-BSS section (Characteristics has IMAGE_SCN_CNT_UNINITIALIZED_DATA,
// SizeOfRawData = 0). ReadObject must classify it correctly: leave Data
// nil and use VirtualSize fallback.
func buildCOFFWithBSS(t *testing.T) []byte {
	t.Helper()
	const (
		hdrSize = 20
		secSize = 40
		nSec    = 2
		symSize = 18
		minRead = 96
	)
	textBytes := []byte{0x90, 0x90, 0x90, 0x90}
	bufSize := hdrSize + secSize*nSec + len(textBytes) + symSize + 4
	if bufSize < minRead {
		bufSize = minRead
	}
	buf := make([]byte, bufSize)
	binary.LittleEndian.PutUint16(buf[0:], 0x8664)
	binary.LittleEndian.PutUint16(buf[2:], nSec)
	binary.LittleEndian.PutUint32(buf[8:], hdrSize+secSize*nSec+uint32(len(textBytes)))
	binary.LittleEndian.PutUint32(buf[12:], 1)
	binary.LittleEndian.PutUint16(buf[16:], 0)

	// Section 1: .text
	sec1 := hdrSize
	copy(buf[sec1:sec1+8], []byte(".text"))
	binary.LittleEndian.PutUint32(buf[sec1+16:], uint32(len(textBytes))) // SizeOfRawData
	binary.LittleEndian.PutUint32(buf[sec1+20:], hdrSize+secSize*nSec)   // PointerToRawData
	binary.LittleEndian.PutUint32(buf[sec1+36:], 0x60000020)

	// Section 2: .bss — IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x80, size=0
	sec2 := hdrSize + secSize
	copy(buf[sec2:sec2+8], []byte(".bss"))
	binary.LittleEndian.PutUint32(buf[sec2+8:], 0x100) // VirtualSize
	binary.LittleEndian.PutUint32(buf[sec2+16:], 0)    // SizeOfRawData=0
	binary.LittleEndian.PutUint32(buf[sec2+36:], 0xC0000080)

	// Section 1 data
	copy(buf[hdrSize+secSize*nSec:], textBytes)

	// Symbol table — one absolute classifier so the SymAbsolute branch
	// in classify() runs.
	sym := hdrSize + secSize*nSec + len(textBytes)
	copy(buf[sym:sym+8], []byte("absval"))
	binary.LittleEndian.PutUint32(buf[sym+8:], 0x42)    // Value
	binary.LittleEndian.PutUint16(buf[sym+12:], 0xFFFE) // SectionNumber = -2 (IMAGE_SYM_ABSOLUTE)
	binary.LittleEndian.PutUint16(buf[sym+14:], 0)
	buf[sym+16] = 3 // STORAGE_CLASS_STATIC
	buf[sym+17] = 0

	binary.LittleEndian.PutUint32(buf[sym+symSize:], 4)
	return buf
}

func TestReadObject_BSS(t *testing.T) {
	obj, err := ReadObject(bytes.NewReader(buildCOFFWithBSS(t)), "synth.o")
	if err != nil {
		t.Fatal(err)
	}
	var sawBSS bool
	for _, s := range obj.Sections {
		if s.Name == ".bss" {
			sawBSS = true
			if s.Data != nil {
				t.Errorf(".bss should have nil Data, got %d bytes", len(s.Data))
			}
			if s.VirtualSize != 0x100 {
				t.Errorf(".bss VirtualSize = %d, want 0x100", s.VirtualSize)
			}
		}
	}
	if !sawBSS {
		t.Error(".bss section not parsed")
	}
}

// TestReadObject_NotPE feeds ReadObject something that isn't a PE/COFF
// file at all → first error path.
func TestReadObject_NotPE(t *testing.T) {
	_, err := ReadObject(bytes.NewReader([]byte("garbage")), "x.o")
	if err == nil {
		t.Fatal("expected parse error")
	}
}

// TestReadObject_LinkedPERejected: a fully-linked PE (non-zero
// OptionalHeader) should be rejected. We reuse buildMinimalPE'-like
// fixture inlined here.
func TestReadObject_LinkedPERejected(t *testing.T) {
	buf := buildLinkedPE(t)
	if _, err := ReadObject(bytes.NewReader(buf), "linked.efi"); err == nil {
		t.Error("ReadObject accepted a linked PE")
	}
}

// buildLinkedPE makes a tiny but well-formed PE32+ image with a non-zero
// optional header. ReadObject must reject it.
func buildLinkedPE(t *testing.T) []byte {
	t.Helper()
	const (
		dosSize = 0x40
		optSize = 240
		secCnt  = 1
	)
	headerEnd := dosSize + 4 + 20 + optSize + secCnt*40
	sizeOfHeaders := alignUp(uint32(headerEnd), 512)
	textData := bytes.Repeat([]byte{0x90}, 16)
	textRaw := alignUp(uint32(len(textData)), 512)
	buf := make([]byte, sizeOfHeaders+textRaw)
	buf[0], buf[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(buf[0x3C:], dosSize)
	copy(buf[dosSize:dosSize+4], []byte("PE\x00\x00"))
	coff := dosSize + 4
	binary.LittleEndian.PutUint16(buf[coff:], 0x8664)
	binary.LittleEndian.PutUint16(buf[coff+2:], 1)
	binary.LittleEndian.PutUint16(buf[coff+16:], optSize)
	binary.LittleEndian.PutUint16(buf[coff+18:], 0x002E)
	opt := coff + 20
	binary.LittleEndian.PutUint16(buf[opt:], 0x020B)
	binary.LittleEndian.PutUint32(buf[opt+32:], 0x1000)
	binary.LittleEndian.PutUint32(buf[opt+36:], 512)
	binary.LittleEndian.PutUint32(buf[opt+56:], 0x2000)
	binary.LittleEndian.PutUint32(buf[opt+60:], sizeOfHeaders)
	binary.LittleEndian.PutUint32(buf[opt+108:], 16)
	sec := opt + optSize
	copy(buf[sec:sec+8], []byte(".text"))
	binary.LittleEndian.PutUint32(buf[sec+8:], uint32(len(textData)))
	binary.LittleEndian.PutUint32(buf[sec+12:], 0x1000)
	binary.LittleEndian.PutUint32(buf[sec+16:], textRaw)
	binary.LittleEndian.PutUint32(buf[sec+20:], sizeOfHeaders)
	binary.LittleEndian.PutUint32(buf[sec+36:], 0x60000020)
	return buf
}

// TestClassify tests the COFF-symbol classifier directly so its less-
// trodden branches (DEBUG / ABSOLUTE / FILE) are covered without
// needing a fixture object that contains every possible symbol shape.
func TestClassify(t *testing.T) {
	cases := []struct {
		s    pe.COFFSymbol
		want SymbolKind
	}{
		{pe.COFFSymbol{SectionNumber: 0}, SymUndefined},
		{pe.COFFSymbol{SectionNumber: -1}, SymAbsolute},                                          // IMAGE_SYM_DEBUG
		{pe.COFFSymbol{SectionNumber: -2}, SymAbsolute},                                          // IMAGE_SYM_ABSOLUTE
		{pe.COFFSymbol{SectionNumber: 1}, SymDefined},                                            // defined
		{pe.COFFSymbol{SectionNumber: 1, NumberOfAuxSymbols: 1, StorageClass: 103}, SymAbsolute}, // .file
	}
	for _, c := range cases {
		if got := classify(c.s); got != c.want {
			t.Errorf("classify(%+v) = %v, want %v", c.s, got, c.want)
		}
	}
}
