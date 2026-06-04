package linker

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"testing"
)

// TestAppendRelocSection_FileAlignmentBump constructs a synthetic Layout
// whose last section ends on a non-FA boundary, so appendRelocSection
// has to bump foff up to the next file-alignment multiple.
func TestAppendRelocSection_FileAlignmentBump(t *testing.T) {
	l := &Layout{
		Opts: LayoutOptions{
			ImageBase: 0x10000, SectionAlignment: 0x1000, FileAlignment: 0x200,
		},
		Out: []*MergedSection{
			// Misaligned end: FileOffset=0x400, RawSize=0x10 → ends at 0x410,
			// which is not a multiple of FileAlignment=0x200.
			{Name: ".text", RVA: 0x1000, FileOffset: 0x400, RawSize: 0x10,
				VirtualSize: 0x10, Characteristics: scnCntCode},
		},
	}
	appendRelocSection(l, []byte{0x00, 0x10, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00})
	last := l.Out[len(l.Out)-1]
	if last.FileOffset%0x200 != 0 {
		t.Errorf("after bump, FileOffset = 0x%x, want FA-aligned", last.FileOffset)
	}
}

// TestEmitPE_EmptyOut drives emitPE with an empty layout to hit the
// no-sections branch of sizeOfImage.
func TestEmitPE_EmptyOut(t *testing.T) {
	l := &Layout{
		Opts: LayoutOptions{
			ImageBase: 0x10000, SectionAlignment: 0x1000, FileAlignment: 0x200, HeaderReserve: 0x400,
		},
	}
	out, err := emitPE(l, LinkOptions{Machine: MachineAMD64, Subsystem: 10, ImageBase: 0x10000}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(out, []byte("MZ")) {
		t.Error("output is not a PE")
	}
}

// TestEmitPE_FileSizeUnderHeaders covers the `fileSize < sizeOfHeaders`
// branch. We construct a (deliberately weird) Layout whose single data-
// bearing section ends well below sizeOfHeaders, so emitPE has to bump
// fileSize back up to the header floor.
func TestEmitPE_FileSizeUnderHeaders(t *testing.T) {
	l := &Layout{
		Opts: LayoutOptions{
			ImageBase: 0x10000, SectionAlignment: 0x1000, FileAlignment: 0x200, HeaderReserve: 0x800,
		},
		Out: []*MergedSection{
			// FileOffset+RawSize = 0x100 + 0x10 = 0x110, well below the
			// 0x800 HeaderReserve. The reserve forces sizeOfHeaders ≥
			// 0x800, so fileSize=0x110 triggers the bump.
			{Name: ".text", RVA: 0x1000, FileOffset: 0x100, RawSize: 0x10, VirtualSize: 0x10,
				Data: make([]byte, 0x10), Characteristics: scnCntCode | scnMemExecute | scnMemRead},
		},
	}
	out, err := emitPE(l, LinkOptions{Machine: MachineAMD64, Subsystem: 10, ImageBase: 0x10000}, 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 0x800 {
		t.Errorf("output too small: %d, want ≥0x800", len(out))
	}
}

// TestEmitPE_BSSOnly verifies that an all-BSS image still produces a
// valid PE (RawSize=0 everywhere → fileSize stays at sizeOfHeaders).
func TestEmitPE_BSSOnly(t *testing.T) {
	l := &Layout{
		Opts: LayoutOptions{
			ImageBase: 0x10000, SectionAlignment: 0x1000, FileAlignment: 0x200, HeaderReserve: 0x400,
		},
		Out: []*MergedSection{
			{Name: ".bss", RVA: 0x1000, FileOffset: 0x400, RawSize: 0, VirtualSize: 0x100,
				Characteristics: scnCntUninitializedData | scnMemRead | scnMemWrite},
		},
	}
	out, err := emitPE(l, LinkOptions{Machine: MachineAMD64, Subsystem: 10, ImageBase: 0x10000}, 0)
	if err != nil || len(out) < 0x400 {
		t.Fatalf("err=%v len=%d", err, len(out))
	}
}

// TestReadObject_BadSectionPointer crafts a COFF where the section
// header's PointerToRawData points past EOF, so debug/pe's s.Data() call
// fails and surfaces a wrapped error.
func TestReadObject_BadSectionPointer(t *testing.T) {
	const (
		hdrSize = 20
		secSize = 40
		minRead = 96
	)
	buf := make([]byte, minRead)
	binary.LittleEndian.PutUint16(buf[0:], 0x8664)
	binary.LittleEndian.PutUint16(buf[2:], 1) // 1 section
	binary.LittleEndian.PutUint32(buf[8:], 0) // no symbol table
	binary.LittleEndian.PutUint32(buf[12:], 0)
	binary.LittleEndian.PutUint16(buf[16:], 0)
	sec := hdrSize
	copy(buf[sec:sec+8], []byte(".text"))
	binary.LittleEndian.PutUint32(buf[sec+8:], 0x100)       // VirtualSize
	binary.LittleEndian.PutUint32(buf[sec+16:], 0x100)      // SizeOfRawData
	binary.LittleEndian.PutUint32(buf[sec+20:], 0xDEADBEEF) // PointerToRawData way past EOF
	binary.LittleEndian.PutUint32(buf[sec+36:], 0x60000020)
	_, err := ReadObject(bytes.NewReader(buf), "bad.o")
	if err == nil {
		t.Errorf("expected ReadObject to fail on bad section pointer")
	}
}

// TestClassify_NegativeSectionNumber drives the default branch (SectionNumber
// not in {-2, -1, 0, >0}) — exotic IMAGE_SYM_* sentinel values.
func TestClassify_NegativeSectionNumber(t *testing.T) {
	if got := classify(pe.COFFSymbol{SectionNumber: -3}); got != SymAbsolute {
		t.Errorf("classify(SectionNumber=-3) = %v, want SymAbsolute", got)
	}
}
