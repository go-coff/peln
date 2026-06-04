package appender

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"testing"
)

// buildMinimalPE constructs a minimal PE32+ image that just has a single
// .text section. It is not a runnable binary — the goal is only to feed it
// to Append() and verify the result is structurally sound.
func buildMinimalPE(t *testing.T) []byte {
	t.Helper()

	const (
		dosSize       = 0x40
		optSize       = 240 // PE32+ standard size
		secTableSlots = 8   // reserve room for 8 section headers
		fileAlign     = 512
		sectionAlign  = 0x1000
	)
	headerEnd := dosSize + 4 /*sig*/ + 20 /*coff*/ + optSize + secTableSlots*40
	sizeOfHeaders := alignUp(uint32(headerEnd), fileAlign)

	textData := bytes.Repeat([]byte{0x90}, 16) // a few NOPs
	textRaw := alignUp(uint32(len(textData)), fileAlign)
	textVA := uint32(sectionAlign)

	buf := make([]byte, sizeOfHeaders+textRaw)

	// DOS header: "MZ" + e_lfanew at 0x3C.
	buf[0] = 'M'
	buf[1] = 'Z'
	binary.LittleEndian.PutUint32(buf[0x3C:], dosSize)

	// PE signature.
	copy(buf[dosSize:dosSize+4], []byte("PE\x00\x00"))
	coffOff := dosSize + 4

	// COFF File Header.
	binary.LittleEndian.PutUint16(buf[coffOff+0:], 0x8664) // Machine = AMD64
	binary.LittleEndian.PutUint16(buf[coffOff+2:], 1)      // NumberOfSections
	binary.LittleEndian.PutUint16(buf[coffOff+16:], optSize)
	binary.LittleEndian.PutUint16(buf[coffOff+18:], 0x002E) // Characteristics

	// Optional header.
	optOff := coffOff + 20
	binary.LittleEndian.PutUint16(buf[optOff+0:], 0x020B) // PE32+ magic
	binary.LittleEndian.PutUint32(buf[optOff+32:], sectionAlign)
	binary.LittleEndian.PutUint32(buf[optOff+36:], fileAlign)
	binary.LittleEndian.PutUint32(buf[optOff+56:], textVA+alignUp(uint32(len(textData)), sectionAlign)) // SizeOfImage
	binary.LittleEndian.PutUint32(buf[optOff+60:], sizeOfHeaders)
	binary.LittleEndian.PutUint32(buf[optOff+108:], 16) // NumberOfRvaAndSizes (16 zero-filled directories)

	// Section table entry for .text.
	secOff := optOff + optSize
	copy(buf[secOff:secOff+8], []byte(".text"))
	binary.LittleEndian.PutUint32(buf[secOff+8:], uint32(len(textData))) // VirtualSize
	binary.LittleEndian.PutUint32(buf[secOff+12:], uint32(textVA))       // VirtualAddress
	binary.LittleEndian.PutUint32(buf[secOff+16:], textRaw)              // SizeOfRawData
	binary.LittleEndian.PutUint32(buf[secOff+20:], sizeOfHeaders)        // PointerToRawData
	binary.LittleEndian.PutUint32(buf[secOff+36:], SCN_CNT_INITIALIZED_DATA|SCN_MEM_READ|SCN_MEM_EXECUTE)

	// .text data.
	copy(buf[sizeOfHeaders:], textData)
	return buf
}

func TestAppend_RoundTrip(t *testing.T) {
	stub := buildMinimalPE(t)
	out, err := Append(stub, []Section{
		{Name: ".osrel", Data: []byte("ID=test\n"), Characteristics: DefaultCharacteristics},
		{Name: ".cmdline", Data: []byte("console=ttyS0\n"), Characteristics: DefaultCharacteristics},
		{Name: ".linux", Data: bytes.Repeat([]byte{0xAA}, 1234), Characteristics: DefaultCharacteristics},
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	f, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("pe.NewFile: %v", err)
	}
	defer f.Close()

	if got, want := len(f.Sections), 4; got != want {
		t.Fatalf("section count = %d, want %d", got, want)
	}

	wantNames := []string{".text", ".osrel", ".cmdline", ".linux"}
	for i, want := range wantNames {
		if got := f.Sections[i].Name; got != want {
			t.Errorf("section[%d] name = %q, want %q", i, got, want)
		}
	}

	osrel, err := f.Sections[1].Data()
	if err != nil {
		t.Fatalf("read .osrel: %v", err)
	}
	if !bytes.HasPrefix(osrel, []byte("ID=test\n")) {
		t.Errorf(".osrel content = %q", osrel)
	}

	linuxData, err := f.Sections[3].Data()
	if err != nil {
		t.Fatalf("read .linux: %v", err)
	}
	if len(linuxData) < 1234 {
		t.Errorf(".linux SizeOfRawData should cover 1234 bytes, got %d", len(linuxData))
	}
	for i := 0; i < 1234; i++ {
		if linuxData[i] != 0xAA {
			t.Fatalf(".linux corruption at byte %d", i)
		}
	}
}

func TestAppend_HeaderOverflow(t *testing.T) {
	stub := buildMinimalPE(t)
	many := make([]Section, 20)
	for i := range many {
		many[i] = Section{Name: ".x", Data: []byte{0}, Characteristics: DefaultCharacteristics}
	}
	if _, err := Append(stub, many); err == nil {
		t.Fatal("expected overflow error")
	}
}

func TestAppend_RejectsLongName(t *testing.T) {
	stub := buildMinimalPE(t)
	if _, err := Append(stub, []Section{{Name: ".toolongname", Data: []byte{0}}}); err == nil {
		t.Fatal("expected long-name error")
	}
}

func TestAppend_RejectsTooShort(t *testing.T) {
	if _, err := Append([]byte("MZ"), nil); err == nil {
		t.Fatal("expected too-short error")
	}
}

func TestAppend_RejectsNonMZ(t *testing.T) {
	stub := make([]byte, 0x40)
	stub[0] = 'X'
	stub[1] = 'Y'
	if _, err := Append(stub, nil); err == nil {
		t.Fatal("expected non-MZ error")
	}
}

// mzWithElfanew returns a buffer of `size` bytes whose DOS header announces
// e_lfanew at the given offset. It is the smallest scaffolding that lets
// callers exercise parse() error branches end-to-end via Append().
func mzWithElfanew(size int, elfanew uint32) []byte {
	b := make([]byte, size)
	b[0] = 'M'
	b[1] = 'Z'
	binary.LittleEndian.PutUint32(b[0x3C:], elfanew)
	return b
}

func TestAppend_RejectsBadElfanew(t *testing.T) {
	// e_lfanew points past the end of the buffer.
	stub := mzWithElfanew(0x40, 0x1000)
	if _, err := Append(stub, nil); err == nil {
		t.Fatal("expected truncated-PE-header error")
	}
}

func TestParse_MissingPESignature(t *testing.T) {
	stub := mzWithElfanew(0x80, 0x40)
	copy(stub[0x40:], []byte("NOPE"))
	if _, err := parse(stub); err == nil {
		t.Fatal("expected missing-signature error")
	}
}

func TestParse_TruncatedOptionalHeader(t *testing.T) {
	stub := mzWithElfanew(0x80, 0x40)
	copy(stub[0x40:], []byte("PE\x00\x00"))
	// COFF.SizeOfOptionalHeader = huge → optOff+sizeOfOpt > len(stub).
	binary.LittleEndian.PutUint16(stub[0x40+4+16:], 0xFFFF)
	if _, err := parse(stub); err == nil {
		t.Fatal("expected truncated-optional-header error")
	}
}

func TestParse_OptionalHeaderTooSmall(t *testing.T) {
	stub := mzWithElfanew(0x80, 0x40)
	copy(stub[0x40:], []byte("PE\x00\x00"))
	// COFF.SizeOfOptionalHeader = 10 (< 68).
	binary.LittleEndian.PutUint16(stub[0x40+4+16:], 10)
	if _, err := parse(stub); err == nil {
		t.Fatal("expected optional-header-too-small error")
	}
}

func TestParse_UnsupportedMagic(t *testing.T) {
	stub := mzWithElfanew(0x200, 0x40)
	copy(stub[0x40:], []byte("PE\x00\x00"))
	const sizeOfOpt uint16 = 240
	binary.LittleEndian.PutUint16(stub[0x40+4+16:], sizeOfOpt)
	optOff := 0x40 + 4 + 20
	binary.LittleEndian.PutUint16(stub[optOff:], 0x0107) // ROM image, unsupported
	if _, err := parse(stub); err == nil {
		t.Fatal("expected unsupported-magic error")
	}
}

// buildMinimalPEOpts lets tests tweak the minimal stub for edge-case coverage.
type buildMinimalPEOpts struct {
	numSections     uint16 // override .text presence (0 = no sections at all)
	trailingJunk    int    // bytes of garbage appended past the last section
	truncateRawData bool   // shrink the file below the declared raw-data end
	sectionAlign    uint32 // override SectionAlignment (0 keeps the default)
	fileAlign       uint32 // override FileAlignment (0 keeps the default)
}

func buildMinimalPEWith(t *testing.T, opts buildMinimalPEOpts) []byte {
	t.Helper()

	const (
		dosSize       = 0x40
		optSize       = 240
		secTableSlots = 8
	)
	fileAlign := uint32(512)
	if opts.fileAlign != 0 {
		fileAlign = opts.fileAlign
	}
	sectionAlign := uint32(0x1000)
	if opts.sectionAlign != 0 {
		sectionAlign = opts.sectionAlign
	}
	headerEnd := dosSize + 4 + 20 + optSize + secTableSlots*40
	sizeOfHeaders := alignUp(uint32(headerEnd), fileAlign)

	numSections := uint16(1)
	if opts.numSections != 0xFFFF { // 0xFFFF = "use default"
		numSections = opts.numSections
	}

	textData := bytes.Repeat([]byte{0x90}, 16)
	textRaw := alignUp(uint32(len(textData)), fileAlign)
	textVA := sectionAlign

	bodySize := uint32(0)
	if numSections > 0 {
		bodySize = textRaw
	}
	buf := make([]byte, sizeOfHeaders+bodySize+uint32(opts.trailingJunk))

	buf[0] = 'M'
	buf[1] = 'Z'
	binary.LittleEndian.PutUint32(buf[0x3C:], dosSize)

	copy(buf[dosSize:dosSize+4], []byte("PE\x00\x00"))
	coffOff := dosSize + 4
	binary.LittleEndian.PutUint16(buf[coffOff+0:], 0x8664)
	binary.LittleEndian.PutUint16(buf[coffOff+2:], numSections)
	binary.LittleEndian.PutUint16(buf[coffOff+16:], optSize)
	binary.LittleEndian.PutUint16(buf[coffOff+18:], 0x002E)

	optOff := coffOff + 20
	binary.LittleEndian.PutUint16(buf[optOff+0:], 0x020B)
	binary.LittleEndian.PutUint32(buf[optOff+32:], sectionAlign)
	binary.LittleEndian.PutUint32(buf[optOff+36:], fileAlign)
	binary.LittleEndian.PutUint32(buf[optOff+56:], textVA+alignUp(uint32(len(textData)), sectionAlign))
	binary.LittleEndian.PutUint32(buf[optOff+60:], sizeOfHeaders)
	binary.LittleEndian.PutUint32(buf[optOff+108:], 16)

	if numSections > 0 {
		secOff := optOff + optSize
		copy(buf[secOff:secOff+8], []byte(".text"))
		binary.LittleEndian.PutUint32(buf[secOff+8:], uint32(len(textData)))
		binary.LittleEndian.PutUint32(buf[secOff+12:], textVA)
		binary.LittleEndian.PutUint32(buf[secOff+16:], textRaw)
		binary.LittleEndian.PutUint32(buf[secOff+20:], sizeOfHeaders)
		binary.LittleEndian.PutUint32(buf[secOff+36:], SCN_CNT_INITIALIZED_DATA|SCN_MEM_READ|SCN_MEM_EXECUTE)
		copy(buf[sizeOfHeaders:], textData)
	}

	if opts.truncateRawData && numSections > 0 {
		// Drop bytes from the tail so the file ends inside the declared raw-data
		// region; nothing else changes.
		buf = buf[:sizeOfHeaders+textRaw/2]
	}
	return buf
}

func TestAppend_ZeroSectionStub(t *testing.T) {
	// numSections = 0 forces nextVA == 0 (the section loop is empty) and
	// nextFile < alignUp(sizeOfHeaders), exercising both fallback branches.
	stub := buildMinimalPEWith(t, buildMinimalPEOpts{numSections: 0})
	// Shrink the buffer below SizeOfHeaders so we also hit the pad branch
	// inside Append where len(out) < aligned.
	stub = stub[:len(stub)-10]
	out, err := Append(stub, []Section{
		{Name: ".x", Data: []byte("hi"), Characteristics: DefaultCharacteristics},
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("Append returned empty output")
	}
}

func TestAppend_TrailingJunkTruncated(t *testing.T) {
	// trailingJunk forces len(stub) > aligned, exercising the truncate branch.
	stub := buildMinimalPEWith(t, buildMinimalPEOpts{numSections: 0xFFFF, trailingJunk: 100})
	out, err := Append(stub, []Section{
		{Name: ".x", Data: []byte("hello"), Characteristics: DefaultCharacteristics},
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	f, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("pe.NewFile: %v", err)
	}
	defer f.Close()
	if got := len(f.Sections); got != 2 {
		t.Fatalf("section count = %d, want 2", got)
	}
}

func TestAlignUp(t *testing.T) {
	cases := []struct {
		v, a, want uint32
	}{
		{0, 0, 0}, // align==0 short-circuit
		{5, 0, 5}, // align==0 short-circuit, non-zero v
		{8, 4, 8}, // already aligned
		{5, 4, 8}, // round up
		{16, 16, 16},
	}
	for _, c := range cases {
		if got := alignUp(c.v, c.a); got != c.want {
			t.Errorf("alignUp(%d,%d) = %d, want %d", c.v, c.a, got, c.want)
		}
	}
}
