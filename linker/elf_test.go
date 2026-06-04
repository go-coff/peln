package linker

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

// --- Real-fixture round trip --------------------------------------------------

// TestReadObject_RealRISCV64 is the end-to-end happy path: parse the
// TinyGo-produced riscv64 ELF, run it through Link, and verify the
// output is a parsable PE32+ EFI binary. The stub objects' presence is
// conditional; the test is skipped on hosts without the local checkout.
func TestReadObject_RealRISCV64(t *testing.T) {
	const path = "../../../go-coff/stub/main-riscv64.o"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("no local fixture at %s", path)
	}
	o, err := ReadObject(bytes.NewReader(data), path)
	if err != nil {
		t.Fatal(err)
	}
	if o.Machine != MachineRISCV64 {
		t.Errorf("Machine = 0x%x, want 0x%x", o.Machine, MachineRISCV64)
	}
	if len(o.Sections) == 0 {
		t.Fatal("no sections parsed")
	}
	out, err := Link([]*Object{o}, LinkOptions{AllowUnresolved: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(out, []byte("MZ")) {
		t.Error("output is not a PE")
	}
}

// --- ELF magic dispatch -------------------------------------------------------

func TestReadObject_BadMagicReader(t *testing.T) {
	// Reader that fails on the very first ReadAt (used by the magic probe).
	_, err := ReadObject(badReader{}, "bad")
	if err == nil || !strings.Contains(err.Error(), "read magic") {
		t.Errorf("want read-magic error, got %v", err)
	}
}

type badReader struct{}

func (badReader) ReadAt([]byte, int64) (int, error) {
	return 0, &os.PathError{Op: "read", Path: "bad", Err: os.ErrInvalid}
}

// --- elfMachine ---------------------------------------------------------------

func TestElfMachine(t *testing.T) {
	cases := []struct {
		in   elf.Machine
		want uint16
	}{
		{elf.EM_X86_64, MachineAMD64},
		{elf.EM_AARCH64, MachineARM64},
		{elf.EM_RISCV, MachineRISCV64},
		{elf.EM_LOONGARCH, MachineLoongArch64},
		{elf.EM_MIPS, 0},
	}
	for _, c := range cases {
		if got := elfMachine(c.in); got != c.want {
			t.Errorf("elfMachine(%v) = 0x%x, want 0x%x", c.in, got, c.want)
		}
	}
}

// --- elfCharacteristics -------------------------------------------------------

func TestElfCharacteristics(t *testing.T) {
	cases := []struct {
		typ   elf.SectionType
		flags elf.SectionFlag
		want  uint32 // expected bits ANDed in
	}{
		{elf.SHT_PROGBITS, 0, scnMemDiscardable}, // no SHF_ALLOC → debug
		{elf.SHT_PROGBITS, elf.SHF_ALLOC, scnMemRead | scnCntInitializedData},
		{elf.SHT_PROGBITS, elf.SHF_ALLOC | elf.SHF_EXECINSTR, scnMemRead | scnCntCode | scnMemExecute},
		{elf.SHT_PROGBITS, elf.SHF_ALLOC | elf.SHF_WRITE, scnMemRead | scnCntInitializedData | scnMemWrite},
		{elf.SHT_NOBITS, elf.SHF_ALLOC | elf.SHF_WRITE, scnMemRead | scnCntUninitializedData | scnMemWrite},
	}
	for _, c := range cases {
		s := &elf.Section{SectionHeader: elf.SectionHeader{Type: c.typ, Flags: c.flags}}
		if got := elfCharacteristics(s); got&c.want != c.want {
			t.Errorf("type=%v flags=0x%x: characteristics 0x%x missing 0x%x", c.typ, c.flags, got, c.want)
		}
	}
}

// --- convertELFSymbol ---------------------------------------------------------

func TestConvertELFSymbol(t *testing.T) {
	cases := []struct {
		s    elf.Symbol
		kind SymbolKind
		cls  uint8
	}{
		{elf.Symbol{Info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC), Section: elf.SHN_UNDEF}, SymUndefined, classExternal},
		{elf.Symbol{Info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC), Section: 2}, SymDefined, classExternal},
		{elf.Symbol{Info: byte(elf.STB_WEAK) << 4, Section: elf.SHN_UNDEF}, SymUndefined, classWeakExternal},
		{elf.Symbol{Info: byte(elf.STB_LOCAL) << 4, Section: 3}, SymDefined, classStatic},
		{elf.Symbol{Info: byte(elf.STB_LOCAL) << 4, Section: elf.SHN_ABS}, SymAbsolute, classStatic},
		{elf.Symbol{Info: byte(elf.STB_LOCAL) << 4, Section: elf.SHN_COMMON}, SymAbsolute, classStatic},
	}
	for _, c := range cases {
		out := convertELFSymbol(c.s)
		if out.Kind != c.kind {
			t.Errorf("%+v Kind = %v, want %v", c.s, out.Kind, c.kind)
		}
		if out.StorageClass != c.cls {
			t.Errorf("%+v Class = %d, want %d", c.s, out.StorageClass, c.cls)
		}
	}
}

// --- ELF readObject error paths -----------------------------------------------

func TestReadELFObject_NotRelocatable(t *testing.T) {
	// Synthesise an ELF64 ET_EXEC (linked, not relocatable). readELFObject
	// must reject it.
	buf := buildSyntheticELF(t, elf.ET_EXEC, elf.EM_X86_64, nil, nil)
	_, err := ReadObject(bytes.NewReader(buf), "exec.so")
	if err == nil || !strings.Contains(err.Error(), "not a relocatable") {
		t.Errorf("want not-relocatable, got %v", err)
	}
}

func TestReadELFObject_UnsupportedMachine(t *testing.T) {
	buf := buildSyntheticELF(t, elf.ET_REL, elf.EM_MIPS, nil, nil)
	_, err := ReadObject(bytes.NewReader(buf), "mips.o")
	if err == nil || !strings.Contains(err.Error(), "unsupported ELF machine") {
		t.Errorf("want unsupported-machine, got %v", err)
	}
}

func TestReadELFObject_Garbage(t *testing.T) {
	// Bytes 0..3 are ELF magic but the rest is malformed.
	buf := []byte{0x7F, 'E', 'L', 'F', 0xff, 0xff, 0xff, 0xff}
	_, err := ReadObject(bytes.NewReader(buf), "bad.elf")
	if err == nil || !strings.Contains(err.Error(), "parse ELF") {
		t.Errorf("want parse-ELF error, got %v", err)
	}
}

// --- parseRELA ----------------------------------------------------------------

func TestParseRELA_BadSize(t *testing.T) {
	// Build an ELF with a .rela section whose size isn't a multiple of 24.
	objs := elfBuilder{
		machine: elf.EM_X86_64,
		sections: []elfBuilderSec{
			{name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, data: []byte{0x90, 0x90, 0x90, 0x90}},
			{name: ".rela.text", typ: elf.SHT_RELA, info: 1, entsize: 24, data: bytes.Repeat([]byte{0xAA}, 23)}, // not /24
		},
	}
	buf := objs.build(t)
	_, err := ReadObject(bytes.NewReader(buf), "x.o")
	if err == nil || !strings.Contains(err.Error(), "not a multiple") {
		t.Errorf("want not-multiple error, got %v", err)
	}
}

func TestParseRELA_TypeOverflow(t *testing.T) {
	// .rela entry with info high-32 = sym index 0, low-32 = 0x10000
	// (one past our uint16 ceiling).
	entry := make([]byte, 24)
	binary.LittleEndian.PutUint64(entry[0:], 0)       // offset
	binary.LittleEndian.PutUint64(entry[8:], 0x10000) // info (type field overflow)
	binary.LittleEndian.PutUint64(entry[16:], 0)      // addend
	objs := elfBuilder{
		machine: elf.EM_X86_64,
		sections: []elfBuilderSec{
			{name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, data: []byte{0x90}},
			{name: ".rela.text", typ: elf.SHT_RELA, info: 1, entsize: 24, data: entry},
		},
	}
	buf := objs.build(t)
	_, err := ReadObject(bytes.NewReader(buf), "x.o")
	if err == nil || !strings.Contains(err.Error(), "doesn't fit") {
		t.Errorf("want type-overflow error, got %v", err)
	}
}

func TestParseRELA_RelaTargetOutOfRange(t *testing.T) {
	objs := elfBuilder{
		machine: elf.EM_X86_64,
		sections: []elfBuilderSec{
			{name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, data: []byte{0x90}},
			{name: ".rela.bogus", typ: elf.SHT_RELA, info: 99, entsize: 24, data: nil}, // info points past sections
		},
	}
	buf := objs.build(t)
	_, err := ReadObject(bytes.NewReader(buf), "x.o")
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("want out-of-range, got %v", err)
	}
}

// --- IO-error paths -----------------------------------------------------------

// These tests use the builder's claimedSize override to lie about a
// section's on-disk size. debug/elf accepts the file (header layout is
// still well-formed) but Data() trips on the missing bytes.

func TestReadELFObject_SectionDataIOError(t *testing.T) {
	objs := elfBuilder{
		machine: elf.EM_X86_64,
		sections: []elfBuilderSec{
			{
				name: ".text", typ: elf.SHT_PROGBITS,
				flags:       elf.SHF_ALLOC | elf.SHF_EXECINSTR,
				data:        []byte{0x90, 0x90, 0x90, 0x90},
				claimedSize: 1 << 24, // 16 MiB, well past EOF
			},
		},
	}
	buf := objs.build(t)
	_, err := ReadObject(bytes.NewReader(buf), "bigs.o")
	if err == nil || !strings.Contains(err.Error(), ".text") {
		t.Errorf("want section-data error on .text, got %v", err)
	}
}

func TestReadELFObject_SymtabIOError(t *testing.T) {
	// .symtab claims more bytes than the file holds → ef.Symbols()
	// returns an io error (not ErrNoSymbols), tripping readELFObject's
	// guard.
	objs := elfBuilder{
		machine: elf.EM_X86_64,
		sections: []elfBuilderSec{
			{name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, data: []byte{0x90}},
			{name: ".strtab", typ: elf.SHT_STRTAB, data: []byte{0, 'a', 0}},
			{
				name: ".symtab", typ: elf.SHT_SYMTAB, link: 2, entsize: 24,
				data: bytes.Repeat([]byte{0}, 24), claimedSize: 1 << 24,
			},
		},
	}
	buf := objs.build(t)
	_, err := ReadObject(bytes.NewReader(buf), "bigsym.o")
	if err == nil || !strings.Contains(err.Error(), "symbols") {
		t.Errorf("want symtab io error, got %v", err)
	}
}

func TestParseRELA_DataIOError(t *testing.T) {
	objs := elfBuilder{
		machine: elf.EM_X86_64,
		sections: []elfBuilderSec{
			{name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, data: []byte{0x90}},
			{
				name: ".rela.text", typ: elf.SHT_RELA, info: 1, entsize: 24,
				data:        []byte{0},
				claimedSize: 1 << 24, // larger than the file
			},
		},
	}
	buf := objs.build(t)
	_, err := ReadObject(bytes.NewReader(buf), "bigrel.o")
	if err == nil || !strings.Contains(err.Error(), "rela") {
		t.Errorf("want rela io error, got %v", err)
	}
}

// --- Synthetic ELF builder ---------------------------------------------------

type elfBuilderSec struct {
	name    string
	typ     elf.SectionType
	flags   elf.SectionFlag
	info    uint32
	link    uint32
	entsize uint64
	data    []byte
	// claimedSize, if non-zero, overrides the section-header Size field
	// so the header claims more (or fewer) bytes than `data` actually
	// contains. Tests use this to trigger Data()/parseRELA IO errors
	// without breaking debug/elf's initial parse.
	claimedSize uint64
}

type elfBuilder struct {
	machine  elf.Machine
	sections []elfBuilderSec
}

// build emits a minimal-but-valid ELF64 LSB relocatable from the
// recipe, suitable for round-tripping through readELFObject. It does
// not produce a real .symtab — tests that need symbols build them via
// buildSyntheticELF + extra section recipes.
func (b elfBuilder) build(t *testing.T) []byte {
	t.Helper()
	// Layout: header (64 bytes), then sections data, then section headers.
	const hdrSize = 64
	const shentsize = 64
	// Always include a SHT_NULL header at index 0 + a .shstrtab.
	nSec := 1 + len(b.sections) + 1 // null + custom + shstrtab
	// Build shstrtab.
	shstrtab := []byte{0}
	type secInfo struct {
		nameOff   uint32
		dataStart uint64
		dataLen   uint64
	}
	infos := make([]secInfo, len(b.sections))
	for i, s := range b.sections {
		infos[i].nameOff = uint32(len(shstrtab))
		shstrtab = append(shstrtab, []byte(s.name)...)
		shstrtab = append(shstrtab, 0)
	}
	shstrtabOff := uint32(len(shstrtab))
	shstrtab = append(shstrtab, []byte(".shstrtab")...)
	shstrtab = append(shstrtab, 0)

	// Place section data after the header, in order.
	cursor := uint64(hdrSize)
	for i, s := range b.sections {
		infos[i].dataStart = cursor
		infos[i].dataLen = uint64(len(s.data))
		cursor += uint64(len(s.data))
	}
	shstrtabStart := cursor
	cursor += uint64(len(shstrtab))
	shtOffset := cursor

	total := shtOffset + uint64(nSec)*shentsize
	buf := make([]byte, total)

	// e_ident
	copy(buf[0:4], []byte{0x7F, 'E', 'L', 'F'})
	buf[4] = byte(elf.ELFCLASS64)
	buf[5] = byte(elf.ELFDATA2LSB)
	buf[6] = byte(elf.EV_CURRENT)
	// e_type
	bo := binary.LittleEndian
	bo.PutUint16(buf[16:], uint16(elf.ET_REL))
	bo.PutUint16(buf[18:], uint16(b.machine))
	bo.PutUint32(buf[20:], uint32(elf.EV_CURRENT))
	// e_phoff = 0
	bo.PutUint64(buf[40:], shtOffset)
	bo.PutUint16(buf[52:], hdrSize)
	// e_phentsize, e_phnum left zero
	bo.PutUint16(buf[58:], shentsize)
	bo.PutUint16(buf[60:], uint16(nSec))
	bo.PutUint16(buf[62:], uint16(nSec-1)) // shstrndx → last section

	// Section data
	for i, s := range b.sections {
		copy(buf[infos[i].dataStart:], s.data)
	}
	copy(buf[shstrtabStart:], shstrtab)

	// Section headers
	writeSH := func(idx int, nameOff uint32, typ elf.SectionType, flags elf.SectionFlag, off, size uint64, link, info uint32, entsize uint64) {
		base := shtOffset + uint64(idx)*shentsize
		bo.PutUint32(buf[base:], nameOff)
		bo.PutUint32(buf[base+4:], uint32(typ))
		bo.PutUint64(buf[base+8:], uint64(flags))
		// addr (16) = 0
		bo.PutUint64(buf[base+24:], off)
		bo.PutUint64(buf[base+32:], size)
		bo.PutUint32(buf[base+40:], link)
		bo.PutUint32(buf[base+44:], info)
		// addralign (48) = 0
		bo.PutUint64(buf[base+56:], entsize)
	}
	// SHT_NULL at index 0
	writeSH(0, 0, elf.SHT_NULL, 0, 0, 0, 0, 0, 0)
	// User sections at 1..N
	for i, s := range b.sections {
		size := infos[i].dataLen
		if s.claimedSize != 0 {
			size = s.claimedSize
		}
		writeSH(i+1, infos[i].nameOff, s.typ, s.flags, infos[i].dataStart, size, s.link, s.info, s.entsize)
	}
	// .shstrtab at last index
	writeSH(nSec-1, shstrtabOff, elf.SHT_STRTAB, 0, shstrtabStart, uint64(len(shstrtab)), 0, 0, 0)
	return buf
}

func buildSyntheticELF(t *testing.T, typ elf.Type, machine elf.Machine, sections []elfBuilderSec, _ any) []byte {
	t.Helper()
	b := elfBuilder{machine: machine, sections: sections}
	buf := b.build(t)
	// Override e_type since elfBuilder hard-codes ET_REL.
	binary.LittleEndian.PutUint16(buf[16:], uint16(typ))
	return buf
}

// --- Tiny synthetic ELF round-trip --------------------------------------------

func TestReadELFObject_TinySynthetic(t *testing.T) {
	// One .text + one BSS section. Verifies basic reading and section
	// classification without needing a real fixture.
	b := elfBuilder{
		machine: elf.EM_X86_64,
		sections: []elfBuilderSec{
			{name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, data: []byte{0x90, 0x90, 0x90, 0x90}},
			{name: ".bss", typ: elf.SHT_NOBITS, flags: elf.SHF_ALLOC | elf.SHF_WRITE, data: bytes.Repeat([]byte{0}, 0x10)},
		},
	}
	buf := b.build(t)
	o, err := ReadObject(bytes.NewReader(buf), "tiny.o")
	if err != nil {
		t.Fatal(err)
	}
	if o.Machine != MachineAMD64 {
		t.Errorf("Machine = 0x%x", o.Machine)
	}
	var sawText, sawBSS bool
	for _, s := range o.Sections {
		switch s.Name {
		case ".text":
			sawText = true
		case ".bss":
			sawBSS = true
			if s.Data != nil {
				t.Errorf(".bss should have nil Data")
			}
		}
	}
	if !sawText || !sawBSS {
		t.Errorf("missing sections: text=%v bss=%v", sawText, sawBSS)
	}
}
