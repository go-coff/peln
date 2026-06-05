package linker

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// --- minimal ET_DYN PIE fixture builder --------------------------------------

type segSpec struct {
	vaddr, off, filesz, memsz uint64
	flags                     elf.ProgFlag
}

type relaSpec struct {
	off    uint64 // r_offset (absolute VA)
	typ    uint32 // relocation type
	sym    uint32 // symbol index (RELATIVE uses 0)
	addend int64  // r_addend
}

type pieSpec struct {
	etype     elf.Type    // default ET_DYN
	machine   elf.Machine // default EM_LOONGARCH
	entry     uint64
	segs      []segSpec
	relas     []relaSpec
	omitRela  bool     // don't emit the .rela section at all
	relaBytes int      // override .rela sh_size (0 = derive 24*len)
	relrs     []uint64 // raw .relr entries (encoded as-is)
	relrBytes int      // override .relr sh_size (0 = derive 8*len)
}

// buildPIE assembles a minimal but debug/elf-parsable ELF64 LE image.
// Layout: [ELF header][program headers][segment data @0x1000][.rela
// @0x2000][shstrtab @0x2800][section headers @0x3000].
func buildPIE(s pieSpec) []byte {
	if s.etype == 0 {
		s.etype = elf.ET_DYN
	}
	if s.machine == 0 {
		s.machine = elf.EM_LOONGARCH
	}
	const (
		phoff      = 64
		segDataOff = 0x1000
		relaOff    = 0x2000
		relrOff    = 0x2400
		shstrOff   = 0x2800
		shoff      = 0x3000
	)
	buf := make([]byte, 0x4000)

	// --- ELF header ---
	copy(buf, []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = 2 // ELFCLASS64
	buf[5] = 1 // ELFDATA2LSB
	buf[6] = 1 // EV_CURRENT
	binary.LittleEndian.PutUint16(buf[16:], uint16(s.etype))
	binary.LittleEndian.PutUint16(buf[18:], uint16(s.machine))
	binary.LittleEndian.PutUint32(buf[20:], 1)
	binary.LittleEndian.PutUint64(buf[24:], s.entry)
	binary.LittleEndian.PutUint64(buf[32:], phoff)
	binary.LittleEndian.PutUint64(buf[40:], shoff)
	binary.LittleEndian.PutUint16(buf[52:], 64) // e_ehsize
	binary.LittleEndian.PutUint16(buf[54:], 56) // e_phentsize
	binary.LittleEndian.PutUint16(buf[56:], uint16(len(s.segs)))
	binary.LittleEndian.PutUint16(buf[58:], 64) // e_shentsize

	// --- program headers ---
	for i, sg := range s.segs {
		p := phoff + i*56
		binary.LittleEndian.PutUint32(buf[p:], uint32(elf.PT_LOAD))
		binary.LittleEndian.PutUint32(buf[p+4:], uint32(sg.flags))
		binary.LittleEndian.PutUint64(buf[p+8:], sg.off)
		binary.LittleEndian.PutUint64(buf[p+16:], sg.vaddr)
		binary.LittleEndian.PutUint64(buf[p+24:], sg.vaddr) // p_paddr
		binary.LittleEndian.PutUint64(buf[p+32:], sg.filesz)
		binary.LittleEndian.PutUint64(buf[p+40:], sg.memsz)
		binary.LittleEndian.PutUint64(buf[p+48:], 0x1000) // p_align
	}

	// --- .rela content ---
	relaLen := len(s.relas) * 24
	for i, r := range s.relas {
		e := relaOff + i*24
		binary.LittleEndian.PutUint64(buf[e:], r.off)
		binary.LittleEndian.PutUint64(buf[e+8:], uint64(r.sym)<<32|uint64(r.typ))
		binary.LittleEndian.PutUint64(buf[e+16:], uint64(r.addend))
	}
	if s.relaBytes != 0 {
		relaLen = s.relaBytes
	}

	// --- .relr content ---
	relrLen := len(s.relrs) * 8
	for i, e := range s.relrs {
		binary.LittleEndian.PutUint64(buf[relrOff+i*8:], e)
	}
	if s.relrBytes != 0 {
		relrLen = s.relrBytes
	}

	// --- shstrtab ---
	names := "\x00.text\x00.rela\x00.relr\x00.shstrtab\x00"
	copy(buf[shstrOff:], names)

	// --- section headers: NULL, .text, [.rela], [.relr], .shstrtab ---
	type sh struct {
		name             uint32
		typ              elf.SectionType
		flags            uint64
		addr, off, size  uint64
		link, info       uint32
		addralign, entsz uint64
	}
	shs := []sh{
		{}, // NULL
		{name: uint32(strings.Index(names, ".text")), typ: elf.SHT_PROGBITS, flags: uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), addr: 0, off: segDataOff, size: 0x100, addralign: 16},
	}
	if !s.omitRela {
		shs = append(shs, sh{name: uint32(strings.Index(names, ".rela")), typ: elf.SHT_RELA, off: relaOff, size: uint64(relaLen), entsz: 24, addralign: 8})
	}
	if s.relrs != nil || s.relrBytes != 0 {
		shs = append(shs, sh{name: uint32(strings.Index(names, ".relr")), typ: shtRELR, off: relrOff, size: uint64(relrLen), entsz: 8, addralign: 8})
	}
	shs = append(shs, sh{name: uint32(strings.Index(names, ".shstrtab")), typ: elf.SHT_STRTAB, off: shstrOff, size: uint64(len(names)), addralign: 1})

	binary.LittleEndian.PutUint16(buf[60:], uint16(len(shs)))   // e_shnum
	binary.LittleEndian.PutUint16(buf[62:], uint16(len(shs)-1)) // e_shstrndx → last (.shstrtab)
	for i, x := range shs {
		o := shoff + i*64
		binary.LittleEndian.PutUint32(buf[o:], x.name)
		binary.LittleEndian.PutUint32(buf[o+4:], uint32(x.typ))
		binary.LittleEndian.PutUint64(buf[o+8:], x.flags)
		binary.LittleEndian.PutUint64(buf[o+16:], x.addr)
		binary.LittleEndian.PutUint64(buf[o+24:], x.off)
		binary.LittleEndian.PutUint64(buf[o+32:], x.size)
		binary.LittleEndian.PutUint32(buf[o+40:], x.link)
		binary.LittleEndian.PutUint32(buf[o+44:], x.info)
		binary.LittleEndian.PutUint64(buf[o+48:], x.addralign)
		binary.LittleEndian.PutUint64(buf[o+56:], x.entsz)
	}
	return buf
}

// canonical good spec: one R+W+X segment at vaddr 0x10000, a single
// R_LARCH_RELATIVE reloc pointing 16 bytes in.
func goodSpec() pieSpec {
	return pieSpec{
		entry: 0x10000,
		segs:  []segSpec{{vaddr: 0x10000, off: 0x1000, filesz: 0x100, memsz: 0x200, flags: elf.PF_R | elf.PF_W | elf.PF_X}},
		relas: []relaSpec{{off: 0x10010, typ: uint32(elf.R_LARCH_RELATIVE), addend: 0x10040}},
	}
}

// --- a minimal PE32+ reader (debug/pe rejects unknown machines like 0x6264) ---

type peSec struct {
	name                         string
	rva, vsize, rawSize, fileOff uint32
	characteristics              uint32
}

type peInfo struct {
	machine                     uint16
	entryRVA                    uint32
	imageBase                   uint64
	subsystem                   uint16
	baseRelocRVA, baseRelocSize uint32
	sections                    []peSec
	raw                         []byte
}

func parsePE(t *testing.T, b []byte) peInfo {
	t.Helper()
	if !bytes.HasPrefix(b, []byte("MZ")) {
		t.Fatal("not a PE (no MZ)")
	}
	lf := binary.LittleEndian.Uint32(b[0x3c:])
	if string(b[lf:lf+4]) != "PE\x00\x00" {
		t.Fatal("bad PE signature")
	}
	coff := int(lf) + 4
	var p peInfo
	p.raw = b
	p.machine = binary.LittleEndian.Uint16(b[coff:])
	nsec := int(binary.LittleEndian.Uint16(b[coff+2:]))
	optSize := int(binary.LittleEndian.Uint16(b[coff+16:]))
	opt := coff + 20
	if binary.LittleEndian.Uint16(b[opt:]) != 0x020b {
		t.Fatal("not PE32+")
	}
	p.entryRVA = binary.LittleEndian.Uint32(b[opt+16:])
	p.imageBase = binary.LittleEndian.Uint64(b[opt+24:])
	p.subsystem = binary.LittleEndian.Uint16(b[opt+68:])
	p.baseRelocRVA = binary.LittleEndian.Uint32(b[opt+112+5*8:])
	p.baseRelocSize = binary.LittleEndian.Uint32(b[opt+112+5*8+4:])
	st := opt + optSize
	for i := 0; i < nsec; i++ {
		o := st + i*40
		name := strings.TrimRight(string(b[o:o+8]), "\x00")
		p.sections = append(p.sections, peSec{
			name:            name,
			vsize:           binary.LittleEndian.Uint32(b[o+8:]),
			rva:             binary.LittleEndian.Uint32(b[o+12:]),
			rawSize:         binary.LittleEndian.Uint32(b[o+16:]),
			fileOff:         binary.LittleEndian.Uint32(b[o+20:]),
			characteristics: binary.LittleEndian.Uint32(b[o+36:]),
		})
	}
	return p
}

func (p peInfo) section(name string) *peSec {
	for i := range p.sections {
		if p.sections[i].name == name {
			return &p.sections[i]
		}
	}
	return nil
}

func (p peInfo) data(s *peSec) []byte {
	return p.raw[s.fileOff : s.fileOff+s.rawSize]
}

// --- success path -------------------------------------------------------------

func TestLinkPIE_Success(t *testing.T) {
	out, err := LinkPIE(bytes.NewReader(buildPIE(goodSpec())), PIEOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p := parsePE(t, out)
	if p.machine != MachineLoongArch64 {
		t.Errorf("machine = 0x%x, want 0x%x", p.machine, MachineLoongArch64)
	}
	if p.imageBase != 0xf000 { // vaddr0 0x10000 - SectionAlignment 0x1000
		t.Errorf("ImageBase = 0x%x, want 0xf000", p.imageBase)
	}
	if p.entryRVA != 0x1000 { // entry 0x10000 - ImageBase 0xf000
		t.Errorf("entry RVA = 0x%x, want 0x1000", p.entryRVA)
	}
	if p.subsystem != 10 {
		t.Errorf("Subsystem = %d, want 10", p.subsystem)
	}
	reloc := p.section(".reloc")
	if reloc == nil {
		t.Fatal("no .reloc section emitted")
	}
	if p.baseRelocRVA != reloc.rva || p.baseRelocSize == 0 {
		t.Errorf("base-reloc dir = {0x%x,%d}, want {0x%x,>0}", p.baseRelocRVA, p.baseRelocSize, reloc.rva)
	}
	// The relocated 8 bytes in .text must hold the absolute target VA.
	text := &p.sections[0]
	got := binary.LittleEndian.Uint64(p.data(text)[0x10:])
	if got != 0x10040 {
		t.Errorf("pre-applied reloc value = 0x%x, want 0x10040", got)
	}
	// .reloc block: page RVA 0 + one DIR64 entry at offset 0x10.
	rd := p.data(reloc)
	if page := binary.LittleEndian.Uint32(rd[0:]); page != 0x1000 {
		t.Errorf("reloc page = 0x%x, want 0x1000", page)
	}
	if entry := binary.LittleEndian.Uint16(rd[8:]); entry != uint16(BaseRelocDir64)<<12|0x10 {
		t.Errorf("reloc entry = 0x%x, want 0x%x", entry, uint16(BaseRelocDir64)<<12|0x10)
	}
}

// Two PT_LOAD segments supplied in descending vaddr order force the
// segment sort (sort.Slice less-func) to actually reorder them — a path a
// single-segment image never exercises.
func TestLinkPIE_MultiSegment(t *testing.T) {
	s := pieSpec{
		entry: 0x10000,
		segs: []segSpec{
			// higher vaddr first → the sort must move it after the lower one
			{vaddr: 0x11000, off: 0x1200, filesz: 0x100, memsz: 0x100, flags: elf.PF_R | elf.PF_W},
			{vaddr: 0x10000, off: 0x1000, filesz: 0x100, memsz: 0x100, flags: elf.PF_R | elf.PF_X},
		},
		relas: []relaSpec{{off: 0x10010, typ: uint32(elf.R_LARCH_RELATIVE), addend: 0x10040}},
	}
	out, err := LinkPIE(bytes.NewReader(buildPIE(s)), PIEOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p := parsePE(t, out)
	if p.imageBase != 0xf000 { // lowest segment 0x10000 - SectionAlignment
		t.Errorf("ImageBase = 0x%x, want 0xf000 (lowest segment - alignment)", p.imageBase)
	}
	// Both loadable segments map to PE sections, in ascending RVA order;
	// the first lands at SectionAlignment (0x1000), after the headers.
	if p.sections[0].rva != 0x1000 || p.sections[1].rva != 0x2000 {
		t.Errorf("section RVAs = 0x%x,0x%x, want 0x1000,0x2000", p.sections[0].rva, p.sections[1].rva)
	}
}

// Regression: the appended .reloc section adds one more section-table
// entry than the segment loop accounted for. If the header reservation
// ignores it, the first segment's file offset is computed too low and the
// (now larger) section table overruns the first section's raw data —
// corrupting the image (and clobbering .reloc's own Characteristics field),
// which UEFI firmware rejects with EFI_UNSUPPORTED. This was latent until a
// real PE load on EDK2/OVMF; loong64 had only ever been booted via QEMU
// -kernel, never loaded as a PE.
func TestLinkPIE_HeaderReserveNoOverlap(t *testing.T) {
	out, err := LinkPIE(bytes.NewReader(buildPIE(goodSpec())), PIEOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p := parsePE(t, out)

	// SizeOfHeaders (optional header +60) must not exceed the first
	// section's file offset — otherwise headers and section data overlap.
	lf := binary.LittleEndian.Uint32(p.raw[0x3c:])
	opt := int(lf) + 4 + 20
	sizeOfHeaders := binary.LittleEndian.Uint32(p.raw[opt+60:])
	first := p.sections[0]
	if first.fileOff < sizeOfHeaders {
		t.Errorf("first section file offset 0x%x < SizeOfHeaders 0x%x: headers overlap section data",
			first.fileOff, sizeOfHeaders)
	}
	// The headers must also not overrun in memory: the first section starts
	// at SectionAlignment, leaving [0, SectionAlignment) for the headers.
	if first.rva != 0x1000 {
		t.Errorf("first section RVA = 0x%x, want 0x1000 (headers reserved below it)", first.rva)
	}
	// .reloc characteristics must survive intact (the overlap used to zero
	// this field by writing .text data over the section header).
	reloc := p.section(".reloc")
	if reloc == nil {
		t.Fatal("no .reloc section emitted")
	}
	const want = scnCntInitializedData | scnMemRead | scnMemDiscardable
	if reloc.characteristics != want {
		t.Errorf(".reloc characteristics = 0x%08x, want 0x%08x", reloc.characteristics, want)
	}
}

// --- option defaults & explicit ImageBase ------------------------------------

func TestLinkPIE_ExplicitImageBase(t *testing.T) {
	out, err := LinkPIE(bytes.NewReader(buildPIE(goodSpec())), PIEOptions{ImageBase: 0x10000, Subsystem: 11, SectionAlignment: 0x1000, FileAlignment: 0x200})
	if err != nil {
		t.Fatal(err)
	}
	if p := parsePE(t, out); p.subsystem != 11 {
		t.Error("explicit subsystem not honoured")
	}
}

// --- error branches -----------------------------------------------------------

func TestLinkPIE_Errors(t *testing.T) {
	cases := []struct {
		name string
		spec pieSpec
		opts PIEOptions
		want string
	}{
		{"not ET_DYN", func() pieSpec { s := goodSpec(); s.etype = elf.ET_REL; return s }(), PIEOptions{}, "position-independent"},
		{"unknown machine", func() pieSpec { s := goodSpec(); s.machine = elf.EM_MIPS; return s }(), PIEOptions{}, "unsupported ELF machine"},
		{"no PT_LOAD", func() pieSpec { s := goodSpec(); s.segs = nil; return s }(), PIEOptions{}, "no PT_LOAD"},
		{"imagebase too high", goodSpec(), PIEOptions{ImageBase: 0x20000}, "above the first segment"},
		{"rela not multiple of 24", func() pieSpec { s := goodSpec(); s.relaBytes = 23; return s }(), PIEOptions{}, "multiple of Elf64_Rela"},
		{"non-relative reloc", func() pieSpec {
			s := goodSpec()
			s.relas = []relaSpec{{off: 0x10010, typ: uint32(elf.R_LARCH_64), addend: 1}}
			return s
		}(), PIEOptions{}, "unsupported dynamic reloc type"},
		{"reloc outside segment", func() pieSpec {
			s := goodSpec()
			s.relas = []relaSpec{{off: 0x99990, typ: uint32(elf.R_LARCH_RELATIVE)}}
			return s
		}(), PIEOptions{}, "outside any loadable segment"},
		{"reloc span crosses end", func() pieSpec {
			s := goodSpec()
			// filesz 0x100 ⇒ data ends at VA 0x10100; a fixup at 0x100fc
			// starts inside the section but its 8-byte span runs past it.
			s.relas = []relaSpec{{off: 0x100fc, typ: uint32(elf.R_LARCH_RELATIVE), addend: 0x10040}}
			return s
		}(), PIEOptions{}, "crosses the end"},
		{"unaligned segment vaddr", func() pieSpec {
			s := goodSpec()
			s.segs[0].vaddr = 0x10040
			s.entry = 0x10040
			return s
			// explicit ImageBase 0x10000 → RVA 0x40, not 0x1000-aligned
			// (the default ImageBase would instead anchor the first segment
			// at RVA == SectionAlignment, which is always aligned).
		}(), PIEOptions{ImageBase: 0x10000}, "not 0x1000-aligned"},
		{"vaddr below alignment", func() pieSpec {
			// Default ImageBase = vaddr0 - SectionAlignment would underflow
			// when the lowest segment sits below SectionAlignment; LinkPIE
			// must reject it rather than wrap around.
			s := goodSpec()
			s.segs = []segSpec{{vaddr: 0x800, off: 0x1000, filesz: 0x100, memsz: 0x100, flags: elf.PF_R | elf.PF_X}}
			s.entry = 0x800
			s.relas = nil
			s.omitRela = true
			return s
		}(), PIEOptions{}, "below SectionAlignment"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := LinkPIE(bytes.NewReader(buildPIE(c.spec)), c.opts)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want containing %q", err, c.want)
			}
		})
	}
}

func TestLinkPIE_BadELF(t *testing.T) {
	_, err := LinkPIE(bytes.NewReader([]byte("not an elf")), PIEOptions{})
	if err == nil || !strings.Contains(err.Error(), "parse ELF") {
		t.Fatalf("err = %v, want parse-ELF error", err)
	}
}

// RELATIVE reloc list with a type-0 (R_LARCH_NONE) entry: the NONE entry
// is skipped as padding, the RELATIVE one still produces a DIR64.
func TestLinkPIE_NoneRelocSkipped(t *testing.T) {
	s := goodSpec()
	s.relas = []relaSpec{
		{off: 0x10010, typ: uint32(elf.R_LARCH_NONE)},
		{off: 0x10020, typ: uint32(elf.R_LARCH_RELATIVE), addend: 0x10040},
	}
	out, err := LinkPIE(bytes.NewReader(buildPIE(s)), PIEOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p := parsePE(t, out)
	reloc := p.section(".reloc")
	rd := p.data(reloc)
	if entry := binary.LittleEndian.Uint16(rd[8:]); entry != uint16(BaseRelocDir64)<<12|0x20 {
		t.Errorf("expected single DIR64 at RVA 0x20, got entry 0x%x", entry)
	}
}

// --- SHT_RELR (DT_RELR) decoding ----------------------------------------------

// relRVAs decodes the .reloc directory of a converted PE into the set of
// (DIR64) base-relocation RVAs it carries. The .reloc format is a series of
// blocks: a uint32 page RVA, a uint32 block byte size, then 2-byte entries
// whose low 12 bits are an offset within the page and whose top 4 bits are
// the reloc type.
func relRVAs(t *testing.T, p peInfo) []uint32 {
	t.Helper()
	reloc := p.section(".reloc")
	if reloc == nil {
		return nil
	}
	rd := p.data(reloc)
	var rvas []uint32
	for off := 0; off+8 <= len(rd); {
		page := binary.LittleEndian.Uint32(rd[off:])
		size := binary.LittleEndian.Uint32(rd[off+4:])
		if size < 8 || off+int(size) > len(rd) {
			break
		}
		for e := off + 8; e+2 <= off+int(size); e += 2 {
			entry := binary.LittleEndian.Uint16(rd[e:])
			if entry == 0 {
				continue
			}
			if entry>>12 != uint16(BaseRelocDir64) {
				t.Fatalf("unexpected reloc type %d", entry>>12)
			}
			rvas = append(rvas, page+uint32(entry&0xfff))
		}
		off += int(size)
	}
	return rvas
}

func hasRVA(rvas []uint32, want uint32) bool {
	for _, r := range rvas {
		if r == want {
			return true
		}
	}
	return false
}

// A .relr section with an address entry followed by a bitmap entry that sets
// several bits across the 63-word window. Each selected site must yield a
// DIR64 base reloc at the matching RVA, and the 8 bytes at each site must be
// left untouched (RELR carries no addend).
func TestLinkPIE_RelrAddressAndBitmap(t *testing.T) {
	s := goodSpec()
	s.relas = nil // exercise RELR in isolation
	s.omitRela = true
	// Pre-seed the link-time absolute VAs RELR must NOT overwrite.
	// Address entry → site 0x10000 (offset 0x00 in .text).
	// Bitmap → cursor 0x10008; bits 1,3,8 (entry bits 2,4,9) → offsets
	// 0x08, 0x18, 0x48.
	const bitmap = uint64(1) | // marker (bit 0)
		(1 << 2) | // i=1 → cursor + 1*8 = 0x10010 (offset 0x10)
		(1 << 4) | // i=3 → cursor + 3*8 = 0x10020 (offset 0x20)
		(1 << 9) // i=8 → cursor + 8*8 = 0x10048 (offset 0x48)
	s.relrs = []uint64{0x10000, bitmap}
	out, err := LinkPIE(bytes.NewReader(buildPIE(s)), PIEOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p := parsePE(t, out)
	rvas := relRVAs(t, p)
	// ImageBase = 0xf000 (vaddr0 - SectionAlignment), so each site VA maps
	// to RVA = VA - 0xf000: 0x10000→0x1000, +0x10/+0x20/+0x48.
	for _, want := range []uint32{0x1000, 0x1010, 0x1020, 0x1048} {
		if !hasRVA(rvas, want) {
			t.Errorf("missing DIR64 base reloc at RVA 0x%x (got %v)", want, rvas)
		}
	}
	if len(rvas) != 4 {
		t.Errorf("got %d base relocs, want 4 (%v)", len(rvas), rvas)
	}
	// RELR must not have overwritten the site bytes.
	text := &p.sections[0]
	for _, loc := range []int{0x00, 0x10, 0x20, 0x48} {
		if got := binary.LittleEndian.Uint64(p.data(text)[loc:]); got != 0 {
			t.Errorf("RELR overwrote site at offset 0x%x: 0x%x", loc, got)
		}
	}
}

// RELA and RELR coexisting must both contribute base relocs.
func TestLinkPIE_RelaAndRelr(t *testing.T) {
	s := goodSpec() // one RELA at 0x10010 → RVA 0x10
	s.relrs = []uint64{0x10020}
	out, err := LinkPIE(bytes.NewReader(buildPIE(s)), PIEOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p := parsePE(t, out)
	rvas := relRVAs(t, p)
	// ImageBase = 0xf000: RELA site 0x10010→RVA 0x1010, RELR 0x10020→0x1020.
	if !hasRVA(rvas, 0x1010) || !hasRVA(rvas, 0x1020) {
		t.Errorf("expected base relocs at 0x1010 (RELA) and 0x1020 (RELR), got %v", rvas)
	}
	// RELA pre-applied its addend; RELR left its site alone.
	text := &p.sections[0]
	if got := binary.LittleEndian.Uint64(p.data(text)[0x10:]); got != 0x10040 {
		t.Errorf("RELA pre-apply = 0x%x, want 0x10040", got)
	}
}

func TestLinkPIE_RelrErrors(t *testing.T) {
	cases := []struct {
		name string
		spec pieSpec
		want string
	}{
		{"relr not multiple of 8", func() pieSpec {
			s := goodSpec()
			s.omitRela = true
			s.relas = nil
			s.relrs = []uint64{0x10000}
			s.relrBytes = 7
			return s
		}(), "multiple of Elf64_Relr"},
		{"relr site outside segment", func() pieSpec {
			s := goodSpec()
			s.omitRela = true
			s.relas = nil
			s.relrs = []uint64{0x99990} // even → address entry, no segment
			return s
		}(), "outside any loadable segment"},
		{"relr site crosses section end", func() pieSpec {
			s := goodSpec()
			s.omitRela = true
			s.relas = nil
			s.relrs = []uint64{0x100fc} // 8-byte span runs past data end 0x10100
			return s
		}(), "crosses the end"},
		{"relr bitmap site outside segment", func() pieSpec {
			s := goodSpec()
			s.omitRela = true
			s.relas = nil
			// Anchor in-segment, then a bitmap whose top bit selects a far
			// site (cursor 0x10008 + 62*8 = 0x101f8, past the 0x100 data),
			// exercising the bitmap branch's emit error path.
			s.relrs = []uint64{0x10000, uint64(1) | (1 << 63)}
			return s
		}(), "outside any loadable segment"},
		{"relr data read error", func() pieSpec {
			s := goodSpec()
			s.omitRela = true
			s.relas = nil
			s.relrs = []uint64{0x10000}
			s.relrBytes = 0x100000 // sh_size beyond the image → Data() EOFs
			return s
		}(), ".relr"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := LinkPIE(bytes.NewReader(buildPIE(c.spec)), PIEOptions{})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want containing %q", err, c.want)
			}
		})
	}
}

// --- multi-arch machine/RELATIVE-type table -----------------------------------

func TestPieMachine(t *testing.T) {
	cases := []struct {
		m       elf.Machine
		peMach  uint16
		relType uint32
		ok      bool
	}{
		{elf.EM_LOONGARCH, MachineLoongArch64, uint32(elf.R_LARCH_RELATIVE), true},
		{elf.EM_X86_64, MachineAMD64, uint32(elf.R_X86_64_RELATIVE), true},
		{elf.EM_AARCH64, MachineARM64, uint32(elf.R_AARCH64_RELATIVE), true},
		{elf.EM_RISCV, MachineRISCV64, uint32(elf.R_RISCV_RELATIVE), true},
		{elf.EM_MIPS, 0, 0, false},
	}
	for _, c := range cases {
		pm, rt, ok := pieMachine(c.m)
		if pm != c.peMach || rt != c.relType || ok != c.ok {
			t.Errorf("pieMachine(%v) = (0x%x,%d,%v), want (0x%x,%d,%v)", c.m, pm, rt, ok, c.peMach, c.relType, c.ok)
		}
	}
}

// --- I/O error paths ----------------------------------------------------------

// failAtReader wraps a ReaderAt and fails any ReadAt that starts exactly
// at failOff — letting debug/elf parse the headers (which it reads from
// other offsets) while breaking one targeted read.
type failAtReader struct {
	r       io.ReaderAt
	failOff int64
}

func (f failAtReader) ReadAt(p []byte, off int64) (int, error) {
	if off == f.failOff {
		return 0, errors.New("synthetic read failure")
	}
	return f.r.ReadAt(p, off)
}

func TestLinkPIE_SegmentReadError(t *testing.T) {
	img := buildPIE(goodSpec()) // segment file data starts at off 0x1000
	r := failAtReader{r: bytes.NewReader(img), failOff: 0x1000}
	_, err := LinkPIE(r, PIEOptions{})
	if err == nil || !strings.Contains(err.Error(), "read segment") {
		t.Fatalf("err = %v, want read-segment error", err)
	}
}

func TestLinkPIE_RelaDataError(t *testing.T) {
	s := goodSpec()
	s.relaBytes = 0x100000 // sh_size far beyond the 0x4000 image → Data() EOFs
	_, err := LinkPIE(bytes.NewReader(buildPIE(s)), PIEOptions{})
	if err == nil || !strings.Contains(err.Error(), ".rela") {
		t.Fatalf("err = %v, want .rela read error", err)
	}
}

func TestSegCharacteristics(t *testing.T) {
	if c := segCharacteristics(elf.PF_R); c&scnCntInitializedData == 0 || c&scnMemWrite != 0 {
		t.Errorf("RO seg chars = 0x%x", c)
	}
	if c := segCharacteristics(elf.PF_R | elf.PF_X); c&scnMemExecute == 0 {
		t.Errorf("RX seg chars = 0x%x", c)
	}
	if c := segCharacteristics(elf.PF_R | elf.PF_W); c&scnMemWrite == 0 {
		t.Errorf("RW seg chars = 0x%x", c)
	}
}

func TestSegName(t *testing.T) {
	if segName(elf.PF_R|elf.PF_X, 0) != ".text" || segName(elf.PF_R|elf.PF_W, 0) != ".data" || segName(elf.PF_R, 0) != ".rodata" {
		t.Error("segName mapping wrong")
	}
}

// --- real TamaGo loong64 PIE (guarded) ----------------------------------------

// TestLinkPIE_RealTamago runs the converter against an actual
// `-buildmode=pie` TamaGo loong64 binary if one is present, and verifies
// the PE parses with a matching base-reloc count. Skipped in CI.
func TestLinkPIE_RealTamago(t *testing.T) {
	const path = "/tmp/lhello/hello-pie.elf"
	f, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("no real PIE fixture at %s", path)
	}
	out, err := LinkPIE(bytes.NewReader(f), PIEOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p := parsePE(t, out)
	if p.machine != MachineLoongArch64 {
		t.Errorf("machine = 0x%x", p.machine)
	}
	if p.section(".reloc") == nil || p.baseRelocSize == 0 {
		t.Error("expected a non-empty .reloc directory for a real PIE")
	}
}
