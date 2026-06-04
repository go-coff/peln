package linker

import (
	"debug/elf"
	"fmt"
	"io"
	"sort"
)

// PIEOptions controls LinkPIE. Sensible PE32+ EFI defaults apply when a
// field is zero.
type PIEOptions struct {
	Subsystem        uint16 // PE Subsystem; default 10 (EFI application)
	ImageBase        uint64 // default: lowest PT_LOAD p_vaddr floored to 64 KiB
	SectionAlignment uint32 // default 0x1000
	FileAlignment    uint32 // default 0x200
}

// LinkPIE converts an already-linked position-independent ELF executable
// into a PE32+/EFI image.
//
// Unlike Link, which merges relocatable ET_REL objects and resolves
// symbols, LinkPIE takes a single ET_DYN PIE whose every dynamic
// relocation is the architecture's RELATIVE type (e.g. R_LARCH_RELATIVE
// on loong64). Such an image is self-contained: there are no symbolic or
// GOT-via-symbol relocations to resolve, only "add the load bias to the
// 64-bit word at this offset" fixups. Those map one-to-one onto PE base
// relocations (IMAGE_REL_BASED_DIR64), so the conversion is:
//
//   - map each PT_LOAD segment to a PE section at RVA = p_vaddr-ImageBase,
//   - pre-apply each RELATIVE reloc by writing its absolute target VA
//     (the addend, which already encodes ImageBase+target_RVA) into the
//     image, and emit a DIR64 base reloc at the same RVA so the firmware
//     re-applies (actualBase-ImageBase) when it rebases the image,
//   - take the entry point from e_entry.
//
// This is the route for turning a TamaGo `-buildmode=pie` bare-metal Go
// binary into a UEFI .efi without an external linker.
func LinkPIE(r io.ReaderAt, opts PIEOptions) ([]byte, error) {
	ef, err := elf.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("parse ELF: %w", err)
	}
	if ef.Type != elf.ET_DYN {
		return nil, fmt.Errorf("LinkPIE requires a position-independent (ET_DYN) ELF, got %v", ef.Type)
	}
	machine, relType, ok := pieMachine(ef.Machine)
	if !ok {
		return nil, fmt.Errorf("unsupported ELF machine %v (no PE machine / RELATIVE reloc mapping)", ef.Machine)
	}

	if opts.Subsystem == 0 {
		opts.Subsystem = 10 // IMAGE_SUBSYSTEM_EFI_APPLICATION
	}
	if opts.SectionAlignment == 0 {
		opts.SectionAlignment = 0x1000
	}
	if opts.FileAlignment == 0 {
		opts.FileAlignment = 0x200
	}

	// Collect PT_LOAD segments in ascending vaddr order.
	var loads []*elf.Prog
	for _, p := range ef.Progs {
		if p.Type == elf.PT_LOAD && p.Memsz > 0 {
			loads = append(loads, p)
		}
	}
	if len(loads) == 0 {
		return nil, fmt.Errorf("no PT_LOAD segments")
	}
	sort.Slice(loads, func(i, j int) bool { return loads[i].Vaddr < loads[j].Vaddr })

	// ImageBase defaults to the lowest segment vaddr floored to 64 KiB so
	// every page-aligned p_vaddr yields a SectionAlignment-aligned RVA.
	if opts.ImageBase == 0 {
		opts.ImageBase = loads[0].Vaddr &^ 0xffff
	}
	if loads[0].Vaddr < opts.ImageBase {
		return nil, fmt.Errorf("ImageBase 0x%x is above the first segment vaddr 0x%x", opts.ImageBase, loads[0].Vaddr)
	}

	// Build one PE section per PT_LOAD, preserving the ELF memory layout
	// (RVA == p_vaddr-ImageBase) so internal pointers and relocations stay
	// valid. File offsets are assigned sequentially after the headers.
	headerTotal := 0x40 + 4 + 20 + 240 + 40*len(loads)
	foff := alignUp(uint32(headerTotal), opts.FileAlignment)
	out := make([]*MergedSection, 0, len(loads))
	for i, p := range loads {
		rva := uint32(p.Vaddr - opts.ImageBase)
		if rva%opts.SectionAlignment != 0 {
			return nil, fmt.Errorf("segment %d vaddr 0x%x not %#x-aligned relative to ImageBase", i, p.Vaddr, opts.SectionAlignment)
		}
		data := make([]byte, p.Filesz)
		if p.Filesz > 0 {
			if _, err := r.ReadAt(data, int64(p.Off)); err != nil {
				return nil, fmt.Errorf("read segment %d: %w", i, err)
			}
		}
		out = append(out, &MergedSection{
			Name:            segName(p.Flags, i),
			RVA:             rva,
			FileOffset:      foff,
			VirtualSize:     uint32(p.Memsz),
			RawSize:         alignUp(uint32(p.Filesz), opts.FileAlignment),
			Characteristics: segCharacteristics(p.Flags),
			Data:            data,
		})
		foff += alignUp(uint32(p.Filesz), opts.FileAlignment)
	}

	// Pre-apply RELATIVE relocations and collect the matching DIR64 base
	// relocations. Each entry stores its absolute target VA into the
	// image; the firmware then adds (actualBase-ImageBase) at load.
	baseRel, err := applyPIERelocs(ef, machine, relType, opts.ImageBase, out)
	if err != nil {
		return nil, err
	}

	layout := &Layout{
		Opts: LayoutOptions{
			ImageBase:        opts.ImageBase,
			SectionAlignment: opts.SectionAlignment,
			FileAlignment:    opts.FileAlignment,
			HeaderReserve:    alignUp(uint32(headerTotal), opts.FileAlignment),
		},
		Out: out,
	}
	if relocBytes := BuildRelocSection(baseRel); len(relocBytes) > 0 {
		appendRelocSection(layout, relocBytes)
	}

	entryRVA := uint32(ef.Entry - opts.ImageBase)
	linkOpts := LinkOptions{
		Machine:          machine,
		Subsystem:        opts.Subsystem,
		ImageBase:        opts.ImageBase,
		SectionAlignment: opts.SectionAlignment,
		FileAlignment:    opts.FileAlignment,
	}
	return emitPE(layout, linkOpts, entryRVA)
}

// pieMachine maps an ELF machine to its PE machine code and the
// architecture's RELATIVE dynamic relocation type, reporting whether the
// architecture is supported for PIE→PE conversion. A single switch keeps
// the two facts in lock-step (no second, unreachable guard).
func pieMachine(m elf.Machine) (peMachine uint16, relType uint32, ok bool) {
	switch m {
	case elf.EM_LOONGARCH:
		return MachineLoongArch64, uint32(elf.R_LARCH_RELATIVE), true
	case elf.EM_X86_64:
		return MachineAMD64, uint32(elf.R_X86_64_RELATIVE), true
	case elf.EM_AARCH64:
		return MachineARM64, uint32(elf.R_AARCH64_RELATIVE), true
	case elf.EM_RISCV:
		return MachineRISCV64, uint32(elf.R_RISCV_RELATIVE), true
	}
	return 0, 0, false
}

// shtRELR is SHT_RELR — a section of DT_RELR packed relative relocations.
// Some releases of debug/elf don't export it as a named constant, so it's
// defined locally (the on-disk value is fixed by the ELF gABI at 19).
const shtRELR elf.SectionType = 19

// applyPIERelocs walks every SHT_RELA section, pre-applies each RELATIVE
// reloc into the segment-backed section data, and returns the DIR64 base
// relocations. Any non-RELATIVE dynamic relocation is rejected — a
// self-contained PIE must not carry symbolic/GOT relocations.
func applyPIERelocs(ef *elf.File, machine uint16, relType uint32, imageBase uint64, out []*MergedSection) ([]BaseReloc, error) {
	var baseRel []BaseReloc
	for _, s := range ef.Sections {
		switch s.Type {
		case elf.SHT_RELA:
			rels, err := applyPIERela(ef, s, relType, imageBase, out)
			if err != nil {
				return nil, err
			}
			baseRel = append(baseRel, rels...)
		case shtRELR:
			rels, err := applyPIERelr(ef, s, imageBase, out)
			if err != nil {
				return nil, err
			}
			baseRel = append(baseRel, rels...)
		}
	}
	return baseRel, nil
}

// applyPIERela handles a single SHT_RELA section: it pre-applies each
// RELATIVE reloc and returns the matching DIR64 base relocations. Any
// non-RELATIVE dynamic relocation is rejected.
func applyPIERela(ef *elf.File, s *elf.Section, relType uint32, imageBase uint64, out []*MergedSection) ([]BaseReloc, error) {
	data, err := s.Data()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", s.Name, err)
	}
	if len(data)%24 != 0 {
		return nil, fmt.Errorf("%s size %d not a multiple of Elf64_Rela (24)", s.Name, len(data))
	}
	bo := ef.ByteOrder
	var baseRel []BaseReloc
	for off := 0; off < len(data); off += 24 {
		rOffset := bo.Uint64(data[off:])
		rInfo := bo.Uint64(data[off+8:])
		rAddend := int64(bo.Uint64(data[off+16:]))
		rt := uint32(rInfo & 0xffffffff)
		if rt == uint32(elf.R_LARCH_NONE) { // 0 across our arches: padding
			continue
		}
		if rt != relType {
			return nil, fmt.Errorf("%s: unsupported dynamic reloc type %d (only RELATIVE %d is supported for a static PIE)", s.Name, rt, relType)
		}
		sec := sectionForVA(out, imageBase, rOffset)
		if sec == nil {
			return nil, fmt.Errorf("RELATIVE reloc offset 0x%x falls outside any loadable segment's file data", rOffset)
		}
		loc := rOffset - (imageBase + uint64(sec.RVA))
		if loc+8 > uint64(len(sec.Data)) {
			return nil, fmt.Errorf("RELATIVE reloc offset 0x%x crosses the end of section %s", rOffset, sec.Name)
		}
		// Store the absolute preferred target VA (== addend); the PE
		// loader rebases it by (actualBase-ImageBase) via the DIR64
		// base reloc emitted below.
		bo.PutUint64(sec.Data[loc:], uint64(rAddend))
		baseRel = append(baseRel, BaseReloc{RVA: uint32(rOffset - imageBase), Type: BaseRelocDir64})
	}
	return baseRel, nil
}

// applyPIERelr decodes a single SHT_RELR (DT_RELR) section into DIR64 base
// relocations. RELR is a compact encoding of relative relocations: a stream
// of uint64 entries where an even entry is the address of a relocation site
// and an odd entry is a bitmap for the 63 words that follow the current
// cursor. Unlike RELA, RELR carries no addend — the link-time absolute VA is
// already stored at each site — so the 8 bytes there are left untouched.
func applyPIERelr(ef *elf.File, s *elf.Section, imageBase uint64, out []*MergedSection) ([]BaseReloc, error) {
	data, err := s.Data()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", s.Name, err)
	}
	if len(data)%8 != 0 {
		return nil, fmt.Errorf("%s size %d not a multiple of Elf64_Relr (8)", s.Name, len(data))
	}
	bo := ef.ByteOrder
	var baseRel []BaseReloc
	// emit resolves the section for a RELR site, bounds-checks its 8-byte
	// span (without overwriting it), and appends a DIR64 base reloc.
	emit := func(site uint64) error {
		sec := sectionForVA(out, imageBase, site)
		if sec == nil {
			return fmt.Errorf("RELR reloc offset 0x%x falls outside any loadable segment's file data", site)
		}
		loc := site - (imageBase + uint64(sec.RVA))
		if loc+8 > uint64(len(sec.Data)) {
			return fmt.Errorf("RELR reloc offset 0x%x crosses the end of section %s", site, sec.Name)
		}
		baseRel = append(baseRel, BaseReloc{RVA: uint32(site - imageBase), Type: BaseRelocDir64})
		return nil
	}
	var where uint64
	for off := 0; off < len(data); off += 8 {
		entry := bo.Uint64(data[off:])
		if entry&1 == 0 {
			// Address entry: relocate this site, advance past it.
			where = entry
			if err := emit(where); err != nil {
				return nil, err
			}
			where += 8
			continue
		}
		// Bitmap entry: bit 0 is the marker; bits 1..63 select the 63
		// words starting at the cursor.
		for i := 0; i < 63; i++ {
			if entry&(1<<uint(i+1)) != 0 {
				if err := emit(where + uint64(i)*8); err != nil {
					return nil, err
				}
			}
		}
		where += 63 * 8
	}
	return baseRel, nil
}

// sectionForVA returns the section whose file-backed data contains the
// absolute virtual address va, or nil. Only the file-backed range
// ([ImageBase+RVA, +len(Data))) is considered — BSS tail bytes beyond it
// are never relocation targets. The caller separately checks that the
// 8-byte fixup span fits.
func sectionForVA(out []*MergedSection, imageBase, va uint64) *MergedSection {
	for _, s := range out {
		start := imageBase + uint64(s.RVA)
		if va >= start && va < start+uint64(len(s.Data)) {
			return s
		}
	}
	return nil
}

// segName synthesises a PE section name from ELF segment flags.
func segName(flags elf.ProgFlag, idx int) string {
	switch {
	case flags&elf.PF_X != 0:
		return ".text"
	case flags&elf.PF_W != 0:
		return ".data"
	default:
		return ".rodata"
	}
}

// segCharacteristics maps ELF segment R/W/X flags to PE section
// characteristics.
func segCharacteristics(flags elf.ProgFlag) uint32 {
	ch := uint32(scnMemRead)
	if flags&elf.PF_X != 0 {
		ch |= scnCntCode | scnMemExecute
	} else {
		ch |= scnCntInitializedData
	}
	if flags&elf.PF_W != 0 {
		ch |= scnMemWrite
	}
	return ch
}
