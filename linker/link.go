package linker

import (
	"encoding/binary"
	"fmt"
)

// LinkOptions controls the top-level linker entry point. Sensible
// PE32+ EFI defaults are applied when fields are zero.
type LinkOptions struct {
	Machine         uint16 // required: MachineAMD64 / MachineARM64 / MachineRISCV64
	Entry           string // entry symbol name; default "_start"
	Subsystem       uint16 // PE Subsystem; default 10 (IMAGE_SUBSYSTEM_EFI_APPLICATION)
	ImageBase       uint64 // default 0x10000
	AllowUnresolved bool   // forward to Resolve; default false

	// Layout overrides (zero → ComputeLayout's defaults).
	SectionAlignment uint32
	FileAlignment    uint32
	HeaderReserve    uint32
}

// Link runs the full pipeline (resolve → layout → relocate → emit) and
// returns the bytes of a complete PE32+ EFI application. The caller
// writes the slice to disk; we do no IO ourselves.
func Link(objs []*Object, opts LinkOptions) ([]byte, error) {
	if len(objs) == 0 {
		return nil, fmt.Errorf("no input objects")
	}
	if opts.Machine == 0 {
		opts.Machine = objs[0].Machine
	}
	if opts.Entry == "" {
		opts.Entry = "_start"
	}
	if opts.Subsystem == 0 {
		opts.Subsystem = 10 // IMAGE_SUBSYSTEM_EFI_APPLICATION
	}
	if opts.ImageBase == 0 {
		opts.ImageBase = 0x10000
	}

	// 1) Resolve global symbols.
	tab, err := Resolve(objs, ResolveOptions{AllowUnresolved: opts.AllowUnresolved})
	if err != nil {
		return nil, err
	}

	// 2) Initial layout (without .reloc — we don't know its size yet).
	layout := ComputeLayout(objs, LayoutOptions{
		ImageBase:        opts.ImageBase,
		SectionAlignment: opts.SectionAlignment,
		FileAlignment:    opts.FileAlignment,
		HeaderReserve:    opts.HeaderReserve,
	})

	// 3) Apply relocations against this layout. The patch bytes get
	// rewritten in place on layout.Out[i].Data.
	baseRel, err := ApplyRelocations(objs, tab, layout)
	if err != nil {
		return nil, err
	}

	// 4) Synthesise the .reloc section from the absolute relocations.
	// We append it AFTER the initial layout so .reloc gets the next
	// free RVA + file offset, leaving every prior section untouched.
	if relocBytes := BuildRelocSection(baseRel); len(relocBytes) > 0 {
		appendRelocSection(layout, relocBytes)
	}

	// 5) Look up the entry symbol's final RVA.
	entryRVA, err := resolveEntryRVA(opts.Entry, tab, layout)
	if err != nil {
		return nil, err
	}

	// 6) Emit the PE32+ file.
	return emitPE(layout, opts, entryRVA)
}

// appendRelocSection installs a fresh .reloc MergedSection at the tail
// of layout.Out, with characteristics flagged read-only + discardable
// (the OS loader walks .reloc once then drops it).
func appendRelocSection(l *Layout, body []byte) {
	prev := l.Out[len(l.Out)-1]
	rva := alignUp(prev.RVA+prev.VirtualSize, l.Opts.SectionAlignment)
	foff := prev.FileOffset + prev.RawSize
	if foff%l.Opts.FileAlignment != 0 {
		foff = alignUp(foff, l.Opts.FileAlignment)
	}
	m := &MergedSection{
		Name:            ".reloc",
		RVA:             rva,
		FileOffset:      foff,
		VirtualSize:     uint32(len(body)),
		RawSize:         alignUp(uint32(len(body)), l.Opts.FileAlignment),
		Characteristics: scnCntInitializedData | scnMemRead | scnMemDiscardable,
		Data:            body,
	}
	l.Out = append(l.Out, m)
}

// resolveEntryRVA looks up the entry symbol in the global table and
// returns its final RVA. Errors with a clear message if the symbol is
// absent or absolute (an absolute entry point makes no sense for an
// EFI app).
func resolveEntryRVA(name string, tab *SymTab, l *Layout) (uint32, error) {
	r, ok := tab.Entries[name]
	if !ok {
		return 0, fmt.Errorf("entry symbol %q not found", name)
	}
	if r.Kind != SymDefined {
		return 0, fmt.Errorf("entry symbol %q is not section-defined (kind=%d)", name, r.Kind)
	}
	return l.ResolveRVA(r.Section, r.Offset), nil
}

// emitPE writes the final byte stream: DOS stub → PE signature →
// COFF header → optional header → section table → padding → section
// data. Field offsets follow PE/COFF Specification §3 (PE32+ variant
// throughout, since EFI requires it).
func emitPE(l *Layout, opts LinkOptions, entryRVA uint32) ([]byte, error) {
	const (
		dosHeaderSize  = 0x40
		peSigSize      = 4
		coffHeaderSize = 20
		optHeaderSize  = 240 // PE32+ (16 data directories × 8 bytes + 112 base)
		sectionEntry   = 40
		numDataDirs    = 16
	)
	headerTotal := dosHeaderSize + peSigSize + coffHeaderSize + optHeaderSize + sectionEntry*len(l.Out)
	sizeOfHeaders := alignUp(uint32(headerTotal), l.Opts.FileAlignment)
	// Respect the layout's HeaderReserve so any downstream appender.Append
	// has slack to extend the section table without re-laying-out the
	// whole image. The layout already placed the first section at
	// alignUp(HeaderReserve, FileAlignment); if we now declare a
	// smaller SizeOfHeaders the firmware would think the gap between
	// SizeOfHeaders and the first section is filler.
	if reserve := alignUp(l.Opts.HeaderReserve, l.Opts.FileAlignment); reserve > sizeOfHeaders {
		sizeOfHeaders = reserve
	}

	// Final file size = SizeOfHeaders + sum of RawSize for each section.
	fileSize := sizeOfHeaders
	for _, s := range l.Out {
		if s.RawSize > 0 {
			// We previously assigned s.FileOffset assuming SizeOfHeaders
			// matches HeaderReserve. Re-derive FileOffset from a running
			// pointer so we never leave gaps in the file.
			fileSize = s.FileOffset + s.RawSize
		}
	}
	if fileSize < sizeOfHeaders {
		fileSize = sizeOfHeaders
	}

	// SizeOfImage = section-aligned virtual end of the last section.
	var sizeOfImage uint32
	if len(l.Out) > 0 {
		last := l.Out[len(l.Out)-1]
		sizeOfImage = alignUp(last.RVA+last.VirtualSize, l.Opts.SectionAlignment)
	} else {
		sizeOfImage = alignUp(sizeOfHeaders, l.Opts.SectionAlignment)
	}

	buf := make([]byte, fileSize)

	// ----- DOS header -----
	buf[0], buf[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(buf[0x3C:], dosHeaderSize) // e_lfanew → PE signature

	// ----- PE signature -----
	off := dosHeaderSize
	copy(buf[off:], []byte("PE\x00\x00"))
	off += peSigSize

	// ----- COFF File Header -----
	// Machine
	binary.LittleEndian.PutUint16(buf[off:], opts.Machine)
	// NumberOfSections
	binary.LittleEndian.PutUint16(buf[off+2:], uint16(len(l.Out)))
	// TimeDateStamp (deterministic 0 for reproducible builds)
	// PointerToSymbolTable / NumberOfSymbols: 0 (we strip symbols)
	// SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(buf[off+16:], optHeaderSize)
	// Characteristics: IMAGE_FILE_EXECUTABLE_IMAGE (2) | IMAGE_FILE_LARGE_ADDRESS_AWARE (0x20)
	binary.LittleEndian.PutUint16(buf[off+18:], 0x0022)
	off += coffHeaderSize

	// ----- Optional Header (PE32+) -----
	opt := off
	// Magic = 0x20b for PE32+
	binary.LittleEndian.PutUint16(buf[opt+0:], 0x020b)
	// LinkerVersion (Major/Minor): 14.0 (cosmetic)
	buf[opt+2] = 14
	buf[opt+3] = 0

	var sizeOfCode, sizeOfInitData, sizeOfUninitData uint32
	var baseOfCode uint32
	for _, s := range l.Out {
		if s.Characteristics&scnMemExecute != 0 {
			sizeOfCode += s.RawSize
			if baseOfCode == 0 {
				baseOfCode = s.RVA
			}
		} else if s.Characteristics&scnCntUninitializedData != 0 {
			sizeOfUninitData += alignUp(s.VirtualSize, l.Opts.FileAlignment)
		} else {
			sizeOfInitData += s.RawSize
		}
	}
	binary.LittleEndian.PutUint32(buf[opt+4:], sizeOfCode)
	binary.LittleEndian.PutUint32(buf[opt+8:], sizeOfInitData)
	binary.LittleEndian.PutUint32(buf[opt+12:], sizeOfUninitData)
	binary.LittleEndian.PutUint32(buf[opt+16:], entryRVA)
	binary.LittleEndian.PutUint32(buf[opt+20:], baseOfCode)
	// PE32+ omits BaseOfData → ImageBase moves up to 0x18 and is 8 bytes.
	binary.LittleEndian.PutUint64(buf[opt+24:], opts.ImageBase)
	binary.LittleEndian.PutUint32(buf[opt+32:], l.Opts.SectionAlignment)
	binary.LittleEndian.PutUint32(buf[opt+36:], l.Opts.FileAlignment)
	// Major/Minor OS/Image/Subsystem versions: leave as zero except for a
	// plausible UEFI subsystem version (the firmware ignores most of it).
	binary.LittleEndian.PutUint16(buf[opt+48:], 0) // MajorSubsystemVersion
	binary.LittleEndian.PutUint16(buf[opt+50:], 0) // MinorSubsystemVersion
	// Win32VersionValue, reserved
	binary.LittleEndian.PutUint32(buf[opt+56:], sizeOfImage)
	binary.LittleEndian.PutUint32(buf[opt+60:], sizeOfHeaders)
	// CheckSum at +64 left as zero (firmware doesn't verify it)
	binary.LittleEndian.PutUint16(buf[opt+68:], opts.Subsystem)
	// DllCharacteristics at +70: leave 0
	// Stack/Heap reserve+commit at +72..+103. Use modest defaults — EFI
	// firmware otherwise gives us a 4 KiB stack which TinyGo's runtime
	// overflows.
	binary.LittleEndian.PutUint64(buf[opt+72:], 0x100000) // SizeOfStackReserve = 1 MiB
	binary.LittleEndian.PutUint64(buf[opt+80:], 0x100000) // SizeOfStackCommit
	binary.LittleEndian.PutUint64(buf[opt+88:], 0x100000) // SizeOfHeapReserve
	binary.LittleEndian.PutUint64(buf[opt+96:], 0x100000) // SizeOfHeapCommit
	// LoaderFlags +104 = 0
	// NumberOfRvaAndSizes +108
	binary.LittleEndian.PutUint32(buf[opt+108:], numDataDirs)
	// Data directories +112 .. +112+128. Most stay zero; index 5 is the
	// base reloc directory.
	for _, s := range l.Out {
		if s.Name == ".reloc" {
			binary.LittleEndian.PutUint32(buf[opt+112+5*8:], s.RVA)
			binary.LittleEndian.PutUint32(buf[opt+112+5*8+4:], s.VirtualSize)
			break
		}
	}
	off += optHeaderSize

	// ----- Section Table -----
	for _, s := range l.Out {
		writeSectionHeader(buf[off:], s)
		off += sectionEntry
	}

	// ----- Section Data -----
	for _, s := range l.Out {
		if s.Data != nil && s.RawSize > 0 {
			copy(buf[s.FileOffset:], s.Data)
		}
	}

	return buf, nil
}

// writeSectionHeader serialises one IMAGE_SECTION_HEADER (40 bytes) for
// the given MergedSection. Names longer than 8 chars are silently
// truncated — none of our sections need the /N+stringtable indirection
// (the standard ones are 5-6 chars).
func writeSectionHeader(dst []byte, s *MergedSection) {
	// Name: 8 bytes NUL-padded
	copy(dst[0:8], []byte(s.Name))
	for i := len(s.Name); i < 8; i++ {
		dst[i] = 0
	}
	binary.LittleEndian.PutUint32(dst[8:], s.VirtualSize)
	binary.LittleEndian.PutUint32(dst[12:], s.RVA)
	binary.LittleEndian.PutUint32(dst[16:], s.RawSize)
	binary.LittleEndian.PutUint32(dst[20:], s.FileOffset)
	// PointerToRelocations / PointerToLineNumbers / NumberOf*: 0
	binary.LittleEndian.PutUint32(dst[36:], s.Characteristics)
}
