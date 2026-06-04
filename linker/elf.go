package linker

import (
	"debug/elf"
	"fmt"
	"io"
)

// readELFObject parses an ELF relocatable into the same Object shape
// produced by readCOFFObject. The mapping is mechanical:
//
//   - elf.File.Machine            → Object.Machine (COFF machine code)
//   - elf.Section{NAME}           → Section{Name, Characteristics, Data, …}
//   - elf.Section{.rela.NAME}     → attached to its target section's Relocs
//   - elf.Symbol{…}               → Symbol{Name, Kind, SectionNumber, …}
//
// Section indices are kept 1-based on the Symbol side (matching the COFF
// convention) so the rest of the linker doesn't need to know whether the
// input came from a PE/COFF or an ELF file.
//
// ELF debug sections (no SHF_ALLOC) come through with IMAGE_SCN_MEM_DISCARDABLE
// set so the layout pass strips them — same path COFF .debug$* takes.
func readELFObject(r io.ReaderAt, name string) (*Object, error) {
	ef, err := elf.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("%s: parse ELF: %w", name, err)
	}
	defer ef.Close()
	if ef.Type != elf.ET_REL {
		return nil, fmt.Errorf("%s: not a relocatable ELF (type=%s)", name, ef.Type)
	}

	o := &Object{Name: name, Machine: elfMachine(ef.Machine), Format: FormatELF}
	if o.Machine == 0 {
		return nil, fmt.Errorf("%s: unsupported ELF machine %v", name, ef.Machine)
	}

	// Pass 1: convert every ELF section to one of our Sections. We keep
	// the original ELF indexing (1:1, in section-table order) so SHT_RELA
	// pointers in .Info still resolve in pass 2.
	o.Sections = make([]*Section, len(ef.Sections))
	for i, es := range ef.Sections {
		if i == 0 {
			// ELF SHN_UNDEF — we keep the slot so indices align, but it
			// has no payload and is filtered out at layout time by the
			// empty-VirtualSize guard.
			o.Sections[i] = &Section{}
			continue
		}
		s := &Section{
			Name:            es.Name,
			Characteristics: elfCharacteristics(es),
			SizeOfRawData:   uint32(es.FileSize),
			VirtualSize:     uint32(es.Size),
		}
		// Only load bytes for sections that actually contribute to the
		// output image (SHF_ALLOC). Everything else (debug, symtab,
		// strtab, .rela.*) is either read elsewhere (parseRELA,
		// ef.Symbols) or doesn't need its payload at all.
		if es.Flags&elf.SHF_ALLOC != 0 && es.Type != elf.SHT_NOBITS && es.Size > 0 {
			data, err := es.Data()
			if err != nil {
				return nil, fmt.Errorf("%s: section %q data: %w", name, es.Name, err)
			}
			s.Data = data
		}
		o.Sections[i] = s
	}

	// Pass 2: parse SHT_RELA sections and attach the relocations to their
	// target sections. We do NOT model SHT_REL — modern toolchains emit
	// SHT_RELA everywhere on 64-bit targets and on RISC-V.
	for _, es := range ef.Sections {
		if es.Type != elf.SHT_RELA {
			continue
		}
		if int(es.Info) >= len(o.Sections) {
			return nil, fmt.Errorf("%s: rela.%s target %d out of range", name, es.Name, es.Info)
		}
		entries, err := parseRELA(ef, es)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		o.Sections[es.Info].Relocs = entries
	}

	// Pass 3: convert the symbol table. ELF doesn't store the SHN_UNDEF
	// placeholder symbol (index 0) in its public Symbols() slice, so we
	// prepend one to keep the SymbolIndex used by relocations consistent.
	syms, err := ef.Symbols()
	if err != nil && err != elf.ErrNoSymbols {
		return nil, fmt.Errorf("%s: symbols: %w", name, err)
	}
	o.Symbols = make([]*Symbol, 0, len(syms)+1)
	// ELF index 0 is the SHN_UNDEF placeholder. Some relocations (notably
	// R_RISCV_RELAX) reference symbol index 0 with no real target — they're
	// hints, not pointers. Resolving to absolute-zero keeps the dispatcher
	// happy on the lookup path; the per-arch backend treats those types as
	// no-ops anyway.
	o.Symbols = append(o.Symbols, &Symbol{Kind: SymAbsolute, StorageClass: classStatic})
	for _, s := range syms {
		o.Symbols = append(o.Symbols, convertELFSymbol(s))
	}
	return o, nil
}

// elfMachine maps the ELF machine code to the equivalent COFF
// IMAGE_FILE_MACHINE_* code, so the dispatcher in relocate.go can stay
// machine-agnostic about the input format.
func elfMachine(m elf.Machine) uint16 {
	switch m {
	case elf.EM_X86_64:
		return MachineAMD64
	case elf.EM_AARCH64:
		return MachineARM64
	case elf.EM_RISCV:
		return MachineRISCV64
	case elf.EM_LOONGARCH:
		return MachineLoongArch64
	default:
		return 0
	}
}

// elfCharacteristics derives the closest COFF IMAGE_SCN_* bitset for an
// ELF section. We translate:
//
//   - SHT_PROGBITS                → INITIALIZED_DATA / CODE
//   - SHT_NOBITS (.bss style)     → UNINITIALIZED_DATA
//   - SHF_EXECINSTR               → CODE | MEM_EXECUTE
//   - SHF_WRITE                   → MEM_WRITE
//   - !SHF_ALLOC                  → MEM_DISCARDABLE (debug-only)
//
// The flags are read-only-by-default; SHF_ALLOC sections that don't
// declare SHF_WRITE land in .rdata.
func elfCharacteristics(es *elf.Section) uint32 {
	if es.Flags&elf.SHF_ALLOC == 0 {
		// Debug / non-load sections — layout drops these.
		return scnMemDiscardable
	}
	var c uint32 = scnMemRead
	if es.Type == elf.SHT_NOBITS {
		c |= scnCntUninitializedData
	} else if es.Flags&elf.SHF_EXECINSTR != 0 {
		c |= scnCntCode | scnMemExecute
	} else {
		c |= scnCntInitializedData
	}
	if es.Flags&elf.SHF_WRITE != 0 {
		c |= scnMemWrite
	}
	return c
}

// convertELFSymbol maps one elf.Symbol to our internal Symbol shape.
// The mapping is one-way (ELF → COFF semantics): bindings collapse into
// COFF storage classes, and SHN_UNDEF / SHN_ABS / SHN_COMMON map to the
// matching SymbolKind. The original ELF section index lives in
// SectionNumber (1-based, matching our COFF convention).
func convertELFSymbol(s elf.Symbol) *Symbol {
	out := &Symbol{Name: s.Name, Value: uint32(s.Value)}
	switch elf.ST_BIND(s.Info) {
	case elf.STB_GLOBAL:
		out.StorageClass = classExternal
	case elf.STB_WEAK:
		out.StorageClass = classWeakExternal
	default:
		out.StorageClass = classStatic
	}
	switch s.Section {
	case elf.SHN_UNDEF:
		out.Kind = SymUndefined
	case elf.SHN_ABS, elf.SHN_COMMON:
		out.Kind = SymAbsolute
	default:
		// Real section reference. ELF section indices live in s.Section;
		// they're 1-based by ELF convention which matches what we want.
		out.Kind = SymDefined
		out.SectionNumber = int16(s.Section)
	}
	// Section symbols (STT_SECTION) come through as STATIC with name=""
	// in TinyGo / clang output. Our linker only ever indexes them via the
	// symbol table from a relocation, so the empty name is fine.
	return out
}
