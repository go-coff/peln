// Package linker turns one or more COFF/PE relocatable object files into
// a single PE32+ image suitable for use as a UEFI application. It exists
// to drop lld-link from the cloud-boot toolchain (and to make a riscv64
// UEFI build possible at all — lld-link's COFF driver does not yet know
// `/machine:riscv64`).
//
// Scope:
//
//   - Input: COFF/PE relocatable .o files produced by TinyGo / clang
//     using a `*-pc-windows-gnu` LLVM triple.
//   - Output: a self-contained PE32+ EFI application (subsystem 10),
//     position-independent via a populated .reloc table.
//   - Machines: amd64, arm64, riscv64. Other machines compile but fail
//     fast at relocation time, since the reloc-type tables are arch-
//     specific.
//
// Non-goals:
//
//   - General-purpose Windows .exe linking. The library intentionally
//     ignores anything that does not matter for an EFI application:
//     no IAT/IDT, no debug directories, no resource trees, no SEH.
//   - Static-archive (.lib / .a) input. Callers pass loose .o files.
//   - Incremental / partial linking.
package linker

import (
	"debug/pe"
	"fmt"
	"io"
)

// Object is one parsed COFF relocatable input. The fields mirror the
// minimum surface debug/pe exposes plus the bits we need to link: the
// raw section bytes and the un-resolved relocation entries.
//
// All section / symbol indices are 0-based regardless of how the COFF
// file encodes them (debug/pe normalises). Symbol table indices are
// PRESERVED from the input so relocations (which reference symbol-table
// rows) keep their meaning across the read.
type Object struct {
	// Name is the file path the object was loaded from, kept for
	// diagnostics.
	Name string

	// Machine is the IMAGE_FILE_MACHINE_* code (e.g. 0x8664 for amd64,
	// 0xaa64 for arm64, 0x5064 for riscv64).
	Machine uint16

	// Format records the source object format. The dispatcher routes to
	// COFF-numbered or ELF-numbered relocation backends based on this:
	// the two formats use completely different type-code namespaces.
	Format Format

	// Sections in input order. Section index 0 in COFF relocations is
	// 1-based, so callers wanting to index in here from a reloc row
	// must subtract 1.
	Sections []*Section

	// Symbols in input order (auxiliary records included so symbol-
	// table indices match the on-disk encoding).
	Symbols []*Symbol
}

// Section captures one input section: its name, raw bytes, characteristics
// (a bitset of IMAGE_SCN_* flags), and the relocations attached to it.
type Section struct {
	Name            string
	Characteristics uint32
	Data            []byte
	Relocs          []Reloc

	// SizeOfRawData is what the file header advertises; usually equal
	// to len(Data) but can be 0 for BSS-style sections that declare
	// VirtualSize > 0 but ship no payload.
	SizeOfRawData uint32
	VirtualSize   uint32
}

// Format identifies the source object format. ReadObject sets it
// automatically from the file magic; callers normally don't touch it.
type Format uint8

const (
	FormatCOFF Format = iota // PE/COFF relocatable (default zero value)
	FormatELF                // ELF relocatable
)

// Reloc is one relocation entry. Type is arch-specific (see the rel*
// constants in reloc_<arch>.go); the linker dispatches on Object.Machine
// + Object.Format + Type to choose the fixup formula.
//
// Addend is the explicit signed addend for ELF/RELA inputs. COFF inputs
// (and ELF/REL inputs, which don't carry an explicit addend either) leave
// it at zero — those formats store the addend inline at the patch site.
// Per-arch backends read whichever applies.
type Reloc struct {
	VirtualAddress uint32 // byte offset into the section's Data
	SymbolIndex    uint32 // 0-based index into Object.Symbols
	Type           uint16
	Addend         int64
}

// SymbolKind summarises the COFF storage class enough for our purposes.
type SymbolKind uint8

const (
	// SymUndefined means the symbol is referenced but defined elsewhere
	// (external linkage). Resolved at link time.
	SymUndefined SymbolKind = iota
	// SymDefined means the symbol is defined in this object, at
	// SectionNumber + Value (Value is the byte offset within the
	// section).
	SymDefined
	// SymAbsolute means the symbol value is final and is NOT relative
	// to any section.
	SymAbsolute
	// SymAux is an auxiliary symbol record that follows a primary one.
	// We keep it so symbol indices stay aligned with COFF on-disk
	// indices; the linker never resolves through an aux entry directly.
	SymAux
)

// Symbol is one row of the COFF symbol table.
type Symbol struct {
	Name string
	Kind SymbolKind

	// SectionNumber is the 1-based index into Object.Sections (or one of
	// IMAGE_SYM_* sentinel negative values reinterpreted as uint16).
	// Only meaningful when Kind == SymDefined.
	SectionNumber int16

	// Value is the byte offset within Sections[SectionNumber-1] when
	// Kind == SymDefined, or the absolute value when Kind == SymAbsolute.
	Value uint32

	// StorageClass mirrors the COFF IMAGE_SYM_CLASS_* value, retained
	// for the few link-time decisions that branch on it (notably
	// CLASS_WEAK_EXTERNAL).
	StorageClass uint8
}

// ReadObject parses a relocatable object from r. Closing r is the
// caller's responsibility.
//
// The file format is auto-detected by magic: input starting with
// "\x7FELF" is parsed as ELF (today the only path for RISC-V, since no
// COFF RV toolchain exists upstream); everything else is treated as
// COFF/PE relocatable. If the input is a fully-linked PE image (i.e.
// has the MZ/DOS stub at offset 0) ReadObject returns an error — the
// linker only consumes relocatable objects.
func ReadObject(r io.ReaderAt, name string) (*Object, error) {
	var magic [4]byte
	if _, err := r.ReadAt(magic[:], 0); err != nil {
		return nil, fmt.Errorf("%s: read magic: %w", name, err)
	}
	if magic == [4]byte{0x7F, 'E', 'L', 'F'} {
		return readELFObject(r, name)
	}
	return readCOFFObject(r, name)
}

// readCOFFObject is the original PE/COFF input parser. ReadObject
// auto-detects between this and the ELF parser; callers who know they
// have a COFF object can target this directly.
func readCOFFObject(r io.ReaderAt, name string) (*Object, error) {
	pf, err := pe.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("%s: parse PE/COFF: %w", name, err)
	}
	defer pf.Close()

	// A fully-linked PE has a non-zero optional header. Relocatables
	// have SizeOfOptionalHeader == 0 (and no OptionalHeader at all).
	if pf.OptionalHeader != nil {
		return nil, fmt.Errorf("%s: input is a linked PE image, not a relocatable .o", name)
	}

	o := &Object{
		Name:    name,
		Machine: pf.FileHeader.Machine,
	}

	// Sections: read their raw bytes, attach the per-section relocs.
	// BSS-style sections (IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080)
	// carry no on-disk bytes; calling .Data() on them returns an error
	// from debug/pe, so we leave .Data nil and rely on VirtualSize for
	// layout.
	const IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
	for _, s := range pf.Sections {
		var data []byte
		if s.Characteristics&IMAGE_SCN_CNT_UNINITIALIZED_DATA == 0 && s.Size > 0 {
			d, err := s.Data()
			if err != nil {
				return nil, fmt.Errorf("%s: section %q data: %w", name, s.Name, err)
			}
			data = d
		}
		// COFF .o convention: SectionHeader.Misc is interpreted as
		// PhysicalAddress (not VirtualSize) for relocatables, so
		// debug/pe reports VirtualSize == 0 across the board even
		// when the section has real content. Fall back to SizeOfRawData,
		// which is what TinyGo / clang put the in-memory size in for
		// BSS (and which equals VirtualSize for non-BSS — RawSize is
		// not file-padded at the .o stage, only at PE-emit time).
		vs := s.VirtualSize
		if vs == 0 {
			vs = s.Size
		}
		out := &Section{
			Name:            s.Name,
			Characteristics: s.Characteristics,
			Data:            data,
			SizeOfRawData:   s.Size,
			VirtualSize:     vs,
		}
		for _, r := range s.Relocs {
			out.Relocs = append(out.Relocs, Reloc{
				VirtualAddress: r.VirtualAddress,
				SymbolIndex:    r.SymbolTableIndex,
				Type:           r.Type,
			})
		}
		o.Sections = append(o.Sections, out)
	}

	// Symbols: debug/pe exposes the raw table as pf.COFFSymbols, which
	// is what we want — keeps aux entries in place so the indices match.
	for _, s := range pf.COFFSymbols {
		name, _ := s.FullName(pf.StringTable)
		o.Symbols = append(o.Symbols, &Symbol{
			Name:          name,
			SectionNumber: s.SectionNumber,
			Value:         s.Value,
			StorageClass:  s.StorageClass,
			Kind:          classify(s),
		})
	}

	return o, nil
}

// classify maps a COFF symbol's section number to one of our SymKind
// buckets. Negative section numbers are the IMAGE_SYM_* sentinels:
//
//	-1 (IMAGE_SYM_DEBUG)    → aux record
//	 0 (IMAGE_SYM_UNDEFINED)→ undefined external
//	-2 (IMAGE_SYM_ABSOLUTE) → absolute value
//	 N (>0)                 → defined in section N (1-based)
//
// IMAGE_SYM_CLASS_WEAK_EXTERNAL (class 105) sits under section 0 and is
// treated as SymUndefined; the per-symbol StorageClass field carries
// the distinction when the linker needs it.
func classify(s pe.COFFSymbol) SymbolKind {
	if s.NumberOfAuxSymbols > 0 && s.StorageClass == 103 /* IMAGE_SYM_CLASS_FILE */ {
		// COFF .file records come with auxiliary entries that hold the
		// source filename; treat the primary as defined-but-irrelevant.
		return SymAbsolute
	}
	switch s.SectionNumber {
	case 0:
		return SymUndefined
	case -1, -2:
		return SymAbsolute
	default:
		if s.SectionNumber > 0 {
			return SymDefined
		}
		return SymAbsolute
	}
}
