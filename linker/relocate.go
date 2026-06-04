package linker

import (
	"encoding/binary"
	"fmt"
)

// Machine codes from <winnt.h>. The COFF File Header puts one of these
// in its Machine field; lld-link / link.exe accept the same values via
// /machine:.
const (
	MachineAMD64       uint16 = 0x8664
	MachineARM64       uint16 = 0xaa64
	MachineRISCV64     uint16 = 0x5064
	MachineLoongArch64 uint16 = 0x6264
)

// BaseReloc is one entry of the output's .reloc section: an RVA + a
// COFF base-relocation type. The OS loader replays them when the image
// is rebased away from ImageBase.
type BaseReloc struct {
	RVA  uint32
	Type uint16 // IMAGE_REL_BASED_*
}

// IMAGE_REL_BASED_* values from <winnt.h>.
const (
	BaseRelocAbsolute uint16 = 0 // padding only — emitted to align blocks to 4 bytes
	BaseRelocDir64    uint16 = 10
	BaseRelocHigh     uint16 = 1
	BaseRelocLow      uint16 = 2
	BaseRelocHighLow  uint16 = 3
)

// ApplyRelocations walks every input section's relocations, looks each
// reloc's target up in the symbol table, computes the target RVA, and
// patches the corresponding bytes in the merged output sections. It
// returns the list of base relocations the .reloc section will carry.
//
// On RISC-V it first builds a side table mapping each PCREL_HI20 site VA
// to its resolved target VA, so the matching PCREL_LO12_I/S can compute
// the same low-12 fixup. The side table only exists for the duration of
// this call.
func ApplyRelocations(objs []*Object, tab *SymTab, l *Layout) ([]BaseReloc, error) {
	if len(objs) == 0 {
		return nil, nil
	}
	machine := objs[0].Machine
	for _, o := range objs[1:] {
		if o.Machine != machine {
			return nil, fmt.Errorf("machine mismatch: %s is 0x%x, %s is 0x%x",
				objs[0].Name, machine, o.Name, o.Machine)
		}
	}

	// RISC-V PCREL_HI20 side table: site VA → (target VA). Built in a
	// pre-pass so any LO12 we encounter later (in any order) can resolve
	// its paired HI20.
	pcrelHI := map[uint64]uint64{}
	if machine == MachineRISCV64 {
		for objIdx, o := range objs {
			for secIdx, sec := range o.Sections {
				ref := SectionRef{ObjIdx: objIdx, SecIdx: secIdx}
				if _, placed := l.Where[ref]; !placed {
					continue
				}
				for _, r := range sec.Relocs {
					if r.Type != rvPCRelHi20 {
						continue
					}
					targetVA, _, _, err := resolveRelocTarget(o, ref, r, tab, l)
					if err != nil {
						continue
					}
					outSec := l.Out[l.Where[ref]]
					siteVA := l.Opts.ImageBase + uint64(outSec.RVA+l.OffsetIn[ref]+r.VirtualAddress)
					pcrelHI[siteVA] = targetVA + uint64(r.Addend)
				}
			}
		}
	}
	pcrelLookup := func(siteVA uint64) (uint64, bool) {
		v, ok := pcrelHI[siteVA]
		return v, ok
	}

	var base []BaseReloc
	for objIdx, o := range objs {
		for secIdx, sec := range o.Sections {
			ref := SectionRef{ObjIdx: objIdx, SecIdx: secIdx}
			if _, placed := l.Where[ref]; !placed {
				continue // section was discarded (e.g. .drectve)
			}
			for _, r := range sec.Relocs {
				added, err := applyOne(machine, o, ref, sec, r, tab, l, pcrelLookup)
				if err != nil {
					return nil, fmt.Errorf("%s:%s reloc @0x%x type 0x%x: %w",
						o.Name, sec.Name, r.VirtualAddress, r.Type, err)
				}
				base = append(base, added...)
			}
		}
	}
	return base, nil
}

// resolveRelocTarget runs the same lookup applyOne performs, but stops
// before patching. Used by the RISC-V PCREL_HI20 pre-pass.
func resolveRelocTarget(obj *Object, ref SectionRef, r Reloc, tab *SymTab, l *Layout) (targetVA uint64, patchVA uint64, patchRVA uint32, err error) {
	res, err := lookupAcrossObjs(tab, obj, ref.ObjIdx, r.SymbolIndex)
	if err != nil {
		return 0, 0, 0, err
	}
	// Resolved.Kind is always SymAbsolute or SymDefined post-Resolve.
	if res.Kind == SymDefined {
		rva := l.Out[l.Where[res.Section]].RVA + l.OffsetIn[res.Section] + res.Offset
		targetVA = l.Opts.ImageBase + uint64(rva)
	} else {
		targetVA = uint64(res.Value)
	}
	outSec := l.Out[l.Where[ref]]
	patchOff := l.OffsetIn[ref] + r.VirtualAddress
	patchRVA = outSec.RVA + patchOff
	patchVA = l.Opts.ImageBase + uint64(patchRVA)
	return
}

// applyOne dispatches one relocation to its arch-specific implementer.
// targetRVA is computed once here so the per-arch code only has to
// translate (RVA, where-to-patch-bytes) into the actual byte fixup.
//
// pcrelLookup is the RISC-V PCREL_HI20 side table; it's nil-safe for
// other arches.
func applyOne(machine uint16, obj *Object, ref SectionRef, sec *Section,
	r Reloc, tab *SymTab, l *Layout, pcrelLookup func(uint64) (uint64, bool)) ([]BaseReloc, error) {

	// Resolve the relocation's target — either a global symbol or an
	// object-local STATIC symbol (which is what section-relative
	// relocations use).
	res, err := lookupAcrossObjs(tab, obj, ref.ObjIdx, r.SymbolIndex)
	if err != nil {
		return nil, err
	}

	// Compute the absolute VA the target sits at. For section-defined
	// symbols that's `imageBase + RVA + offset`; for absolute symbols
	// (notably the AllowUnresolved externals, Value=0) it's the symbol
	// value itself. The per-arch handlers work in VAs rather than RVAs
	// because PC-relative relocations need the imageBase to cancel out
	// correctly: disp = targetVA - patchVA. If we passed RVAs the
	// arithmetic would silently fold imageBase the wrong way for
	// absolute symbols (where target is NOT image-relative).
	var targetVA uint64
	switch res.Kind {
	case SymAbsolute:
		targetVA = uint64(res.Value)
	case SymDefined:
		rva := l.Out[l.Where[res.Section]].RVA + l.OffsetIn[res.Section] + res.Offset
		targetVA = l.Opts.ImageBase + uint64(rva)
	default:
		return nil, fmt.Errorf("unresolved symbol via reloc")
	}

	// Locate the patch bytes inside the merged output. Per-arch
	// handlers know how many bytes their relocation type touches and
	// validate before reading/writing.
	outSec := l.Out[l.Where[ref]]
	patchOff := l.OffsetIn[ref] + r.VirtualAddress
	if int(patchOff) > len(outSec.Data) {
		return nil, fmt.Errorf("patch offset 0x%x past section end (size %d)",
			patchOff, len(outSec.Data))
	}
	patchBytes := outSec.Data[patchOff:]
	patchRVA := outSec.RVA + patchOff
	patchVA := l.Opts.ImageBase + uint64(patchRVA)

	if obj.Format == FormatELF {
		switch machine {
		case MachineAMD64:
			return applyAMD64ELF(r.Type, patchBytes, patchVA, targetVA, patchRVA, l.Opts.ImageBase, r.Addend)
		case MachineARM64:
			return applyARM64ELF(r.Type, patchBytes, patchVA, targetVA, patchRVA, l.Opts.ImageBase, r.Addend)
		case MachineRISCV64:
			return applyRISCV64(r.Type, patchBytes, patchVA, targetVA, patchRVA, l.Opts.ImageBase, r.Addend, pcrelLookup)
		case MachineLoongArch64:
			return applyLoongArch64(r.Type, patchBytes, patchVA, targetVA, patchRVA, l.Opts.ImageBase, r.Addend)
		default:
			return nil, fmt.Errorf("machine 0x%x not supported (ELF)", machine)
		}
	}
	switch machine {
	case MachineAMD64:
		return applyAMD64(r.Type, patchBytes, patchVA, targetVA, patchRVA, l.Opts.ImageBase)
	case MachineARM64:
		return applyARM64(r.Type, patchBytes, patchVA, targetVA, patchRVA, l.Opts.ImageBase)
	default:
		return nil, fmt.Errorf("machine 0x%x not supported", machine)
	}
}

// lookupAcrossObjs is the tab.Lookup variant that knows which object
// the relocation came from. It hides the (objs slice, objIdx) tuple
// from per-arch implementers — they only see the resolved RVA.
func lookupAcrossObjs(tab *SymTab, obj *Object, objIdx int, symIdx uint32) (Resolved, error) {
	if int(symIdx) >= len(obj.Symbols) {
		return Resolved{}, fmt.Errorf("symbol index %d out of range", symIdx)
	}
	s := obj.Symbols[symIdx]
	if s.StorageClass == classStatic {
		if s.Kind == SymDefined {
			return Resolved{
				Section: SectionRef{ObjIdx: objIdx, SecIdx: int(s.SectionNumber) - 1},
				Offset:  s.Value,
				Kind:    SymDefined,
			}, nil
		}
		return Resolved{Kind: s.Kind, Value: s.Value}, nil
	}
	r, ok := tab.Entries[s.Name]
	if !ok {
		return Resolved{}, fmt.Errorf("unresolved %q", s.Name)
	}
	return r, nil
}

// rd32/wr32 are the little-endian helpers the per-arch code uses to
// read+rewrite 32-bit immediates embedded in instructions.
func rd32(b []byte) uint32    { return binary.LittleEndian.Uint32(b) }
func wr32(b []byte, v uint32) { binary.LittleEndian.PutUint32(b, v) }
func rd64(b []byte) uint64    { return binary.LittleEndian.Uint64(b) }
func wr64(b []byte, v uint64) { binary.LittleEndian.PutUint64(b, v) }
