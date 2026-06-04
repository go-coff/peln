package linker

import "fmt"

// AMD64 relocation type codes from <winnt.h>:
//
//	IMAGE_REL_AMD64_ABSOLUTE 0x0000 — reference is absolute, no relocation is necessary
//	IMAGE_REL_AMD64_ADDR64   0x0001 — 64-bit VA (ImageBase + RVA) at offset; needs a .reloc DIR64 entry
//	IMAGE_REL_AMD64_ADDR32   0x0002 — 32-bit VA at offset; needs HIGHLOW .reloc
//	IMAGE_REL_AMD64_ADDR32NB 0x0003 — 32-bit RVA at offset; NO .reloc (image-base-independent)
//	IMAGE_REL_AMD64_REL32    0x0004 — 32-bit PC-relative; NO .reloc
//	IMAGE_REL_AMD64_REL32_1  0x0005 — REL32 with -1 implicit addend
//	IMAGE_REL_AMD64_REL32_2  0x0006 — REL32 with -2 implicit addend
//	IMAGE_REL_AMD64_REL32_3  0x0007 — REL32 with -3 implicit addend
//	IMAGE_REL_AMD64_REL32_4  0x0008 — REL32 with -4 implicit addend
//	IMAGE_REL_AMD64_REL32_5  0x0009 — REL32 with -5 implicit addend
//	IMAGE_REL_AMD64_SECTION  0x000a — 16-bit section index
//	IMAGE_REL_AMD64_SECREL   0x000b — 32-bit section-relative offset
const (
	relAMD64Absolute uint16 = 0x0
	relAMD64Addr64   uint16 = 0x1
	relAMD64Addr32   uint16 = 0x2
	relAMD64Addr32NB uint16 = 0x3
	relAMD64Rel32    uint16 = 0x4
	relAMD64Rel32_1  uint16 = 0x5
	relAMD64Rel32_2  uint16 = 0x6
	relAMD64Rel32_3  uint16 = 0x7
	relAMD64Rel32_4  uint16 = 0x8
	relAMD64Rel32_5  uint16 = 0x9
	relAMD64Section  uint16 = 0xa
	relAMD64SecRel   uint16 = 0xb
)

// applyAMD64 patches one AMD64 relocation. patchBytes is a slice of the
// merged output beginning at the relocation site. patchVA / targetVA
// are the absolute virtual addresses of the patch site and the resolved
// target (imageBase + RVA for section-defined symbols, the symbol value
// as-is for absolute symbols — that distinction is the reason these
// arrive as VAs rather than RVAs). patchRVA is kept around for the
// BaseReloc entries we emit; those are RVAs, not VAs.
//
// All COFF relocations on AMD64 take an addend stored *in the bytes
// being patched* (so we read whatever's there, add the relocation
// result, and write back). lld-link follows the same convention.
func applyAMD64(t uint16, patchBytes []byte, patchVA, targetVA uint64, patchRVA uint32, imageBase uint64) ([]BaseReloc, error) {
	switch t {
	case relAMD64Absolute:
		// Padding entry, never applied.
		return nil, nil

	case relAMD64Addr64:
		// 64-bit absolute VA = targetVA + addend.
		addend := rd64(patchBytes)
		wr64(patchBytes, targetVA+addend)
		return []BaseReloc{{RVA: patchRVA, Type: BaseRelocDir64}}, nil

	case relAMD64Addr32:
		// 32-bit VA = (targetVA + addend) truncated to 32.
		addend := uint64(rd32(patchBytes))
		wr32(patchBytes, uint32(targetVA+addend))
		return []BaseReloc{{RVA: patchRVA, Type: BaseRelocHighLow}}, nil

	case relAMD64Addr32NB:
		// 32-bit RVA — image-base independent, no .reloc entry.
		addend := rd32(patchBytes)
		wr32(patchBytes, uint32(targetVA-imageBase)+addend)
		return nil, nil

	case relAMD64Rel32,
		relAMD64Rel32_1, relAMD64Rel32_2, relAMD64Rel32_3,
		relAMD64Rel32_4, relAMD64Rel32_5:
		// PC-relative 32-bit. The "_N" variants encode an extra fixed
		// addend (-N) for the case where the instruction's immediate
		// is not at offset 0 from the next-instruction address.
		extraAddend := int32(0)
		switch t {
		case relAMD64Rel32:
			extraAddend = 4
		case relAMD64Rel32_1:
			extraAddend = 5
		case relAMD64Rel32_2:
			extraAddend = 6
		case relAMD64Rel32_3:
			extraAddend = 7
		case relAMD64Rel32_4:
			extraAddend = 8
		case relAMD64Rel32_5:
			extraAddend = 9
		}
		fileAddend := int32(rd32(patchBytes))
		disp := int64(targetVA) - int64(patchVA) - int64(extraAddend) + int64(fileAddend)
		if disp < -0x80000000 || disp > 0x7fffffff {
			return nil, fmt.Errorf("AMD64 REL32 displacement 0x%x out of range", disp)
		}
		wr32(patchBytes, uint32(int32(disp)))
		return nil, nil

	case relAMD64Section, relAMD64SecRel:
		// Section index / section-relative offset are used by debug
		// info. We strip discardable sections during layout so these
		// can be ignored without affecting correctness for our stub.
		return nil, nil
	}
	return nil, fmt.Errorf("unsupported AMD64 reloc type 0x%x", t)
}
