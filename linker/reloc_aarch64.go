package linker

import (
	"encoding/binary"
	"fmt"
)

// ARM64 relocation type codes from <winnt.h>:
//
//	IMAGE_REL_ARM64_ABSOLUTE        0x0000 — no fixup
//	IMAGE_REL_ARM64_ADDR32          0x0001 — 32-bit VA at offset; HIGHLOW .reloc
//	IMAGE_REL_ARM64_ADDR32NB        0x0002 — 32-bit RVA at offset; no .reloc
//	IMAGE_REL_ARM64_BRANCH26        0x0003 — B/BL imm26 (signed disp/4, ±128 MiB)
//	IMAGE_REL_ARM64_PAGEBASE_REL21  0x0004 — ADRP imm21 page-relative
//	IMAGE_REL_ARM64_REL21           0x0005 — ADR imm21 byte-relative
//	IMAGE_REL_ARM64_PAGEOFFSET_12A  0x0006 — ADD/SUB imm12 (low 12 of target)
//	IMAGE_REL_ARM64_PAGEOFFSET_12L  0x0007 — LDR/STR imm12 (size-scaled)
//	IMAGE_REL_ARM64_SECREL          0x0008 — 32-bit section-relative
//	IMAGE_REL_ARM64_SECREL_LOW12A   0x0009 — ADD/SUB imm12 of secrel
//	IMAGE_REL_ARM64_SECREL_HIGH12A  0x000a — ADD/SUB imm12 of (secrel >> 12)
//	IMAGE_REL_ARM64_SECREL_LOW12L   0x000b — LDR/STR imm12 of secrel
//	IMAGE_REL_ARM64_TOKEN           0x000c — debug metadata token
//	IMAGE_REL_ARM64_SECTION         0x000d — 16-bit section index
//	IMAGE_REL_ARM64_ADDR64          0x000e — 64-bit VA; DIR64 .reloc
//	IMAGE_REL_ARM64_BRANCH19        0x000f — B.cond/CBZ/CBNZ imm19 (signed disp/4)
const (
	relARM64Absolute      uint16 = 0x0
	relARM64Addr32        uint16 = 0x1
	relARM64Addr32NB      uint16 = 0x2
	relARM64Branch26      uint16 = 0x3
	relARM64PageBaseRel21 uint16 = 0x4
	relARM64Rel21         uint16 = 0x5
	relARM64PageOffset12A uint16 = 0x6
	relARM64PageOffset12L uint16 = 0x7
	relARM64SecRel        uint16 = 0x8
	relARM64SecRelLow12A  uint16 = 0x9
	relARM64SecRelHigh12A uint16 = 0xa
	relARM64SecRelLow12L  uint16 = 0xb
	relARM64Token         uint16 = 0xc
	relARM64Section       uint16 = 0xd
	relARM64Addr64        uint16 = 0xe
	relARM64Branch19      uint16 = 0xf
)

// applyARM64 patches one ARM64 relocation. patchBytes points at the
// instruction (or data slot) to fix up; patchRVA is its RVA in the
// final image; targetRVA is the resolved target's RVA.
//
// Instruction-imm relocations OVERWRITE the imm bits in place — the
// COFF convention on ARM64 puts the addend in the instruction's other
// fields (already correct in the .o), never in the bits the linker
// patches. The data-style relocations (ADDR64 / ADDR32 / ADDR32NB) DO
// honour the on-disk addend, exactly like AMD64.
func applyARM64(t uint16, patchBytes []byte, patchVA, targetVA uint64, patchRVA uint32, imageBase uint64) ([]BaseReloc, error) {
	switch t {
	case relARM64Absolute:
		return nil, nil

	case relARM64Addr64:
		if len(patchBytes) < 8 {
			return nil, fmt.Errorf("ADDR64 needs 8 bytes")
		}
		addend := rd64(patchBytes)
		wr64(patchBytes, targetVA+addend)
		return []BaseReloc{{RVA: patchRVA, Type: BaseRelocDir64}}, nil

	case relARM64Addr32:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("ADDR32 needs 4 bytes")
		}
		addend := uint64(rd32(patchBytes))
		wr32(patchBytes, uint32(targetVA+addend))
		return []BaseReloc{{RVA: patchRVA, Type: BaseRelocHighLow}}, nil

	case relARM64Addr32NB:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("ADDR32NB needs 4 bytes")
		}
		addend := rd32(patchBytes)
		wr32(patchBytes, uint32(targetVA-imageBase)+addend)
		return nil, nil

	case relARM64Branch26:
		// B / BL: imm26 in bits[25:0] of the instruction, byte
		// displacement / 4. Range ±128 MiB.
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("BRANCH26 needs 4 bytes")
		}
		inst := binary.LittleEndian.Uint32(patchBytes)
		disp := int64(targetVA) - int64(patchVA)
		if disp&3 != 0 {
			return nil, fmt.Errorf("BRANCH26 misaligned (disp=0x%x)", disp)
		}
		dispWords := disp >> 2
		if dispWords < -(1<<25) || dispWords >= (1<<25) {
			return nil, fmt.Errorf("BRANCH26 disp 0x%x out of range", disp)
		}
		inst = (inst &^ 0x03FFFFFF) | (uint32(dispWords) & 0x03FFFFFF)
		binary.LittleEndian.PutUint32(patchBytes, inst)
		return nil, nil

	case relARM64Branch19:
		// B.cond / CBZ / CBNZ: imm19 at bits[23:5], byte disp / 4.
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("BRANCH19 needs 4 bytes")
		}
		inst := binary.LittleEndian.Uint32(patchBytes)
		disp := int64(targetVA) - int64(patchVA)
		if disp&3 != 0 {
			return nil, fmt.Errorf("BRANCH19 misaligned (disp=0x%x)", disp)
		}
		dispWords := disp >> 2
		if dispWords < -(1<<18) || dispWords >= (1<<18) {
			return nil, fmt.Errorf("BRANCH19 disp 0x%x out of range", disp)
		}
		inst = (inst &^ (0x7FFFF << 5)) | ((uint32(dispWords) & 0x7FFFF) << 5)
		binary.LittleEndian.PutUint32(patchBytes, inst)
		return nil, nil

	case relARM64PageBaseRel21:
		// ADRP: imm21 page-relative. Page = 4 KiB, so we compare page
		// numbers (VA >> 12). The 21 bits land in two split fields:
		// bits[30:29] = immlo (low 2 bits), bits[23:5] = immhi (upper 19).
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("PAGEBASE_REL21 needs 4 bytes")
		}
		inst := binary.LittleEndian.Uint32(patchBytes)
		targetPage := int64(targetVA) &^ 0xFFF
		pcPage := int64(patchVA) &^ 0xFFF
		pageDisp := (targetPage - pcPage) >> 12
		if pageDisp < -(1<<20) || pageDisp >= (1<<20) {
			return nil, fmt.Errorf("PAGEBASE_REL21 disp 0x%x out of range", pageDisp)
		}
		immLo := (uint32(pageDisp) & 0x3) << 29
		immHi := ((uint32(pageDisp) >> 2) & 0x7FFFF) << 5
		inst = (inst &^ ((0x3 << 29) | (0x7FFFF << 5))) | immLo | immHi
		binary.LittleEndian.PutUint32(patchBytes, inst)
		return nil, nil

	case relARM64Rel21:
		// ADR: imm21 byte-relative (no page rounding).
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("REL21 needs 4 bytes")
		}
		inst := binary.LittleEndian.Uint32(patchBytes)
		disp := int64(targetVA) - int64(patchVA)
		if disp < -(1<<20) || disp >= (1<<20) {
			return nil, fmt.Errorf("REL21 disp 0x%x out of range", disp)
		}
		immLo := (uint32(disp) & 0x3) << 29
		immHi := ((uint32(disp) >> 2) & 0x7FFFF) << 5
		inst = (inst &^ ((0x3 << 29) | (0x7FFFF << 5))) | immLo | immHi
		binary.LittleEndian.PutUint32(patchBytes, inst)
		return nil, nil

	case relARM64PageOffset12A:
		// ADD/SUB imm12: low 12 bits of (targetVA + addend) go into
		// bits[21:10]. The existing imm12 in the .o is the addend
		// (TinyGo/clang emit the section-relative offset there for
		// section-symbol references).
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("PAGEOFFSET_12A needs 4 bytes")
		}
		inst := binary.LittleEndian.Uint32(patchBytes)
		addend := (inst >> 10) & 0xFFF
		off := uint32((targetVA + uint64(addend)) & 0xFFF)
		inst = (inst &^ (0xFFF << 10)) | (off << 10)
		binary.LittleEndian.PutUint32(patchBytes, inst)
		return nil, nil

	case relARM64PageOffset12L:
		// LDR/STR (unsigned offset, 12-bit immediate). The encoded
		// imm12 in the .o is a SCALED addend (scaled by access size).
		// Reverse-scale it to byte units, add to targetVA, then re-
		// scale to compose the final imm12. Mirrors lld-link's
		// applyArm64Imm pattern.
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("PAGEOFFSET_12L needs 4 bytes")
		}
		inst := binary.LittleEndian.Uint32(patchBytes)
		accessSize := uint32(1) << ((inst >> 30) & 0x3)
		addendScaled := (inst >> 10) & 0xFFF
		addendBytes := addendScaled * accessSize
		rawOff := uint32((targetVA + uint64(addendBytes)) & 0xFFF)
		if rawOff%accessSize != 0 {
			return nil, fmt.Errorf("PAGEOFFSET_12L misaligned (off=0x%x, size=%d)", rawOff, accessSize)
		}
		scaled := rawOff / accessSize
		inst = (inst &^ (0xFFF << 10)) | (scaled << 10)
		binary.LittleEndian.PutUint32(patchBytes, inst)
		return nil, nil

	case relARM64Section,
		relARM64SecRel, relARM64SecRelLow12A, relARM64SecRelHigh12A,
		relARM64SecRelLow12L, relARM64Token:
		// Debug-info relocations: SECREL points into a discardable
		// section that we strip during layout, so the relocation has
		// no observable effect on the final image.
		return nil, nil
	}
	return nil, fmt.Errorf("unsupported ARM64 reloc type 0x%x", t)
}
