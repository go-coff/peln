package linker

import (
	"encoding/binary"
	"fmt"
)

// R_AARCH64_* relocation type codes from the AArch64 ELF psABI. Only
// the subset clang / TinyGo emit into SHF_ALLOC sections is implemented.
const (
	raNone        uint16 = 0
	raAbs64       uint16 = 257 // R_AARCH64_ABS64
	raAbs32       uint16 = 258 // R_AARCH64_ABS32
	raAbs16       uint16 = 259 // R_AARCH64_ABS16
	raPRel64      uint16 = 260 // R_AARCH64_PREL64
	raPRel32      uint16 = 261 // R_AARCH64_PREL32
	raPRel16      uint16 = 262 // R_AARCH64_PREL16
	raAdrPRel21   uint16 = 274 // R_AARCH64_ADR_PREL_LO21
	raAdrPRelPG   uint16 = 275 // R_AARCH64_ADR_PREL_PG_HI21
	raAddLo12     uint16 = 277 // R_AARCH64_ADD_ABS_LO12_NC
	raLdSt8Lo12   uint16 = 278 // R_AARCH64_LDST8_ABS_LO12_NC
	raTstBr14     uint16 = 279 // R_AARCH64_TSTBR14
	raCondBr19    uint16 = 280 // R_AARCH64_CONDBR19
	raJump26      uint16 = 282 // R_AARCH64_JUMP26
	raCall26      uint16 = 283 // R_AARCH64_CALL26
	raLdSt16Lo12  uint16 = 284 // R_AARCH64_LDST16_ABS_LO12_NC
	raLdSt32Lo12  uint16 = 285 // R_AARCH64_LDST32_ABS_LO12_NC
	raLdSt64Lo12  uint16 = 286 // R_AARCH64_LDST64_ABS_LO12_NC
	raLdSt128Lo12 uint16 = 299 // R_AARCH64_LDST128_ABS_LO12_NC
)

// applyARM64ELF patches one aarch64 ELF relocation. The arithmetic is
// the AArch64 psABI counterpart to the COFF backend in reloc_aarch64.go:
// instruction encodings are identical (same hardware) but addends come
// from Reloc.Addend rather than the instruction bits.
func applyARM64ELF(t uint16, patchBytes []byte, patchVA, targetVA uint64, patchRVA uint32, imageBase uint64, addend int64) ([]BaseReloc, error) {
	switch t {

	case raNone:
		return nil, nil

	case raAbs64:
		if len(patchBytes) < 8 {
			return nil, fmt.Errorf("R_AARCH64_ABS64 needs 8 bytes")
		}
		binary.LittleEndian.PutUint64(patchBytes, uint64(int64(targetVA)+addend))
		return []BaseReloc{{RVA: patchRVA, Type: BaseRelocDir64}}, nil

	case raAbs32:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_AARCH64_ABS32 needs 4 bytes")
		}
		binary.LittleEndian.PutUint32(patchBytes, uint32(int64(targetVA)+addend))
		return []BaseReloc{{RVA: patchRVA, Type: BaseRelocHighLow}}, nil

	case raAbs16:
		if len(patchBytes) < 2 {
			return nil, fmt.Errorf("R_AARCH64_ABS16 needs 2 bytes")
		}
		binary.LittleEndian.PutUint16(patchBytes, uint16(int64(targetVA)+addend))
		return nil, nil

	case raPRel64:
		if len(patchBytes) < 8 {
			return nil, fmt.Errorf("R_AARCH64_PREL64 needs 8 bytes")
		}
		binary.LittleEndian.PutUint64(patchBytes, uint64(int64(targetVA)+addend-int64(patchVA)))
		return nil, nil

	case raPRel32:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_AARCH64_PREL32 needs 4 bytes")
		}
		binary.LittleEndian.PutUint32(patchBytes, uint32(int64(targetVA)+addend-int64(patchVA)))
		return nil, nil

	case raPRel16:
		if len(patchBytes) < 2 {
			return nil, fmt.Errorf("R_AARCH64_PREL16 needs 2 bytes")
		}
		binary.LittleEndian.PutUint16(patchBytes, uint16(int64(targetVA)+addend-int64(patchVA)))
		return nil, nil

	case raCall26, raJump26:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_AARCH64_*26 needs 4 bytes")
		}
		disp := int64(targetVA) + addend - int64(patchVA)
		if disp&3 != 0 {
			return nil, fmt.Errorf("R_AARCH64_*26 misaligned disp=0x%x", disp)
		}
		dispWords := disp >> 2
		if dispWords < -(1<<25) || dispWords >= (1<<25) {
			return nil, fmt.Errorf("R_AARCH64_*26 disp 0x%x out of range", disp)
		}
		encodeARM64Branch26(patchBytes, dispWords)
		return nil, nil

	case raCondBr19:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_AARCH64_CONDBR19 needs 4 bytes")
		}
		disp := int64(targetVA) + addend - int64(patchVA)
		if disp&3 != 0 {
			return nil, fmt.Errorf("R_AARCH64_CONDBR19 misaligned 0x%x", disp)
		}
		dispWords := disp >> 2
		if dispWords < -(1<<18) || dispWords >= (1<<18) {
			return nil, fmt.Errorf("R_AARCH64_CONDBR19 disp 0x%x out of range", disp)
		}
		encodeARM64Branch19(patchBytes, dispWords)
		return nil, nil

	case raTstBr14:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_AARCH64_TSTBR14 needs 4 bytes")
		}
		disp := int64(targetVA) + addend - int64(patchVA)
		if disp&3 != 0 {
			return nil, fmt.Errorf("R_AARCH64_TSTBR14 misaligned 0x%x", disp)
		}
		dispWords := disp >> 2
		if dispWords < -(1<<13) || dispWords >= (1<<13) {
			return nil, fmt.Errorf("R_AARCH64_TSTBR14 disp 0x%x out of range", disp)
		}
		encodeARM64TBranch14(patchBytes, dispWords)
		return nil, nil

	case raAdrPRelPG:
		// ADRP: page-relative 21-bit (page = 4 KiB).
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_AARCH64_ADR_PREL_PG_HI21 needs 4 bytes")
		}
		target := int64(targetVA) + addend
		pageDisp := (target &^ 0xFFF) - (int64(patchVA) &^ 0xFFF)
		pageDisp >>= 12
		if pageDisp < -(1<<20) || pageDisp >= (1<<20) {
			return nil, fmt.Errorf("R_AARCH64_ADR_PREL_PG_HI21 disp 0x%x out of range", pageDisp)
		}
		encodeARM64ADRP(patchBytes, pageDisp)
		return nil, nil

	case raAdrPRel21:
		// ADR: byte-relative 21-bit.
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_AARCH64_ADR_PREL_LO21 needs 4 bytes")
		}
		disp := int64(targetVA) + addend - int64(patchVA)
		if disp < -(1<<20) || disp >= (1<<20) {
			return nil, fmt.Errorf("R_AARCH64_ADR_PREL_LO21 disp 0x%x out of range", disp)
		}
		encodeARM64ADR(patchBytes, disp)
		return nil, nil

	case raAddLo12:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_AARCH64_ADD_ABS_LO12_NC needs 4 bytes")
		}
		off := uint32((uint64(int64(targetVA) + addend)) & 0xFFF)
		encodeARM64Imm12(patchBytes, off)
		return nil, nil

	case raLdSt8Lo12, raLdSt16Lo12, raLdSt32Lo12, raLdSt64Lo12, raLdSt128Lo12:
		// LDR/STR imm12 scaled by access size.
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_AARCH64_LDST*_ABS_LO12_NC needs 4 bytes")
		}
		var scale uint32
		switch t {
		case raLdSt8Lo12:
			scale = 1
		case raLdSt16Lo12:
			scale = 2
		case raLdSt32Lo12:
			scale = 4
		case raLdSt64Lo12:
			scale = 8
		case raLdSt128Lo12:
			scale = 16
		}
		off := uint32((uint64(int64(targetVA) + addend)) & 0xFFF)
		if off%scale != 0 {
			return nil, fmt.Errorf("R_AARCH64_LDST%d_ABS_LO12_NC misaligned 0x%x", scale*8, off)
		}
		encodeARM64Imm12(patchBytes, off/scale)
		return nil, nil
	}
	return nil, fmt.Errorf("unsupported aarch64 ELF reloc type %d", t)
}
