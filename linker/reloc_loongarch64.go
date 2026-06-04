package linker

import (
	"encoding/binary"
	"fmt"
)

// LoongArch64 relocation type codes, from the psABI v2.x
// (loongarch-elf-abi-v2.00.pdf, §Relocation Types) and
// debug/elf's R_LARCH_*.
//
// Only the subset that clang / TinyGo for `goarch=loong64` emits into
// SHF_ALLOC sections is implemented. Debug-info-only ones (ADD/SUB/SET
// families, the SOP_* stack-of-pieces fixups used by GCC's older path)
// land on discardable sections that the layout pass strips, so the
// dispatcher never reaches them.
const (
	laNone        uint16 = 0   // R_LARCH_NONE
	laAbs32       uint16 = 1   // R_LARCH_32
	laAbs64       uint16 = 2   // R_LARCH_64
	laRelative    uint16 = 3   // R_LARCH_RELATIVE (dynamic; static images rebase via .reloc)
	laMarkLA      uint16 = 20  // R_LARCH_MARK_LA       (sequence marker, no fixup)
	laMarkPCREL   uint16 = 21  // R_LARCH_MARK_PCREL    (sequence marker, no fixup)
	laB16         uint16 = 64  // R_LARCH_B16  (beq/bne, 18-bit signed × 4)
	laB21         uint16 = 65  // R_LARCH_B21  (beqz/bnez, 23-bit signed × 4)
	laB26         uint16 = 66  // R_LARCH_B26  (b/bl, 28-bit signed × 4)
	laAbsHi20     uint16 = 67  // R_LARCH_ABS_HI20      (lu12i.w bits[5..24])
	laAbsLo12     uint16 = 68  // R_LARCH_ABS_LO12      (ori/addi/ld/st bits[10..21])
	laAbs64Lo20   uint16 = 69  // R_LARCH_ABS64_LO20    (lu32i.d bits[5..24])
	laAbs64Hi12   uint16 = 70  // R_LARCH_ABS64_HI12    (lu52i.d bits[10..21])
	laPCALA_Hi20  uint16 = 71  // R_LARCH_PCALA_HI20    (pcalau12i bits[5..24])
	laPCALA_Lo12  uint16 = 72  // R_LARCH_PCALA_LO12    (addi/ld/st bits[10..21])
	laPCALA64Lo20 uint16 = 73  // R_LARCH_PCALA64_LO20  (lu32i.d bits[5..24])
	laPCALA64Hi12 uint16 = 74  // R_LARCH_PCALA64_HI12  (lu52i.d bits[10..21])
	laRelax       uint16 = 100 // R_LARCH_RELAX
	laAlign       uint16 = 102 // R_LARCH_ALIGN — alignment marker, no fixup
)

// applyLoongArch64 patches one LoongArch64 ELF relocation. The
// arithmetic follows the standard psABI symbols:
//
//	S      = target symbol's resolved value (its VA)
//	A      = explicit addend from the .rela entry (Reloc.Addend)
//	P      = patch site VA (patchVA)
//	target = S + A
//	disp   = target - P
//
// The HI20+LO12 carry adjustment is the same as RISC-V's: when the
// low 12 bits sign-extend negative, the high 20 must be incremented
// by one — so hi = (val + 0x800) >> 12.
//
// For the PCALA family the high relocation operates on the *page*
// difference, where a page is 4 KiB. Per the psABI:
//
//	hi = ((((S + A + 0x800) & ~0xFFF) - (P & ~0xFFF)) >> 12) & 0xFFFFF
//	lo = (S + A) & 0xFFF
//
// (Identical to AArch64's ADRP+ADD pattern.)
func applyLoongArch64(t uint16, patchBytes []byte, patchVA, targetVA uint64, patchRVA uint32, imageBase uint64, addend int64) ([]BaseReloc, error) {
	switch t {

	case laNone, laRelax, laMarkLA, laMarkPCREL, laAlign:
		// No fixup.
		// RELAX is an optimisation marker the linker may honour by
		// shrinking adjacent instructions; we don't, so it's a no-op.
		// MARK_* are sequence diagnostics; ALIGN reports the SHF_ALLOC
		// alignment to the linker — peln honours alignments via the
		// section layout step rather than as a per-fixup operation.
		return nil, nil

	case laAbs32:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_LARCH_32 needs 4 bytes")
		}
		v := uint32(int64(targetVA) + addend)
		binary.LittleEndian.PutUint32(patchBytes, v)
		return []BaseReloc{{RVA: patchRVA, Type: BaseRelocHighLow}}, nil

	case laAbs64:
		if len(patchBytes) < 8 {
			return nil, fmt.Errorf("R_LARCH_64 needs 8 bytes")
		}
		v := uint64(int64(targetVA) + addend)
		binary.LittleEndian.PutUint64(patchBytes, v)
		return []BaseReloc{{RVA: patchRVA, Type: BaseRelocDir64}}, nil

	case laAbsHi20:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_LARCH_ABS_HI20 needs 4 bytes")
		}
		val := uint32(int64(targetVA) + addend)
		hi := (val + 0x800) >> 12 & 0xFFFFF
		patchLoongImm20(patchBytes, hi)
		return nil, nil

	case laAbsLo12:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_LARCH_ABS_LO12 needs 4 bytes")
		}
		val := uint32(int64(targetVA) + addend)
		patchLoongImm12(patchBytes, val&0xFFF)
		return nil, nil

	case laAbs64Lo20:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_LARCH_ABS64_LO20 needs 4 bytes")
		}
		// bits 32..51 of (S + A) → lu32i.d imm20
		v := uint64(int64(targetVA) + addend)
		patchLoongImm20(patchBytes, uint32((v>>32)&0xFFFFF))
		return nil, nil

	case laAbs64Hi12:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_LARCH_ABS64_HI12 needs 4 bytes")
		}
		// bits 52..63 of (S + A) → lu52i.d imm12
		v := uint64(int64(targetVA) + addend)
		patchLoongImm12(patchBytes, uint32((v>>52)&0xFFF))
		return nil, nil

	case laPCALA_Hi20:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_LARCH_PCALA_HI20 needs 4 bytes")
		}
		// Page-aligned PC-relative high 20 bits.
		target := uint64(int64(targetVA) + addend)
		hi := int64((target+0x800)&^0xFFF) - int64(patchVA&^0xFFF)
		patchLoongImm20(patchBytes, uint32((hi>>12)&0xFFFFF))
		return nil, nil

	case laPCALA_Lo12:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_LARCH_PCALA_LO12 needs 4 bytes")
		}
		target := uint64(int64(targetVA) + addend)
		patchLoongImm12(patchBytes, uint32(target&0xFFF))
		return nil, nil

	case laPCALA64Lo20:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_LARCH_PCALA64_LO20 needs 4 bytes")
		}
		target := uint64(int64(targetVA) + addend)
		disp := int64(target) - int64(patchVA)
		patchLoongImm20(patchBytes, uint32((uint64(disp)>>32)&0xFFFFF))
		return nil, nil

	case laPCALA64Hi12:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_LARCH_PCALA64_HI12 needs 4 bytes")
		}
		target := uint64(int64(targetVA) + addend)
		disp := int64(target) - int64(patchVA)
		patchLoongImm12(patchBytes, uint32((uint64(disp)>>52)&0xFFF))
		return nil, nil

	case laB16:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_LARCH_B16 needs 4 bytes")
		}
		disp := int64(targetVA) + addend - int64(patchVA)
		if disp&3 != 0 {
			return nil, fmt.Errorf("R_LARCH_B16 misaligned target (disp=%d)", disp)
		}
		if disp < -(1<<17) || disp >= (1<<17) {
			return nil, fmt.Errorf("R_LARCH_B16 disp out of ±128 KiB range: %d", disp)
		}
		patchLoongB16(patchBytes, int32(disp>>2))
		return nil, nil

	case laB21:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_LARCH_B21 needs 4 bytes")
		}
		disp := int64(targetVA) + addend - int64(patchVA)
		if disp&3 != 0 {
			return nil, fmt.Errorf("R_LARCH_B21 misaligned target (disp=%d)", disp)
		}
		if disp < -(1<<22) || disp >= (1<<22) {
			return nil, fmt.Errorf("R_LARCH_B21 disp out of ±4 MiB range: %d", disp)
		}
		patchLoongB21(patchBytes, int32(disp>>2))
		return nil, nil

	case laB26:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_LARCH_B26 needs 4 bytes")
		}
		disp := int64(targetVA) + addend - int64(patchVA)
		if disp&3 != 0 {
			return nil, fmt.Errorf("R_LARCH_B26 misaligned target (disp=%d)", disp)
		}
		if disp < -(1<<27) || disp >= (1<<27) {
			return nil, fmt.Errorf("R_LARCH_B26 disp out of ±128 MiB range: %d", disp)
		}
		patchLoongB26(patchBytes, int32(disp>>2))
		return nil, nil

	default:
		return nil, fmt.Errorf("unsupported LoongArch reloc 0x%x", t)
	}
}

// patchLoongImm20 splices a 20-bit immediate into bits[24:5] of the
// 32-bit instruction word at the start of buf. The other bits are
// preserved.
func patchLoongImm20(buf []byte, imm20 uint32) {
	w := binary.LittleEndian.Uint32(buf)
	w = (w &^ (0xFFFFF << 5)) | ((imm20 & 0xFFFFF) << 5)
	binary.LittleEndian.PutUint32(buf, w)
}

// patchLoongImm12 splices a 12-bit immediate into bits[21:10] of the
// 32-bit instruction word.
func patchLoongImm12(buf []byte, imm12 uint32) {
	w := binary.LittleEndian.Uint32(buf)
	w = (w &^ (0xFFF << 10)) | ((imm12 & 0xFFF) << 10)
	binary.LittleEndian.PutUint32(buf, w)
}

// patchLoongB16 splices a 16-bit signed displacement (already scaled
// down by 4) into bits[25:10] of a `beq`/`bne`/`blt`/`bge`/`bltu`/
// `bgeu` instruction.
func patchLoongB16(buf []byte, disp int32) {
	w := binary.LittleEndian.Uint32(buf)
	w = (w &^ (0xFFFF << 10)) | ((uint32(disp) & 0xFFFF) << 10)
	binary.LittleEndian.PutUint32(buf, w)
}

// patchLoongB21 splices a 21-bit signed displacement (scaled /4) into
// a `beqz`/`bnez` instruction. The displacement is split:
//
//	bits[15:0]  → instr bits[25:10]
//	bits[20:16] → instr bits[4:0]
func patchLoongB21(buf []byte, disp int32) {
	w := binary.LittleEndian.Uint32(buf)
	d := uint32(disp) & ((1 << 21) - 1)
	lo16 := d & 0xFFFF
	hi5 := (d >> 16) & 0x1F
	w = (w &^ ((0xFFFF << 10) | 0x1F)) | (lo16 << 10) | hi5
	binary.LittleEndian.PutUint32(buf, w)
}

// patchLoongB26 splices a 26-bit signed displacement (scaled /4) into
// a `b`/`bl` instruction. The displacement is split:
//
//	bits[15:0]  → instr bits[25:10]
//	bits[25:16] → instr bits[9:0]
func patchLoongB26(buf []byte, disp int32) {
	w := binary.LittleEndian.Uint32(buf)
	d := uint32(disp) & ((1 << 26) - 1)
	lo16 := d & 0xFFFF
	hi10 := (d >> 16) & 0x3FF
	w = (w &^ ((0xFFFF << 10) | 0x3FF)) | (lo16 << 10) | hi10
	binary.LittleEndian.PutUint32(buf, w)
}
