package linker

import (
	"encoding/binary"
	"fmt"
)

// RISC-V relocation type codes, copied from the psABI / binutils
// elfnn-riscv.c. Only the subset that TinyGo / clang outputs into
// SHF_ALLOC sections is implemented; debug-info-only ones (ADD/SUB/SET
// families) land on discardable sections that the layout pass strips,
// so the dispatcher never reaches them.
const (
	rvNone       uint16 = 0
	rvReloc32    uint16 = 1  // R_RISCV_32
	rvReloc64    uint16 = 2  // R_RISCV_64
	rvBranch     uint16 = 16 // R_RISCV_BRANCH       (B-type, 13-bit signed *2)
	rvJAL        uint16 = 17 // R_RISCV_JAL          (J-type, 21-bit signed *2)
	rvCall       uint16 = 18 // R_RISCV_CALL         (auipc + jalr, 32-bit PC-rel)
	rvCallPLT    uint16 = 19 // R_RISCV_CALL_PLT     (same encoding, static link)
	rvPCRelHi20  uint16 = 23 // R_RISCV_PCREL_HI20
	rvPCRelLo12I uint16 = 24 // R_RISCV_PCREL_LO12_I (paired w/ HI20 via local label)
	rvPCRelLo12S uint16 = 25 // R_RISCV_PCREL_LO12_S
	rvHi20       uint16 = 26 // R_RISCV_HI20         (lui)
	rvLo12I      uint16 = 27 // R_RISCV_LO12_I       (addi / load)
	rvLo12S      uint16 = 28 // R_RISCV_LO12_S       (store)
	rvRVCBranch  uint16 = 44 // R_RISCV_RVC_BRANCH   (CB-type, 9-bit signed *2)
	rvRVCJump    uint16 = 45 // R_RISCV_RVC_JUMP     (CJ-type, 12-bit signed *2)
	rvRelax      uint16 = 51 // R_RISCV_RELAX        (optimisation hint, no fixup)
)

// applyRISCV64 patches one RISC-V relocation. The arithmetic follows
// the RISC-V psABI (§3 of riscv-elf-psabi-doc):
//
//	S      = target symbol's resolved value (its VA)
//	A      = explicit addend from the .rela entry (Reloc.Addend)
//	P      = patch site VA (patchVA)
//	target = S + A
//	disp   = target - P
//
// Several relocations come in two flavours that share the LO12 fixup
// (HI20 vs PCREL_HI20). The HI20 side encodes (value + 0x800) >> 12 so
// that the matching LO12's sign-extended low 12 bits add up to `value`
// rather than `value - 0x1000`.
//
// PCREL_LO12_* relocations are paired with a PCREL_HI20 sitting at a
// LOCAL LABEL referenced by the relocation's symbol. We resolve the
// pair via a side table the dispatcher primes (pcrelLookup).
func applyRISCV64(t uint16, patchBytes []byte, patchVA, targetVA uint64, patchRVA uint32, imageBase uint64, addend int64, pcrelLookup func(siteVA uint64) (uint64, bool)) ([]BaseReloc, error) {
	switch t {

	case rvNone, rvRelax:
		// No fixup. RELAX is an optimisation marker the linker may
		// honour by shrinking adjacent instructions; we don't, so it's
		// a no-op.
		return nil, nil

	case rvReloc32:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_RISCV_32 needs 4 bytes")
		}
		v := uint32(int64(targetVA) + addend)
		binary.LittleEndian.PutUint32(patchBytes, v)
		return []BaseReloc{{RVA: patchRVA, Type: BaseRelocHighLow}}, nil

	case rvReloc64:
		if len(patchBytes) < 8 {
			return nil, fmt.Errorf("R_RISCV_64 needs 8 bytes")
		}
		v := uint64(int64(targetVA) + addend)
		binary.LittleEndian.PutUint64(patchBytes, v)
		return []BaseReloc{{RVA: patchRVA, Type: BaseRelocDir64}}, nil

	case rvHi20:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_RISCV_HI20 needs 4 bytes")
		}
		val := uint32(int64(targetVA) + addend)
		hi := (val + 0x800) >> 12 & 0xFFFFF
		patchU(patchBytes, hi)
		return nil, nil

	case rvLo12I:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_RISCV_LO12_I needs 4 bytes")
		}
		val := uint32(int64(targetVA) + addend)
		patchI(patchBytes, val&0xFFF)
		return nil, nil

	case rvLo12S:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_RISCV_LO12_S needs 4 bytes")
		}
		val := uint32(int64(targetVA) + addend)
		patchS(patchBytes, val&0xFFF)
		return nil, nil

	case rvBranch:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_RISCV_BRANCH needs 4 bytes")
		}
		disp := int64(targetVA) + addend - int64(patchVA)
		if disp&1 != 0 {
			return nil, fmt.Errorf("R_RISCV_BRANCH misaligned disp=0x%x", disp)
		}
		if disp < -(1<<12) || disp >= (1<<12) {
			return nil, fmt.Errorf("R_RISCV_BRANCH disp 0x%x out of range", disp)
		}
		patchB(patchBytes, uint32(disp))
		return nil, nil

	case rvJAL:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_RISCV_JAL needs 4 bytes")
		}
		disp := int64(targetVA) + addend - int64(patchVA)
		if disp&1 != 0 {
			return nil, fmt.Errorf("R_RISCV_JAL misaligned disp=0x%x", disp)
		}
		if disp < -(1<<20) || disp >= (1<<20) {
			return nil, fmt.Errorf("R_RISCV_JAL disp 0x%x out of range", disp)
		}
		patchJ(patchBytes, uint32(disp))
		return nil, nil

	case rvCall, rvCallPLT:
		// auipc rd, %pcrel_hi(disp); jalr rd, rd, %pcrel_lo(disp).
		// The two instructions live consecutively; patch both.
		if len(patchBytes) < 8 {
			return nil, fmt.Errorf("R_RISCV_CALL needs 8 bytes")
		}
		disp := int64(targetVA) + addend - int64(patchVA)
		if disp < -(1<<31) || disp >= (1<<31) {
			return nil, fmt.Errorf("R_RISCV_CALL disp 0x%x out of range", disp)
		}
		hi := (uint32(disp) + 0x800) >> 12 & 0xFFFFF
		lo := uint32(disp) & 0xFFF
		patchU(patchBytes[0:4], hi)
		patchI(patchBytes[4:8], lo)
		return nil, nil

	case rvPCRelHi20:
		// auipc rd, %pcrel_hi(target). Same encoding as HI20, but the
		// value is target - PC + 0x800.
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_RISCV_PCREL_HI20 needs 4 bytes")
		}
		disp := int64(targetVA) + addend - int64(patchVA)
		hi := (uint32(disp) + 0x800) >> 12 & 0xFFFFF
		patchU(patchBytes, hi)
		return nil, nil

	case rvPCRelLo12I, rvPCRelLo12S:
		// Paired with a PCREL_HI20 at the LOCAL LABEL named by this
		// relocation's symbol. targetVA *is* the HI20 site address —
		// we need the HI20's target instead, looked up via pcrelLookup.
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_RISCV_PCREL_LO12 needs 4 bytes")
		}
		if pcrelLookup == nil {
			return nil, fmt.Errorf("R_RISCV_PCREL_LO12 with no HI20 side table")
		}
		hiTarget, ok := pcrelLookup(targetVA)
		if !ok {
			return nil, fmt.Errorf("R_RISCV_PCREL_LO12 at 0x%x: no matching HI20 at 0x%x", patchVA, targetVA)
		}
		disp := int64(hiTarget) - int64(targetVA)
		lo := uint32(disp) & 0xFFF
		if t == rvPCRelLo12I {
			patchI(patchBytes, lo)
		} else {
			patchS(patchBytes, lo)
		}
		return nil, nil

	case rvRVCBranch:
		// c.beqz / c.bnez. 16-bit instruction at offset; 9-bit signed
		// offset, *2 scaled.
		if len(patchBytes) < 2 {
			return nil, fmt.Errorf("R_RISCV_RVC_BRANCH needs 2 bytes")
		}
		disp := int64(targetVA) + addend - int64(patchVA)
		if disp&1 != 0 {
			return nil, fmt.Errorf("R_RISCV_RVC_BRANCH misaligned 0x%x", disp)
		}
		if disp < -(1<<8) || disp >= (1<<8) {
			return nil, fmt.Errorf("R_RISCV_RVC_BRANCH disp 0x%x out of range", disp)
		}
		patchCB(patchBytes, uint16(disp))
		return nil, nil

	case rvRVCJump:
		// c.j / c.jal. 16-bit instruction at offset; 12-bit signed
		// offset, *2 scaled.
		if len(patchBytes) < 2 {
			return nil, fmt.Errorf("R_RISCV_RVC_JUMP needs 2 bytes")
		}
		disp := int64(targetVA) + addend - int64(patchVA)
		if disp&1 != 0 {
			return nil, fmt.Errorf("R_RISCV_RVC_JUMP misaligned 0x%x", disp)
		}
		if disp < -(1<<11) || disp >= (1<<11) {
			return nil, fmt.Errorf("R_RISCV_RVC_JUMP disp 0x%x out of range", disp)
		}
		patchCJ(patchBytes, uint16(disp))
		return nil, nil
	}
	return nil, fmt.Errorf("unsupported RISC-V reloc type %d", t)
}

// --- RISC-V instruction-encoding helpers -----------------------------------
//
// Each helper takes the byte slice at the patch site and a range-checked
// value, clears + ORs the relocation's bit field, and writes the result
// back. Bits outside the relocation's mask pass through untouched so the
// opcode in the .o input is preserved.

// patchU writes a 20-bit immediate into a U-type instruction (lui /
// auipc), at bits[31:12].
func patchU(b []byte, imm20 uint32) {
	inst := binary.LittleEndian.Uint32(b)
	inst = (inst &^ 0xFFFFF000) | ((imm20 & 0xFFFFF) << 12)
	binary.LittleEndian.PutUint32(b, inst)
}

// patchI writes a 12-bit immediate into an I-type instruction (addi /
// jalr / load), at bits[31:20].
func patchI(b []byte, imm12 uint32) {
	inst := binary.LittleEndian.Uint32(b)
	inst = (inst &^ 0xFFF00000) | ((imm12 & 0xFFF) << 20)
	binary.LittleEndian.PutUint32(b, inst)
}

// patchS writes a 12-bit immediate into an S-type instruction (store).
// imm[11:5] → bits[31:25], imm[4:0] → bits[11:7].
func patchS(b []byte, imm12 uint32) {
	inst := binary.LittleEndian.Uint32(b)
	hi := (imm12 >> 5) & 0x7F
	lo := imm12 & 0x1F
	inst = (inst &^ (0x7F<<25 | 0x1F<<7)) | (hi << 25) | (lo << 7)
	binary.LittleEndian.PutUint32(b, inst)
}

// patchB writes a 13-bit signed byte displacement (low bit always 0)
// into a B-type instruction.
//
//	bit 31 = imm[12]    bit 7  = imm[11]
//	bits 30:25 = imm[10:5]    bits 11:8 = imm[4:1]
func patchB(b []byte, disp uint32) {
	inst := binary.LittleEndian.Uint32(b)
	imm12 := (disp >> 12) & 0x1
	imm11 := (disp >> 11) & 0x1
	imm10_5 := (disp >> 5) & 0x3F
	imm4_1 := (disp >> 1) & 0xF
	clear := uint32(1)<<31 | uint32(0x3F)<<25 | uint32(0xF)<<8 | uint32(1)<<7
	inst = (inst &^ clear) |
		(imm12 << 31) | (imm10_5 << 25) | (imm4_1 << 8) | (imm11 << 7)
	binary.LittleEndian.PutUint32(b, inst)
}

// patchJ writes a 21-bit signed byte displacement into a J-type
// instruction (jal). Bits imm[20|10:1|11|19:12] map to inst[31|30:21|20|19:12].
func patchJ(b []byte, disp uint32) {
	inst := binary.LittleEndian.Uint32(b)
	imm20 := (disp >> 20) & 0x1
	imm19_12 := (disp >> 12) & 0xFF
	imm11 := (disp >> 11) & 0x1
	imm10_1 := (disp >> 1) & 0x3FF
	inst = (inst & 0xFFF) |
		(imm20 << 31) | (imm10_1 << 21) | (imm11 << 20) | (imm19_12 << 12)
	binary.LittleEndian.PutUint32(b, inst)
}

// patchCB writes a 9-bit signed byte displacement into a CB-type 16-bit
// compressed instruction (c.beqz / c.bnez). imm[8|4:3|7:6|2:1|5] maps
// to inst[12|11:10|6:5|4:3|2].
func patchCB(b []byte, disp uint16) {
	inst := binary.LittleEndian.Uint16(b)
	imm8 := (disp >> 8) & 0x1
	imm7_6 := (disp >> 6) & 0x3
	imm5 := (disp >> 5) & 0x1
	imm4_3 := (disp >> 3) & 0x3
	imm2_1 := (disp >> 1) & 0x3
	clear := uint16(1)<<12 | uint16(3)<<10 | uint16(3)<<5 | uint16(3)<<3 | uint16(1)<<2
	inst = (inst &^ clear) |
		(imm8 << 12) | (imm4_3 << 10) | (imm7_6 << 5) | (imm2_1 << 3) | (imm5 << 2)
	binary.LittleEndian.PutUint16(b, inst)
}

// patchCJ writes a 12-bit signed byte displacement into a CJ-type 16-bit
// compressed instruction (c.j / c.jal). imm[11|4|9:8|10|6|7|3:1|5] maps
// to inst[12|11|10:9|8|7|6|5:3|2].
func patchCJ(b []byte, disp uint16) {
	inst := binary.LittleEndian.Uint16(b)
	imm11 := (disp >> 11) & 0x1
	imm10 := (disp >> 10) & 0x1
	imm9_8 := (disp >> 8) & 0x3
	imm7 := (disp >> 7) & 0x1
	imm6 := (disp >> 6) & 0x1
	imm5 := (disp >> 5) & 0x1
	imm4 := (disp >> 4) & 0x1
	imm3_1 := (disp >> 1) & 0x7
	clear := uint16(0x1FFC) // bits 12..2
	inst = (inst &^ clear) |
		(imm11 << 12) | (imm4 << 11) | (imm9_8 << 9) | (imm10 << 8) |
		(imm6 << 7) | (imm7 << 6) | (imm3_1 << 3) | (imm5 << 2)
	binary.LittleEndian.PutUint16(b, inst)
}
