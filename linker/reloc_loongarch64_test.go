package linker

import (
	"encoding/binary"
	"strings"
	"testing"
)

// laInst returns a fresh 4-byte instruction slot pre-filled with `v`.
func laInst(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func TestApplyLoongArch64_NoFixup(t *testing.T) {
	for _, typ := range []uint16{laNone, laRelax, laMarkLA, laMarkPCREL, laAlign} {
		br, err := applyLoongArch64(typ, laInst(0xAAAAAAAA), 0, 0, 0, 0, 0)
		if err != nil || br != nil {
			t.Errorf("type %d: %v %v", typ, err, br)
		}
	}
}

func TestApplyLoongArch64_Abs32(t *testing.T) {
	b := laInst(0)
	br, err := applyLoongArch64(laAbs32, b, 0, 0x1234, 0x500, 0x10000, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(b); got != 0x1238 {
		t.Errorf("Abs32 = 0x%x, want 0x1238", got)
	}
	if len(br) != 1 || br[0].Type != BaseRelocHighLow {
		t.Errorf("Abs32 should emit HIGHLOW, got %+v", br)
	}
}

func TestApplyLoongArch64_Abs64(t *testing.T) {
	b := make([]byte, 8)
	br, err := applyLoongArch64(laAbs64, b, 0, 0x4000, 0x500, 0x10000, 0x8)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(b); got != 0x4008 {
		t.Errorf("Abs64 = 0x%x, want 0x4008", got)
	}
	if len(br) != 1 || br[0].Type != BaseRelocDir64 {
		t.Errorf("Abs64 should emit DIR64, got %+v", br)
	}
}

func TestApplyLoongArch64_AbsHi20Lo12(t *testing.T) {
	// target = 0x12345.
	// hi20 = (0x12345 + 0x800) >> 12 = 0x12B45>>12 = 0x12;
	// lo12 = 0x12345 & 0xFFF = 0x345.
	// Reconstructed: 0x12<<12 + sign-extended 0x345 = 0x12345 ✓.
	bHi := laInst(0x14000004) // lu12i.w $r4, 0 — opcode 0x14<<26 + rd=4
	if _, err := applyLoongArch64(laAbsHi20, bHi, 0, 0x12345, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint32(bHi)
	if (got>>5)&0xFFFFF != 0x12 {
		t.Errorf("ABS_HI20 imm = 0x%x, want 0x12", (got>>5)&0xFFFFF)
	}
	if got>>26 != 0x05 || got&0x1F != 4 { // opcode top 6 bits = 0x14>>2 = 0x05; rd preserved
		t.Errorf("ABS_HI20 opcode/rd lost: 0x%x", got)
	}

	// addi.d $r4, $r4, ? — opcode 0x02C00000 + rj=4 (bits 5..9) + rd=4 (bits 0..4)
	bLo := laInst(0x02C00084)
	if _, err := applyLoongArch64(laAbsLo12, bLo, 0, 0x12345, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	got = binary.LittleEndian.Uint32(bLo)
	if (got>>10)&0xFFF != 0x345 {
		t.Errorf("ABS_LO12 imm = 0x%x, want 0x345", (got>>10)&0xFFF)
	}
}

func TestApplyLoongArch64_PCALA(t *testing.T) {
	// pcalau12i at PC=0x1004; target=0x9876, addend=0.
	//   lo12 = 0x9876 & 0xFFF = 0x876 — sign-extends to −0x78A (bit 11 set).
	// To keep target = (PC & ~0xFFF) + (imm20 << 12) + sext(lo12), the HI20
	// must carry +1 when lo12 is negative; the +0x800 carry trick folds
	// that in:
	//   hi20 = ((target + 0x800) & ~0xFFF - PC & ~0xFFF) >> 12
	//        = (0xA000 - 0x1000) >> 12 = 0x9
	// Runtime check: 0x1000 + (0x9 << 12) − 0x78A = 0xA000 − 0x78A = 0x9876 ✓
	bHi := laInst(0x1A000004)
	if _, err := applyLoongArch64(laPCALA_Hi20, bHi, 0x1004, 0x9876, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint32(bHi)
	if (got>>5)&0xFFFFF != 0x9 {
		t.Errorf("PCALA_HI20 imm = 0x%x, want 0x9 (raw 0x%x)", (got>>5)&0xFFFFF, got)
	}

	bLo := laInst(0x02C00084)
	if _, err := applyLoongArch64(laPCALA_Lo12, bLo, 0x1008, 0x9876, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	got = binary.LittleEndian.Uint32(bLo)
	if (got>>10)&0xFFF != 0x876 {
		t.Errorf("PCALA_LO12 imm = 0x%x, want 0x876", (got>>10)&0xFFF)
	}
}

// Reverse case: lo12's bit 11 is 0, so no HI20 carry adjustment needed.
func TestApplyLoongArch64_PCALA_NoCarry(t *testing.T) {
	// PC=0x1004, target=0x9123 → lo12=0x123 (positive, no sign-extend trick).
	// hi20 = ((0x9123 + 0x800) & ~0xFFF − 0x1000) >> 12 = (0x9000 − 0x1000) >> 12 = 0x8
	// Runtime: 0x1000 + 0x8000 + 0x123 = 0x9123 ✓
	bHi := laInst(0x1A000004)
	if _, err := applyLoongArch64(laPCALA_Hi20, bHi, 0x1004, 0x9123, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint32(bHi)
	if (got>>5)&0xFFFFF != 0x8 {
		t.Errorf("PCALA_HI20 (no-carry) = 0x%x, want 0x8", (got>>5)&0xFFFFF)
	}
}

func TestApplyLoongArch64_B16(t *testing.T) {
	// beq $r0, $r0, +8 — opcode 0x16<<26 = 0x58000000, rj=0, rd=0, disp=8/4=2.
	b := laInst(0x58000000)
	if _, err := applyLoongArch64(laB16, b, 0x1000, 0x1008, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint32(b)
	if (got>>10)&0xFFFF != 2 {
		t.Errorf("B16 disp = %d, want 2 (raw 0x%x)", (got>>10)&0xFFFF, got)
	}
}

func TestApplyLoongArch64_B16Misaligned(t *testing.T) {
	_, err := applyLoongArch64(laB16, laInst(0), 0x1000, 0x1001, 0, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "misaligned") {
		t.Errorf("want misaligned, got %v", err)
	}
}

func TestApplyLoongArch64_B16OutOfRange(t *testing.T) {
	_, err := applyLoongArch64(laB16, laInst(0), 0, 1<<18, 0, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "out of") {
		t.Errorf("want out-of-range, got %v", err)
	}
}

func TestApplyLoongArch64_B21(t *testing.T) {
	// beqz $r4, +0x10 — disp=4 (in instructions). Encode and decode.
	b := laInst(0x40000004) // opcode 0x10<<26 = 0x40000000, rj=4 (bits 5..9)
	if _, err := applyLoongArch64(laB21, b, 0x1000, 0x1010, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint32(b)
	lo16 := (got >> 10) & 0xFFFF
	hi5 := got & 0x1F
	disp := (hi5 << 16) | lo16
	if disp != 4 {
		t.Errorf("B21 disp = %d, want 4 (raw 0x%x)", disp, got)
	}
}

func TestApplyLoongArch64_B21Misaligned(t *testing.T) {
	_, err := applyLoongArch64(laB21, laInst(0), 0, 1, 0, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "misaligned") {
		t.Errorf("want misaligned, got %v", err)
	}
}

func TestApplyLoongArch64_B21OutOfRange(t *testing.T) {
	// disp = 1<<23 is aligned (multiple of 4) but exceeds the ±4 MiB range.
	_, err := applyLoongArch64(laB21, laInst(0), 0, 1<<23, 0, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "out of") {
		t.Errorf("want out-of-range, got %v", err)
	}
}

func TestApplyLoongArch64_B26(t *testing.T) {
	// b +0x40 — opcode 0x14<<26 = 0x50000000, disp=16 (in instructions).
	b := laInst(0x50000000)
	if _, err := applyLoongArch64(laB26, b, 0x1000, 0x1040, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint32(b)
	lo16 := (got >> 10) & 0xFFFF
	hi10 := got & 0x3FF
	disp := (hi10 << 16) | lo16
	if disp != 16 {
		t.Errorf("B26 disp = %d, want 16 (raw 0x%x)", disp, got)
	}
}

func TestApplyLoongArch64_B26OutOfRange(t *testing.T) {
	_, err := applyLoongArch64(laB26, laInst(0), 0, 1<<28, 0, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "out of") {
		t.Errorf("want out-of-range, got %v", err)
	}
}

func TestApplyLoongArch64_B26Misaligned(t *testing.T) {
	// Target VA not 4-byte aligned ⇒ disp&3 != 0 ⇒ misaligned error.
	_, err := applyLoongArch64(laB26, laInst(0), 0x1000, 0x1002, 0, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "misaligned") {
		t.Errorf("want misaligned, got %v", err)
	}
}

// TestApplyLoongArch64_Abs64Lo20 covers the lu32i.d (bits 32..51) splice.
func TestApplyLoongArch64_Abs64Lo20(t *testing.T) {
	// target = 0x000A_BCDE_1234_5678, addend 0.
	// bits 32..51 = (target >> 32) & 0xFFFFF = 0x000ABCDE & 0xFFFFF = 0xABCDE.
	const target = uint64(0x000ABCDE12345678)
	b := laInst(0x16000004) // lu32i.d $r4, 0 (rd=4 preserved)
	if _, err := applyLoongArch64(laAbs64Lo20, b, 0, target, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint32(b)
	if (got>>5)&0xFFFFF != 0xABCDE {
		t.Errorf("ABS64_LO20 imm = 0x%x, want 0xABCDE (raw 0x%x)", (got>>5)&0xFFFFF, got)
	}
	if got&0x1F != 4 {
		t.Errorf("ABS64_LO20 rd lost: 0x%x", got)
	}
}

// TestApplyLoongArch64_Abs64Hi12 covers the lu52i.d (bits 52..63) splice.
func TestApplyLoongArch64_Abs64Hi12(t *testing.T) {
	// target = 0xABC0_0000_0000_0000, addend 0.
	// bits 52..63 = (target >> 52) & 0xFFF = 0xABC.
	const target = uint64(0xABC0000000000000)
	b := laInst(0x03000084) // lu52i.d $r4,$r4,0 (rj=4 bits5..9, rd=4 bits0..4)
	if _, err := applyLoongArch64(laAbs64Hi12, b, 0, target, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint32(b)
	if (got>>10)&0xFFF != 0xABC {
		t.Errorf("ABS64_HI12 imm = 0x%x, want 0xABC (raw 0x%x)", (got>>10)&0xFFF, got)
	}
	if got&0x3FF != 0x84 {
		t.Errorf("ABS64_HI12 rj/rd lost: 0x%x", got)
	}
}

// TestApplyLoongArch64_PCALA64Lo20 covers the PC-relative lu32i.d
// (bits 32..51 of disp) splice.
func TestApplyLoongArch64_PCALA64Lo20(t *testing.T) {
	// disp = target - patchVA. Choose disp = 0x000A_BCDE_0000_0000.
	const patchVA = uint64(0x1000)
	const disp = uint64(0x000ABCDE00000000)
	target := patchVA + disp
	// bits 32..51 = (disp >> 32) & 0xFFFFF = 0xABCDE.
	b := laInst(0x16000004) // lu32i.d $r4, 0
	if _, err := applyLoongArch64(laPCALA64Lo20, b, patchVA, target, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint32(b)
	if (got>>5)&0xFFFFF != 0xABCDE {
		t.Errorf("PCALA64_LO20 imm = 0x%x, want 0xABCDE (raw 0x%x)", (got>>5)&0xFFFFF, got)
	}
}

// TestApplyLoongArch64_PCALA64Hi12 covers the PC-relative lu52i.d
// (bits 52..63 of disp) splice.
func TestApplyLoongArch64_PCALA64Hi12(t *testing.T) {
	// disp = target - patchVA. Choose disp so bits 52..63 = 0xABC.
	const patchVA = uint64(0x1000)
	const disp = uint64(0xABC0000000000000)
	target := patchVA + disp // wraps in uint64, but disp recovered as target-patchVA
	// bits 52..63 = (disp >> 52) & 0xFFF = 0xABC.
	b := laInst(0x03000084) // lu52i.d $r4,$r4,0
	if _, err := applyLoongArch64(laPCALA64Hi12, b, patchVA, target, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint32(b)
	if (got>>10)&0xFFF != 0xABC {
		t.Errorf("PCALA64_HI12 imm = 0x%x, want 0xABC (raw 0x%x)", (got>>10)&0xFFF, got)
	}
}

// TestApplyLoongArch64_ShortBytes exercises the too-short-buffer error
// branch of every reloc case. laAbs64 needs 8 bytes, all others 4.
func TestApplyLoongArch64_ShortBytes(t *testing.T) {
	cases := []struct {
		typ uint16
		min int
	}{
		{laAbs32, 4},
		{laAbs64, 8},
		{laAbsHi20, 4},
		{laAbsLo12, 4},
		{laAbs64Lo20, 4},
		{laAbs64Hi12, 4},
		{laPCALA_Hi20, 4},
		{laPCALA_Lo12, 4},
		{laPCALA64Lo20, 4},
		{laPCALA64Hi12, 4},
		{laB16, 4},
		{laB21, 4},
		{laB26, 4},
	}
	for _, c := range cases {
		_, err := applyLoongArch64(c.typ, make([]byte, c.min-1), 0, 0, 0, 0, 0)
		if err == nil {
			t.Errorf("type %d with %d bytes: expected error", c.typ, c.min-1)
		}
	}
}

func TestApplyLoongArch64_UnsupportedReloc(t *testing.T) {
	_, err := applyLoongArch64(0xFF, laInst(0), 0, 0, 0, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("want unsupported, got %v", err)
	}
}

func TestPatchLoongImm20_PreservesOtherBits(t *testing.T) {
	// Top 7 bits + bottom 5 bits should survive a splice of bits[24:5].
	b := laInst(0xFE00001F) // opcode-ish top + rd=31
	patchLoongImm20(b, 0xABCDE)
	got := binary.LittleEndian.Uint32(b)
	if got>>25 != 0x7F {
		t.Errorf("top 7 bits lost: 0x%x", got>>25)
	}
	if got&0x1F != 0x1F {
		t.Errorf("bottom 5 bits lost: 0x%x", got&0x1F)
	}
	if (got>>5)&0xFFFFF != 0xABCDE {
		t.Errorf("imm20 = 0x%x, want 0xABCDE", (got>>5)&0xFFFFF)
	}
}

func TestPatchLoongImm12_PreservesOtherBits(t *testing.T) {
	b := laInst(0xFFC003FF) // bits 31..22 set; rj+rd set
	patchLoongImm12(b, 0xABC)
	got := binary.LittleEndian.Uint32(b)
	if got>>22 != 0x3FF {
		t.Errorf("opcode bits lost: 0x%x", got>>22)
	}
	if got&0x3FF != 0x3FF {
		t.Errorf("rj/rd bits lost: 0x%x", got&0x3FF)
	}
	if (got>>10)&0xFFF != 0xABC {
		t.Errorf("imm12 = 0x%x, want 0xABC", (got>>10)&0xFFF)
	}
}
