package linker

import (
	"encoding/binary"
	"strings"
	"testing"
)

// Helpers — fresh 4-byte / 2-byte instruction slots.
func rv32inst(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}
func rv16inst(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

func TestApplyRISCV64_NoneAndRelax(t *testing.T) {
	for _, typ := range []uint16{rvNone, rvRelax} {
		br, err := applyRISCV64(typ, rv32inst(0xAAAAAAAA), 0, 0, 0, 0, 0, nil)
		if err != nil || br != nil {
			t.Errorf("type %d: %v %v", typ, err, br)
		}
	}
}

func TestApplyRISCV64_R32(t *testing.T) {
	b := rv32inst(0)
	br, err := applyRISCV64(rvReloc32, b, 0, 0x1234, 0x500, 0x10000, 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(b); got != 0x1238 {
		t.Errorf("R32 = 0x%x, want 0x1238", got)
	}
	if len(br) != 1 || br[0].Type != BaseRelocHighLow {
		t.Errorf("R32 should emit HIGHLOW, got %+v", br)
	}
}

func TestApplyRISCV64_R64(t *testing.T) {
	b := make([]byte, 8)
	br, err := applyRISCV64(rvReloc64, b, 0, 0x4000, 0x500, 0x10000, 0x8, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(b); got != 0x4008 {
		t.Errorf("R64 = 0x%x, want 0x4008", got)
	}
	if len(br) != 1 || br[0].Type != BaseRelocDir64 {
		t.Errorf("R64 should emit DIR64, got %+v", br)
	}
}

func TestApplyRISCV64_Hi20Lo12I(t *testing.T) {
	// target = 0x12345 → hi20 = (0x12345 + 0x800) >> 12 = 0x12B45>>12 = 0x12;
	// lo12 = 0x12345 & 0xFFF = 0x345. Reconstructed: 0x12<<12 + sign-extended
	// 0x345 = 0x12345 ✓.
	bHi := rv32inst(0x000000B7) // lui x1
	if _, err := applyRISCV64(rvHi20, bHi, 0, 0x12345, 0, 0, 0, nil); err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint32(bHi)
	if (got >> 12) != 0x12 {
		t.Errorf("HI20 imm = 0x%x, want 0x12", got>>12)
	}
	if got&0xFFF != 0xB7 {
		t.Errorf("HI20 opcode/rd lost: 0x%x", got&0xFFF)
	}

	// LO12_I instruction `addi x1, x1, ?` opcode template 0x00008093.
	bLo := rv32inst(0x00008093)
	if _, err := applyRISCV64(rvLo12I, bLo, 0, 0x12345, 0, 0, 0, nil); err != nil {
		t.Fatal(err)
	}
	got = binary.LittleEndian.Uint32(bLo)
	if (got>>20)&0xFFF != 0x345 {
		t.Errorf("LO12_I imm = 0x%x, want 0x345", (got>>20)&0xFFF)
	}
}

func TestApplyRISCV64_Lo12S(t *testing.T) {
	// SW x2, ?(x1) template 0x00012023.
	b := rv32inst(0x00012023)
	if _, err := applyRISCV64(rvLo12S, b, 0, 0x12345, 0, 0, 0, nil); err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint32(b)
	hi7 := (got >> 25) & 0x7F
	lo5 := (got >> 7) & 0x1F
	imm := (hi7 << 5) | lo5
	if imm != 0x345 {
		t.Errorf("LO12_S imm = 0x%x, want 0x345", imm)
	}
}

func TestApplyRISCV64_Branch(t *testing.T) {
	// beq x0, x0, ? opcode 0x00000063. disp=+8 → imm[12,10:5,4:1,11] all zero
	// except bit at imm[3] (since 8 = 0b1000).
	b := rv32inst(0x00000063)
	if _, err := applyRISCV64(rvBranch, b, 0x1000, 0x1008, 0, 0, 0, nil); err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint32(b)
	// Decode back
	imm12 := (got >> 31) & 0x1
	imm11 := (got >> 7) & 0x1
	imm10_5 := (got >> 25) & 0x3F
	imm4_1 := (got >> 8) & 0xF
	disp := imm12<<12 | imm11<<11 | imm10_5<<5 | imm4_1<<1
	if disp != 8 {
		t.Errorf("BRANCH disp = %d, want 8 (raw 0x%x)", disp, got)
	}
}

func TestApplyRISCV64_BranchMisaligned(t *testing.T) {
	_, err := applyRISCV64(rvBranch, rv32inst(0), 0x1000, 0x1001, 0, 0, 0, nil)
	if err == nil || !strings.Contains(err.Error(), "misaligned") {
		t.Errorf("want misaligned, got %v", err)
	}
}

func TestApplyRISCV64_BranchOutOfRange(t *testing.T) {
	_, err := applyRISCV64(rvBranch, rv32inst(0), 0, 0x4000, 0, 0, 0, nil)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("want out-of-range, got %v", err)
	}
}

func TestApplyRISCV64_JAL(t *testing.T) {
	// jal x1, ? template 0x000000EF, disp = +0x10.
	b := rv32inst(0x000000EF)
	if _, err := applyRISCV64(rvJAL, b, 0x1000, 0x1010, 0, 0, 0, nil); err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint32(b)
	imm20 := (got >> 31) & 0x1
	imm10_1 := (got >> 21) & 0x3FF
	imm11 := (got >> 20) & 0x1
	imm19_12 := (got >> 12) & 0xFF
	disp := imm20<<20 | imm19_12<<12 | imm11<<11 | imm10_1<<1
	if disp != 0x10 {
		t.Errorf("JAL disp = 0x%x, want 0x10 (raw 0x%x)", disp, got)
	}
}

func TestApplyRISCV64_JALMisaligned(t *testing.T) {
	_, err := applyRISCV64(rvJAL, rv32inst(0), 0, 1, 0, 0, 0, nil)
	if err == nil || !strings.Contains(err.Error(), "misaligned") {
		t.Errorf("want misaligned, got %v", err)
	}
}

func TestApplyRISCV64_JALOutOfRange(t *testing.T) {
	_, err := applyRISCV64(rvJAL, rv32inst(0), 0, 1<<22, 0, 0, 0, nil)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("want out-of-range, got %v", err)
	}
}

func TestApplyRISCV64_Call(t *testing.T) {
	// auipc x1, 0 (0x00000097) + jalr x1, x1 (0x000080E7), disp = +0x10.
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b[0:4], 0x00000097)
	binary.LittleEndian.PutUint32(b[4:8], 0x000080E7)
	if _, err := applyRISCV64(rvCallPLT, b, 0x1000, 0x1010, 0, 0, 0, nil); err != nil {
		t.Fatal(err)
	}
	auipc := binary.LittleEndian.Uint32(b[0:4])
	jalr := binary.LittleEndian.Uint32(b[4:8])
	if (auipc >> 12) != 0 { // disp=0x10 → hi=(0x10+0x800)>>12=0
		t.Errorf("CALL auipc hi = 0x%x, want 0", auipc>>12)
	}
	if (jalr>>20)&0xFFF != 0x10 {
		t.Errorf("CALL jalr lo = 0x%x, want 0x10", (jalr>>20)&0xFFF)
	}
}

func TestApplyRISCV64_PCRelPair(t *testing.T) {
	// HI20 at site 0x1000 targets 0x12345 → side table records 0x1000 → 0x12345.
	// LO12 at site 0x1100 references the HI20 (its symbol points at 0x1000).
	pcrelHI := map[uint64]uint64{0x1000: 0x12345}
	lookup := func(siteVA uint64) (uint64, bool) { v, ok := pcrelHI[siteVA]; return v, ok }
	// disp_at_HI = 0x12345 - 0x1000 = 0x11345. low12 = 0x345.
	bLo := rv32inst(0x00008093) // addi
	if _, err := applyRISCV64(rvPCRelLo12I, bLo, 0x1100, 0x1000, 0, 0, 0, lookup); err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint32(bLo)
	if (got>>20)&0xFFF != 0x345 {
		t.Errorf("PCREL_LO12_I imm = 0x%x, want 0x345", (got>>20)&0xFFF)
	}
}

func TestApplyRISCV64_PCRelLo12S(t *testing.T) {
	pcrelHI := map[uint64]uint64{0x1000: 0x12345}
	lookup := func(siteVA uint64) (uint64, bool) { v, ok := pcrelHI[siteVA]; return v, ok }
	bLo := rv32inst(0x00012023)
	if _, err := applyRISCV64(rvPCRelLo12S, bLo, 0x1100, 0x1000, 0, 0, 0, lookup); err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint32(bLo)
	hi7 := (got >> 25) & 0x7F
	lo5 := (got >> 7) & 0x1F
	if (hi7<<5)|lo5 != 0x345 {
		t.Errorf("PCREL_LO12_S imm = 0x%x, want 0x345", (hi7<<5)|lo5)
	}
}

func TestApplyRISCV64_PCRelLo12NoSideTable(t *testing.T) {
	_, err := applyRISCV64(rvPCRelLo12I, rv32inst(0), 0, 0, 0, 0, 0, nil)
	if err == nil || !strings.Contains(err.Error(), "side table") {
		t.Errorf("want side-table error, got %v", err)
	}
}

func TestApplyRISCV64_PCRelLo12NoMatch(t *testing.T) {
	lookup := func(uint64) (uint64, bool) { return 0, false }
	_, err := applyRISCV64(rvPCRelLo12I, rv32inst(0), 0, 0x1000, 0, 0, 0, lookup)
	if err == nil || !strings.Contains(err.Error(), "no matching HI20") {
		t.Errorf("want no-matching-HI20, got %v", err)
	}
}

func TestApplyRISCV64_PCRelHi20(t *testing.T) {
	// auipc at PC=0x1000, target 0x12345 → disp = 0x11345.
	// hi = (0x11345 + 0x800) >> 12 = 0x11B45>>12 = 0x11.
	b := rv32inst(0x00000017) // auipc x0, 0
	if _, err := applyRISCV64(rvPCRelHi20, b, 0x1000, 0x12345, 0, 0, 0, nil); err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint32(b)
	if (got >> 12) != 0x11 {
		t.Errorf("PCREL_HI20 imm = 0x%x, want 0x11", got>>12)
	}
}

func TestApplyRISCV64_RVCBranch(t *testing.T) {
	// c.beqz template 0xC001 (op=01, funct3=110, rs1'=0, imm=0)
	b := rv16inst(0xC001)
	if _, err := applyRISCV64(rvRVCBranch, b, 0x1000, 0x1004, 0, 0, 0, nil); err != nil {
		t.Fatal(err)
	}
	// disp=4; should encode imm[2]=4→bit_imm5? Let me just verify round-trip
	// by decoding the bits back.
	got := binary.LittleEndian.Uint16(b)
	imm8 := (got >> 12) & 0x1
	imm4_3 := (got >> 10) & 0x3
	imm7_6 := (got >> 5) & 0x3
	imm2_1 := (got >> 3) & 0x3
	imm5 := (got >> 2) & 0x1
	disp := imm8<<8 | imm7_6<<6 | imm5<<5 | imm4_3<<3 | imm2_1<<1
	if disp != 4 {
		t.Errorf("RVC_BRANCH disp = %d, want 4 (raw 0x%x)", disp, got)
	}
}

func TestApplyRISCV64_RVCBranchMisaligned(t *testing.T) {
	_, err := applyRISCV64(rvRVCBranch, rv16inst(0), 0x1000, 0x1001, 0, 0, 0, nil)
	if err == nil || !strings.Contains(err.Error(), "misaligned") {
		t.Errorf("want misaligned, got %v", err)
	}
}

func TestApplyRISCV64_RVCBranchOutOfRange(t *testing.T) {
	_, err := applyRISCV64(rvRVCBranch, rv16inst(0), 0, 1<<10, 0, 0, 0, nil)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("want out-of-range, got %v", err)
	}
}

func TestApplyRISCV64_RVCJump(t *testing.T) {
	// c.j template 0xA001 (op=01, funct3=101)
	b := rv16inst(0xA001)
	if _, err := applyRISCV64(rvRVCJump, b, 0x1000, 0x100C, 0, 0, 0, nil); err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint16(b)
	imm11 := (got >> 12) & 0x1
	imm4 := (got >> 11) & 0x1
	imm9_8 := (got >> 9) & 0x3
	imm10 := (got >> 8) & 0x1
	imm6 := (got >> 7) & 0x1
	imm7 := (got >> 6) & 0x1
	imm3_1 := (got >> 3) & 0x7
	imm5 := (got >> 2) & 0x1
	disp := imm11<<11 | imm10<<10 | imm9_8<<8 | imm7<<7 | imm6<<6 | imm5<<5 | imm4<<4 | imm3_1<<1
	if disp != 0xC {
		t.Errorf("RVC_JUMP disp = 0x%x, want 0xC (raw 0x%x)", disp, got)
	}
}

func TestApplyRISCV64_RVCJumpMisaligned(t *testing.T) {
	_, err := applyRISCV64(rvRVCJump, rv16inst(0), 0x1000, 0x1001, 0, 0, 0, nil)
	if err == nil || !strings.Contains(err.Error(), "misaligned") {
		t.Errorf("want misaligned, got %v", err)
	}
}

func TestApplyRISCV64_RVCJumpOutOfRange(t *testing.T) {
	_, err := applyRISCV64(rvRVCJump, rv16inst(0), 0, 1<<13, 0, 0, 0, nil)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("want out-of-range, got %v", err)
	}
}

func TestApplyRISCV64_ShortBytes(t *testing.T) {
	cases := []struct {
		typ uint16
		min int
	}{
		{rvReloc32, 4}, {rvReloc64, 8}, {rvHi20, 4}, {rvLo12I, 4}, {rvLo12S, 4},
		{rvBranch, 4}, {rvJAL, 4}, {rvCallPLT, 8}, {rvPCRelHi20, 4},
		{rvPCRelLo12I, 4}, {rvRVCBranch, 2}, {rvRVCJump, 2},
	}
	for _, c := range cases {
		_, err := applyRISCV64(c.typ, make([]byte, c.min-1), 0, 0, 0, 0, 0, func(uint64) (uint64, bool) { return 0, true })
		if err == nil {
			t.Errorf("type %d with %d bytes: expected error", c.typ, c.min-1)
		}
	}
}

func TestApplyRISCV64_CallOutOfRange(t *testing.T) {
	_, err := applyRISCV64(rvCallPLT, make([]byte, 8), 0, 1<<32, 0, 0, 0, nil)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("want out-of-range, got %v", err)
	}
}

func TestApplyRISCV64_UnsupportedType(t *testing.T) {
	_, err := applyRISCV64(0x9999, make([]byte, 8), 0, 0, 0, 0, 0, nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("want unsupported, got %v", err)
	}
}
