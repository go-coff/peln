package linker

import (
	"encoding/binary"
	"strings"
	"testing"
)

func ainst(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func TestApplyARM64ELF_None(t *testing.T) {
	br, err := applyARM64ELF(raNone, ainst(0xAA), 0, 0, 0, 0, 0)
	if err != nil || br != nil {
		t.Errorf("None: %v %v", err, br)
	}
}

func TestApplyARM64ELF_Abs64(t *testing.T) {
	b := make([]byte, 8)
	br, err := applyARM64ELF(raAbs64, b, 0, 0x4000, 0x400, 0x10000, 0x8)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(b); got != 0x4008 {
		t.Errorf("ABS64 = 0x%x, want 0x4008", got)
	}
	if len(br) != 1 || br[0].Type != BaseRelocDir64 {
		t.Errorf("expected DIR64 base reloc")
	}
}

func TestApplyARM64ELF_Abs32(t *testing.T) {
	b := make([]byte, 4)
	br, err := applyARM64ELF(raAbs32, b, 0, 0x2000, 0x400, 0x10000, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(b); got != 0x2003 {
		t.Errorf("ABS32 = 0x%x", got)
	}
	if len(br) != 1 || br[0].Type != BaseRelocHighLow {
		t.Errorf("expected HIGHLOW")
	}
}

func TestApplyARM64ELF_Abs16(t *testing.T) {
	b := make([]byte, 2)
	if _, err := applyARM64ELF(raAbs16, b, 0, 0x1234, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint16(b); got != 0x1234 {
		t.Errorf("ABS16 = 0x%x", got)
	}
}

func TestApplyARM64ELF_PRel32(t *testing.T) {
	b := make([]byte, 4)
	if _, err := applyARM64ELF(raPRel32, b, 0x1000, 0x5000, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if got := int32(binary.LittleEndian.Uint32(b)); got != 0x4000 {
		t.Errorf("PREL32 = %d", got)
	}
}

func TestApplyARM64ELF_PRel64(t *testing.T) {
	b := make([]byte, 8)
	if _, err := applyARM64ELF(raPRel64, b, 0x1000, 0x9000, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(b); got != 0x8000 {
		t.Errorf("PREL64 = 0x%x", got)
	}
}

func TestApplyARM64ELF_PRel16(t *testing.T) {
	b := make([]byte, 2)
	if _, err := applyARM64ELF(raPRel16, b, 0x1000, 0x1010, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint16(b); got != 0x10 {
		t.Errorf("PREL16 = 0x%x", got)
	}
}

func TestApplyARM64ELF_Call26(t *testing.T) {
	// BL template + dispWords = 4 → bottom of imm26 = 4.
	for _, typ := range []uint16{raCall26, raJump26} {
		b := ainst(0x94000000)
		if _, err := applyARM64ELF(typ, b, 0x1000, 0x1010, 0, 0, 0); err != nil {
			t.Fatalf("type %d: %v", typ, err)
		}
		got := binary.LittleEndian.Uint32(b)
		if got&0x03FFFFFF != 4 {
			t.Errorf("type %d imm26 = 0x%x", typ, got&0x03FFFFFF)
		}
	}
}

func TestApplyARM64ELF_Call26Misaligned(t *testing.T) {
	_, err := applyARM64ELF(raCall26, ainst(0), 0x1000, 0x1001, 0, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "misaligned") {
		t.Errorf("want misaligned, got %v", err)
	}
}

func TestApplyARM64ELF_Call26OutOfRange(t *testing.T) {
	_, err := applyARM64ELF(raCall26, ainst(0), 0, 1<<28, 0, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("want out-of-range, got %v", err)
	}
}

func TestApplyARM64ELF_CondBr19(t *testing.T) {
	b := ainst(0x54000000) // B.cond template
	if _, err := applyARM64ELF(raCondBr19, b, 0x1000, 0x1010, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint32(b)
	if (got>>5)&0x7FFFF != 4 {
		t.Errorf("CONDBR19 imm = 0x%x", (got>>5)&0x7FFFF)
	}
}

func TestApplyARM64ELF_CondBr19Misaligned(t *testing.T) {
	_, err := applyARM64ELF(raCondBr19, ainst(0), 0x1000, 0x1001, 0, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "misaligned") {
		t.Errorf("want misaligned, got %v", err)
	}
}

func TestApplyARM64ELF_CondBr19OutOfRange(t *testing.T) {
	_, err := applyARM64ELF(raCondBr19, ainst(0), 0, 1<<21, 0, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("want out-of-range, got %v", err)
	}
}

func TestApplyARM64ELF_TstBr14(t *testing.T) {
	b := ainst(0x36000000) // TBZ template
	if _, err := applyARM64ELF(raTstBr14, b, 0x1000, 0x1010, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint32(b)
	if (got>>5)&0x3FFF != 4 {
		t.Errorf("TSTBR14 imm = 0x%x", (got>>5)&0x3FFF)
	}
}

func TestApplyARM64ELF_TstBr14Misaligned(t *testing.T) {
	_, err := applyARM64ELF(raTstBr14, ainst(0), 0x1000, 0x1001, 0, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "misaligned") {
		t.Errorf("want misaligned, got %v", err)
	}
}

func TestApplyARM64ELF_TstBr14OutOfRange(t *testing.T) {
	_, err := applyARM64ELF(raTstBr14, ainst(0), 0, 1<<16, 0, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("want out-of-range, got %v", err)
	}
}

func TestApplyARM64ELF_AdrPRelPG(t *testing.T) {
	// patchVA=0x1000, target=0x12345 → pages 0x0 vs 0x12, pageDisp=0x12.
	b := ainst(0x90000000) // ADRP
	if _, err := applyARM64ELF(raAdrPRelPG, b, 0x1000, 0x12345, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	// pageDisp=0x12, immLo=(0x12&3)<<29=0x40000000, immHi=(0x12>>2)<<5=0x80
	got := binary.LittleEndian.Uint32(b)
	if got != 0xB0000080 {
		t.Errorf("ADRP = 0x%x", got)
	}
}

func TestApplyARM64ELF_AdrPRelPGOutOfRange(t *testing.T) {
	_, err := applyARM64ELF(raAdrPRelPG, ainst(0), 0, 1<<33, 0, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("want out-of-range, got %v", err)
	}
}

func TestApplyARM64ELF_AdrPRel21(t *testing.T) {
	b := ainst(0x10000000) // ADR
	if _, err := applyARM64ELF(raAdrPRel21, b, 0x1000, 0x2000, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	// disp=0x1000, immLo=0, immHi=(0x1000>>2)<<5 = 0x400<<5 = 0x8000
	if got := binary.LittleEndian.Uint32(b); got != 0x10008000 {
		t.Errorf("ADR = 0x%x", got)
	}
}

func TestApplyARM64ELF_AdrPRel21OutOfRange(t *testing.T) {
	_, err := applyARM64ELF(raAdrPRel21, ainst(0), 0, 1<<22, 0, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("want out-of-range, got %v", err)
	}
}

func TestApplyARM64ELF_AddLo12(t *testing.T) {
	b := ainst(0x91000000) // ADD imm12=0
	if _, err := applyARM64ELF(raAddLo12, b, 0, 0x12345, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint32(b)
	if (got>>10)&0xFFF != 0x345 {
		t.Errorf("ADD imm12 = 0x%x", (got>>10)&0xFFF)
	}
}

func TestApplyARM64ELF_LDSTLo12(t *testing.T) {
	cases := []struct {
		typ   uint16
		scale uint32
	}{
		{raLdSt8Lo12, 1},
		{raLdSt16Lo12, 2},
		{raLdSt32Lo12, 4},
		{raLdSt64Lo12, 8},
		{raLdSt128Lo12, 16},
	}
	for _, c := range cases {
		b := ainst(0xF9400000) // LDR template
		// Pick target with low12 = scale × 3 so it's aligned.
		target := uint64(c.scale * 3)
		if _, err := applyARM64ELF(c.typ, b, 0, target, 0, 0, 0); err != nil {
			t.Fatalf("scale=%d: %v", c.scale, err)
		}
		got := binary.LittleEndian.Uint32(b)
		scaled := (got >> 10) & 0xFFF
		if scaled != 3 {
			t.Errorf("scale=%d scaled imm = %d, want 3", c.scale, scaled)
		}
	}
}

func TestApplyARM64ELF_LDSTLo12Misaligned(t *testing.T) {
	// LDR32 (scale 4) with low12 = 2 → not multiple of 4.
	_, err := applyARM64ELF(raLdSt32Lo12, ainst(0xB9400000), 0, 0x2, 0, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "misaligned") {
		t.Errorf("want misaligned, got %v", err)
	}
}

func TestApplyARM64ELF_ShortBytes(t *testing.T) {
	cases := []struct {
		typ uint16
		min int
	}{
		{raAbs64, 8}, {raAbs32, 4}, {raAbs16, 2},
		{raPRel64, 8}, {raPRel32, 4}, {raPRel16, 2},
		{raCall26, 4}, {raCondBr19, 4}, {raTstBr14, 4},
		{raAdrPRelPG, 4}, {raAdrPRel21, 4}, {raAddLo12, 4},
		{raLdSt32Lo12, 4},
	}
	for _, c := range cases {
		_, err := applyARM64ELF(c.typ, make([]byte, c.min-1), 0, 0, 0, 0, 0)
		if err == nil {
			t.Errorf("type %d with %d bytes: expected error", c.typ, c.min-1)
		}
	}
}

func TestApplyARM64ELF_Unsupported(t *testing.T) {
	_, err := applyARM64ELF(0x9999, ainst(0), 0, 0, 0, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("want unsupported, got %v", err)
	}
}
