package linker

import (
	"encoding/binary"
	"strings"
	"testing"
)

// inst writes a single 32-bit ARM64 instruction word into b and returns
// the slice, used as a fresh patch site for each test.
func inst(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func TestApplyARM64_Absolute(t *testing.T) {
	br, err := applyARM64(relARM64Absolute, inst(0xAAAAAAAA), 0, 0, 0, 0)
	if err != nil || br != nil {
		t.Errorf("absolute: %v %v", err, br)
	}
}

func TestApplyARM64_Addr64(t *testing.T) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, 0x5) // addend
	br, err := applyARM64(relARM64Addr64, b, 0x1000, 0x4000, 0x400, 0x10000)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(b); got != 0x4005 {
		t.Errorf("addr64 = 0x%x, want 0x4005", got)
	}
	if len(br) != 1 || br[0].Type != BaseRelocDir64 {
		t.Errorf("expected DIR64 base reloc, got %+v", br)
	}
}

func TestApplyARM64_Addr32(t *testing.T) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, 0x3)
	br, err := applyARM64(relARM64Addr32, b, 0, 0x2000, 0x400, 0x10000)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(b); got != 0x2003 {
		t.Errorf("addr32 = 0x%x, want 0x2003", got)
	}
	if len(br) != 1 || br[0].Type != BaseRelocHighLow {
		t.Errorf("expected HIGHLOW, got %+v", br)
	}
}

func TestApplyARM64_Addr32NB(t *testing.T) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, 0x2)
	br, err := applyARM64(relARM64Addr32NB, b, 0, 0x14000, 0x400, 0x10000)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(b); got != 0x4002 {
		t.Errorf("addr32nb = 0x%x, want 0x4002", got)
	}
	if br != nil {
		t.Errorf("addr32nb should emit no base relocs, got %+v", br)
	}
}

func TestApplyARM64_Branch26(t *testing.T) {
	// patchVA=0x1000, targetVA=0x1010 → disp=16, dispWords=4.
	// BL opcode: 0x94000000, with imm26=4 → 0x94000004.
	b := inst(0x94000000)
	_, err := applyARM64(relARM64Branch26, b, 0x1000, 0x1010, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(b); got != 0x94000004 {
		t.Errorf("branch26 = 0x%x, want 0x94000004", got)
	}
}

func TestApplyARM64_Branch26Misaligned(t *testing.T) {
	_, err := applyARM64(relARM64Branch26, inst(0), 0x1000, 0x1001, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "misaligned") {
		t.Errorf("want misaligned error, got %v", err)
	}
}

func TestApplyARM64_Branch26OutOfRange(t *testing.T) {
	_, err := applyARM64(relARM64Branch26, inst(0), 0, 1<<28, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("want out-of-range, got %v", err)
	}
}

func TestApplyARM64_Branch19(t *testing.T) {
	// CBZ opcode: 0xB4000000, with imm19=4 → 0xB4000080 (imm19 at bits 23:5)
	b := inst(0xB4000000)
	_, err := applyARM64(relARM64Branch19, b, 0x1000, 0x1010, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(b); got != 0xB4000080 {
		t.Errorf("branch19 = 0x%x, want 0xB4000080", got)
	}
}

func TestApplyARM64_Branch19Misaligned(t *testing.T) {
	_, err := applyARM64(relARM64Branch19, inst(0), 0x1000, 0x1001, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "misaligned") {
		t.Errorf("want misaligned, got %v", err)
	}
}

func TestApplyARM64_Branch19OutOfRange(t *testing.T) {
	_, err := applyARM64(relARM64Branch19, inst(0), 0, 1<<21, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("want out-of-range, got %v", err)
	}
}

func TestApplyARM64_PageBaseRel21(t *testing.T) {
	// ADRP: targetVA page 0x2000, patchVA page 0x1000 → pageDisp=1.
	// immLo: 1&3=1 << 29 = 0x20000000; immHi: 0 → result has just immLo.
	b := inst(0x90000000) // ADRP opcode
	_, err := applyARM64(relARM64PageBaseRel21, b, 0x1000, 0x2000, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(b); got != 0xB0000000 {
		t.Errorf("page21 = 0x%x, want 0xB0000000", got)
	}
}

func TestApplyARM64_PageBaseRel21OutOfRange(t *testing.T) {
	// pageDisp = 2^32/4096 = way beyond ±2^20.
	_, err := applyARM64(relARM64PageBaseRel21, inst(0), 0, 1<<33, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("want out-of-range, got %v", err)
	}
}

func TestApplyARM64_Rel21(t *testing.T) {
	// disp = 0x2000 - 0x1000 = 0x1000. immLo=(0x1000&3)<<29=0; immHi=(0x1000>>2)&0x7FFFF<<5=0x400<<5=0x8000
	b := inst(0x10000000) // ADR opcode
	_, err := applyARM64(relARM64Rel21, b, 0x1000, 0x2000, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(b); got != 0x10008000 {
		t.Errorf("rel21 = 0x%x, want 0x10008000", got)
	}
}

func TestApplyARM64_Rel21OutOfRange(t *testing.T) {
	_, err := applyARM64(relARM64Rel21, inst(0), 0, 1<<22, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("want out-of-range, got %v", err)
	}
}

func TestApplyARM64_PageOffset12A(t *testing.T) {
	// ADD with imm12=0x10: 0x91004000. Target page-low = 0x800. result imm12 = (0x800+0x10)&0xFFF = 0x810.
	b := inst(0x91004000)
	_, err := applyARM64(relARM64PageOffset12A, b, 0, 0x800, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint32(b)
	wantImm := uint32(0x810)
	if (got>>10)&0xFFF != wantImm {
		t.Errorf("pageoff12A imm = 0x%x, want 0x%x (raw=0x%x)", (got>>10)&0xFFF, wantImm, got)
	}
}

func TestApplyARM64_PageOffset12L(t *testing.T) {
	// LDR word (size=4, [31:30]=10b → access size = 4).
	// 0xB9400000 base + imm12 (scaled by 4 in encoding). imm12 raw=2 → addendBytes=8.
	// targetVA low12 = 0x10, + 8 → 0x18, divided by 4 = 6.
	b := inst(0xB9400800)
	_, err := applyARM64(relARM64PageOffset12L, b, 0, 0x10, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint32(b)
	scaled := (got >> 10) & 0xFFF
	if scaled != 6 {
		t.Errorf("pageoff12L scaled imm = %d, want 6 (raw=0x%x)", scaled, got)
	}
}

func TestApplyARM64_PageOffset12LMisaligned(t *testing.T) {
	// LDR word (access size 4) but target low12 = 0x12 → not multiple of 4.
	b := inst(0xB9400000)
	_, err := applyARM64(relARM64PageOffset12L, b, 0, 0x12, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "misaligned") {
		t.Errorf("want misaligned, got %v", err)
	}
}

func TestApplyARM64_DebugRelocs(t *testing.T) {
	// SECREL / SECTION / TOKEN / SECREL_LOW12A/HIGH12A/LOW12L all return
	// nil silently.
	for _, typ := range []uint16{
		relARM64Section, relARM64SecRel, relARM64SecRelLow12A,
		relARM64SecRelHigh12A, relARM64SecRelLow12L, relARM64Token,
	} {
		br, err := applyARM64(typ, inst(0), 0, 0, 0, 0)
		if err != nil || br != nil {
			t.Errorf("type 0x%x: %v %v", typ, err, br)
		}
	}
}

func TestApplyARM64_UnsupportedType(t *testing.T) {
	_, err := applyARM64(0x99, inst(0), 0, 0, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("want unsupported, got %v", err)
	}
}

func TestApplyARM64_ShortBytes(t *testing.T) {
	cases := []struct {
		typ uint16
		min int
	}{
		{relARM64Addr64, 8}, {relARM64Addr32, 4}, {relARM64Addr32NB, 4},
		{relARM64Branch26, 4}, {relARM64Branch19, 4}, {relARM64PageBaseRel21, 4},
		{relARM64Rel21, 4}, {relARM64PageOffset12A, 4}, {relARM64PageOffset12L, 4},
	}
	for _, c := range cases {
		_, err := applyARM64(c.typ, make([]byte, c.min-1), 0, 0, 0, 0)
		if err == nil {
			t.Errorf("type 0x%x with %d bytes: expected error", c.typ, c.min-1)
		}
	}
}
