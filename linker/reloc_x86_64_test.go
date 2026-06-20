package linker

import (
	"encoding/binary"
	"strings"
	"testing"
)

// rel32Cases covers every IMAGE_REL_AMD64_REL32* variant. The extraAddend
// (the number subtracted from disp in applyAMD64) goes from 4 → 9 across
// the six type codes. We pick patchVA/targetVA so disp evaluates to a
// small, easy-to-eyeball value.
func TestApplyAMD64_Rel32Variants(t *testing.T) {
	cases := []struct {
		typ          uint16
		wantSubtract int32
	}{
		{relAMD64Rel32, 4},
		{relAMD64Rel32_1, 5},
		{relAMD64Rel32_2, 6},
		{relAMD64Rel32_3, 7},
		{relAMD64Rel32_4, 8},
		{relAMD64Rel32_5, 9},
	}
	for _, c := range cases {
		bytes := make([]byte, 4) // 0 in-file addend
		_, err := applyAMD64(c.typ, bytes, 0x1000, 0x2000, 0, 0x10000)
		if err != nil {
			t.Fatalf("type 0x%x: %v", c.typ, err)
		}
		got := int32(binary.LittleEndian.Uint32(bytes))
		// disp = 0x2000 - 0x1000 - extraAddend + 0 = 0x1000 - extraAddend
		want := int32(0x1000 - c.wantSubtract)
		if got != want {
			t.Errorf("type 0x%x: got disp=%d, want %d", c.typ, got, want)
		}
	}
}

func TestApplyAMD64_Rel32WithFileAddend(t *testing.T) {
	bytes := make([]byte, 4)
	fileAddend := int32(-2)
	binary.LittleEndian.PutUint32(bytes, uint32(fileAddend))
	_, err := applyAMD64(relAMD64Rel32, bytes, 0x1000, 0x2000, 0, 0x10000)
	if err != nil {
		t.Fatal(err)
	}
	got := int32(binary.LittleEndian.Uint32(bytes))
	want := int32(0x1000 - 4 - 2)
	if got != want {
		t.Errorf("disp = %d, want %d", got, want)
	}
}

func TestApplyAMD64_Addr64(t *testing.T) {
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, 0x7) // addend
	br, err := applyAMD64(relAMD64Addr64, bytes, 0x1000, 0x4000, 0x500, 0x10000)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(bytes); got != 0x4000+0x7 {
		t.Errorf("addr64 = 0x%x, want 0x%x", got, 0x4007)
	}
	if len(br) != 1 || br[0].Type != BaseRelocDir64 || br[0].RVA != 0x500 {
		t.Errorf("base reloc = %+v, want {RVA:0x500 Type:DIR64}", br)
	}
}

func TestApplyAMD64_Addr32(t *testing.T) {
	bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(bytes, 0x3) // addend
	br, err := applyAMD64(relAMD64Addr32, bytes, 0x1000, 0x2000, 0x500, 0x10000)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(bytes); got != 0x2003 {
		t.Errorf("addr32 = 0x%x, want 0x2003", got)
	}
	if len(br) != 1 || br[0].Type != BaseRelocHighLow {
		t.Errorf("expected one HIGHLOW base reloc, got %+v", br)
	}
}

func TestApplyAMD64_Addr32NB(t *testing.T) {
	bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(bytes, 0x1) // addend
	br, err := applyAMD64(relAMD64Addr32NB, bytes, 0x1000, 0x14000, 0x500, 0x10000)
	if err != nil {
		t.Fatal(err)
	}
	// 0x14000 - 0x10000 = 0x4000; +1 addend → 0x4001
	if got := binary.LittleEndian.Uint32(bytes); got != 0x4001 {
		t.Errorf("addr32nb = 0x%x, want 0x4001", got)
	}
	if len(br) != 0 {
		t.Errorf("addr32nb should not emit base relocs, got %+v", br)
	}
}

func TestApplyAMD64_Absolute(t *testing.T) {
	bytes := []byte{0x11, 0x22, 0x33, 0x44}
	br, err := applyAMD64(relAMD64Absolute, bytes, 0x1000, 0x2000, 0, 0x10000)
	if err != nil || len(br) != 0 {
		t.Errorf("absolute: %v %v", err, br)
	}
	if bytes[0] != 0x11 {
		t.Errorf("absolute should not modify bytes")
	}
}

func TestApplyAMD64_SectionAndSecRel(t *testing.T) {
	for _, typ := range []uint16{relAMD64Section, relAMD64SecRel} {
		br, err := applyAMD64(typ, make([]byte, 4), 0, 0, 0, 0)
		if err != nil || br != nil {
			t.Errorf("type 0x%x: %v %v", typ, err, br)
		}
	}
}

func TestApplyAMD64_Rel32OutOfRange(t *testing.T) {
	bytes := make([]byte, 4)
	// patchVA=0, targetVA=2^32 → disp ~= 2^32 - 4 (way beyond 2^31)
	_, err := applyAMD64(relAMD64Rel32, bytes, 0, 1<<32, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("expected out-of-range error, got %v", err)
	}
}

func TestApplyAMD64_UnsupportedType(t *testing.T) {
	_, err := applyAMD64(0x99, make([]byte, 4), 0, 0, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("expected unsupported-type error, got %v", err)
	}
}

// TestApplyAMD64_ShortPatchBytes verifies that a relocation whose patch bytes
// run past the section end returns an error instead of panicking with an
// out-of-range slice read (the audit's COFF/AMD64 DoS vector).
func TestApplyAMD64_ShortPatchBytes(t *testing.T) {
	cases := []struct {
		name string
		typ  uint16
		n    int // one byte short of what the type needs
	}{
		{"ADDR64", relAMD64Addr64, 7},
		{"ADDR32", relAMD64Addr32, 3},
		{"ADDR32NB", relAMD64Addr32NB, 3},
		{"REL32", relAMD64Rel32, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := applyAMD64(c.typ, make([]byte, c.n), 0x1000, 0x2000, 0, 0x10000); err == nil {
				t.Fatalf("%s: expected error for %d-byte patch, got nil", c.name, c.n)
			}
		})
	}
}
