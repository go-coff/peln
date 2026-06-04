package linker

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestApplyAMD64ELF_None(t *testing.T) {
	for _, typ := range []uint16{rxNone, rxRelax} {
		br, err := applyAMD64ELF(typ, make([]byte, 4), 0, 0, 0, 0, 0)
		if err != nil || br != nil {
			t.Errorf("type %d: %v %v", typ, err, br)
		}
	}
}

func TestApplyAMD64ELF_Abs64(t *testing.T) {
	b := make([]byte, 8)
	br, err := applyAMD64ELF(rxAbs64, b, 0, 0x4000, 0x500, 0x10000, 0x8)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(b); got != 0x4008 {
		t.Errorf("ABS64 = 0x%x, want 0x4008", got)
	}
	if len(br) != 1 || br[0].Type != BaseRelocDir64 {
		t.Errorf("ABS64 should emit DIR64, got %+v", br)
	}
}

func TestApplyAMD64ELF_Abs32(t *testing.T) {
	for _, typ := range []uint16{rxAbs32, rxAbs32S} {
		b := make([]byte, 4)
		br, err := applyAMD64ELF(typ, b, 0, 0x1234, 0x500, 0x10000, 4)
		if err != nil {
			t.Fatalf("type %d: %v", typ, err)
		}
		if got := binary.LittleEndian.Uint32(b); got != 0x1238 {
			t.Errorf("type %d = 0x%x, want 0x1238", typ, got)
		}
		if len(br) != 1 || br[0].Type != BaseRelocHighLow {
			t.Errorf("type %d should emit HIGHLOW, got %+v", typ, br)
		}
	}
}

func TestApplyAMD64ELF_PC32(t *testing.T) {
	// patchVA=0x1000, targetVA=0x2000, addend=-4 → disp=0xFFC.
	for _, typ := range []uint16{rxPC32, rxPLT32} {
		b := make([]byte, 4)
		if _, err := applyAMD64ELF(typ, b, 0x1000, 0x2000, 0, 0x10000, -4); err != nil {
			t.Fatal(err)
		}
		if got := int32(binary.LittleEndian.Uint32(b)); got != 0xFFC {
			t.Errorf("type %d disp = %d, want 0xFFC", typ, got)
		}
	}
}

func TestApplyAMD64ELF_PC32OutOfRange(t *testing.T) {
	_, err := applyAMD64ELF(rxPC32, make([]byte, 4), 0, 1<<32, 0, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("want out-of-range, got %v", err)
	}
}

func TestApplyAMD64ELF_PC64(t *testing.T) {
	b := make([]byte, 8)
	if _, err := applyAMD64ELF(rxPC64, b, 0x1000, 0x5000, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(b); got != 0x4000 {
		t.Errorf("PC64 = 0x%x, want 0x4000", got)
	}
}

func TestApplyAMD64ELF_ShortBytes(t *testing.T) {
	cases := []struct {
		typ uint16
		min int
	}{
		{rxAbs64, 8}, {rxAbs32, 4}, {rxAbs32S, 4},
		{rxPC32, 4}, {rxPLT32, 4}, {rxPC64, 8},
	}
	for _, c := range cases {
		_, err := applyAMD64ELF(c.typ, make([]byte, c.min-1), 0, 0, 0, 0, 0)
		if err == nil {
			t.Errorf("type %d with %d bytes: expected error", c.typ, c.min-1)
		}
	}
}

func TestApplyAMD64ELF_Unsupported(t *testing.T) {
	_, err := applyAMD64ELF(0x9999, make([]byte, 4), 0, 0, 0, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("want unsupported, got %v", err)
	}
}
