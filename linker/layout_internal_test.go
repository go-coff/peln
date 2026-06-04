package linker

import (
	"testing"
)

func TestCanonicalName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{".text", ".text"},
		{".text$mn", ".text"},
		{"$leading", ""},
		{"trailing$", "trailing"},
		{"a$b$c", "a"},
	}
	for _, c := range cases {
		if got := canonicalName(c.in); got != c.want {
			t.Errorf("canonicalName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestOutputClass(t *testing.T) {
	cases := []struct {
		name string
		ch   uint32
		want string
	}{
		{".text", 0, "text"},
		{".text$mn", scnMemExecute, "text"},
		{".rdata", 0, "rdata"},
		{".rodata", 0, "rdata"},
		{".xdata", 0, "rdata"},
		{".data", 0, "data"},
		{".bss", 0, "bss"},
		{".pdata", 0, "other"},
		{".custom$x", scnCntCode, "text"}, // COMDAT executable falls through
		{".custom$x", scnMemExecute, "text"},
		{".unknown$x", 0, "other"},
	}
	for _, c := range cases {
		if got := outputClass(c.name, c.ch); got != c.want {
			t.Errorf("outputClass(%q, 0x%x) = %q, want %q", c.name, c.ch, got, c.want)
		}
	}
}

func TestOutputCharacteristics(t *testing.T) {
	cases := []struct {
		class string
		want  uint32
	}{
		{"text", scnCntCode | scnMemExecute | scnMemRead},
		{"rdata", scnCntInitializedData | scnMemRead},
		{"data", scnCntInitializedData | scnMemRead | scnMemWrite},
		{"bss", scnCntUninitializedData | scnMemRead | scnMemWrite},
		{"other", 0},
	}
	for _, c := range cases {
		if got := outputCharacteristics(c.class); got != c.want {
			t.Errorf("outputCharacteristics(%q) = 0x%x, want 0x%x", c.class, got, c.want)
		}
	}
}

func TestOutputName(t *testing.T) {
	cases := []struct {
		class, src, want string
	}{
		{"text", ".text$mn", ".text"},
		{"rdata", ".xdata", ".rdata"},
		{"data", ".data", ".data"},
		{"bss", ".bss", ".bss"},
		{"other", ".cmdline$x", ".cmdline"},
	}
	for _, c := range cases {
		if got := outputName(c.class, c.src); got != c.want {
			t.Errorf("outputName(%q, %q) = %q, want %q", c.class, c.src, got, c.want)
		}
	}
}

// TestComputeLayout_Synthetic exercises layout with a hand-built object
// graph that hits every classification branch: .text, .rdata, .data, .bss,
// a custom section, plus a discardable + .drectve that should be dropped.
func TestComputeLayout_Synthetic(t *testing.T) {
	obj := &Object{
		Name:    "x.o",
		Machine: MachineAMD64,
		Sections: []*Section{
			{Name: ".text", Characteristics: scnCntCode | scnMemExecute, Data: []byte{0x90, 0x90}, VirtualSize: 2},
			{Name: ".rdata", Characteristics: scnCntInitializedData, Data: []byte{0x01}, VirtualSize: 1},
			{Name: ".data", Characteristics: scnCntInitializedData | scnMemWrite, Data: []byte{0x02, 0x03}, VirtualSize: 2},
			{Name: ".bss", Characteristics: scnCntUninitializedData, VirtualSize: 16},
			{Name: ".drectve", Characteristics: scnMemDiscardable, Data: []byte{0xCC}, VirtualSize: 1},
			{Name: ".debug$S", Characteristics: scnMemDiscardable, Data: []byte{0xDD}, VirtualSize: 1},
			{Name: ".cmdline", Characteristics: scnCntInitializedData, Data: []byte("cli"), VirtualSize: 3},
		},
	}
	l := ComputeLayout([]*Object{obj}, LayoutOptions{})
	// Expect .text, .rdata, .data (with BSS overlay), .cmdline.
	got := map[string]bool{}
	for _, m := range l.Out {
		got[m.Name] = true
	}
	for _, want := range []string{".text", ".rdata", ".data", ".cmdline"} {
		if !got[want] {
			t.Errorf("missing output section %q", want)
		}
	}
	if got[".drectve"] || got[".debug$S"] {
		t.Errorf("discardable section was not stripped: %v", got)
	}
	// VirtualSize on the merged .data must include the 16 BSS bytes.
	for _, m := range l.Out {
		if m.Name == ".data" && m.VirtualSize < 16 {
			t.Errorf(".data VirtualSize = %d, expected ≥16 (BSS contribution)", m.VirtualSize)
		}
	}
}

// TestComputeLayout_EmptySectionSkipped: a section with no data and zero
// VirtualSize gets dropped entirely.
func TestComputeLayout_EmptySectionSkipped(t *testing.T) {
	obj := &Object{
		Name:    "empty.o",
		Machine: MachineAMD64,
		Sections: []*Section{
			{Name: ".text", Characteristics: scnCntCode, Data: []byte{0x90}, VirtualSize: 1},
			{Name: ".empty", Characteristics: scnCntInitializedData},
		},
	}
	l := ComputeLayout([]*Object{obj}, LayoutOptions{})
	for _, m := range l.Out {
		if m.Name == ".empty" {
			t.Errorf(".empty section should have been dropped, got %+v", m)
		}
	}
}
