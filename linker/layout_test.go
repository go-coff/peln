package linker

import (
	"testing"
)

func TestComputeLayout_StubObjects(t *testing.T) {
	const stubDir = "../../../go-coff/stub"
	objs := loadStubObjects(t, stubDir, "arm64")
	if len(objs) == 0 {
		return
	}
	l := ComputeLayout(objs, LayoutOptions{})
	// We must have at least one merged section.
	if len(l.Out) == 0 {
		t.Fatal("no output sections")
	}
	// First section is .text, RVA = SectionAlignment.
	if l.Out[0].Name != ".text" {
		t.Errorf("first section %q, want .text", l.Out[0].Name)
	}
	if l.Out[0].RVA != l.Opts.SectionAlignment {
		t.Errorf(".text RVA = 0x%x, want 0x%x", l.Out[0].RVA, l.Opts.SectionAlignment)
	}
	// Every following section's RVA is strictly greater than the
	// previous, and aligned to SectionAlignment.
	for i := 1; i < len(l.Out); i++ {
		prev, cur := l.Out[i-1], l.Out[i]
		if cur.RVA <= prev.RVA {
			t.Errorf("section %q RVA 0x%x not greater than %q RVA 0x%x",
				cur.Name, cur.RVA, prev.Name, prev.RVA)
		}
		if cur.RVA%l.Opts.SectionAlignment != 0 {
			t.Errorf("section %q RVA 0x%x not aligned", cur.Name, cur.RVA)
		}
	}
	// ResolveRVA(_start) must land somewhere inside .text. _start is
	// EXTERNAL Defined; look it up via per-object symbols.
	for objIdx, obj := range objs {
		for symIdx, sym := range obj.Symbols {
			_ = symIdx
			if sym.Name == "_start" && sym.Kind == SymDefined {
				ref := SectionRef{ObjIdx: objIdx, SecIdx: int(sym.SectionNumber) - 1}
				rva := l.ResolveRVA(ref, sym.Value)
				if rva < l.Out[0].RVA || rva >= l.Out[0].RVA+l.Out[0].VirtualSize {
					t.Errorf("_start RVA 0x%x falls outside .text [0x%x,0x%x)",
						rva, l.Out[0].RVA, l.Out[0].RVA+l.Out[0].VirtualSize)
				}
				return
			}
		}
	}
}
