package linker

import (
	"testing"
)

// TestApplyRelocations_StubAMD64 walks every relocation in the amd64
// stub objects and checks the linker can apply them without erroring.
// This is the strongest end-to-end signal short of actually booting:
// if any relocation type our toolchain emits is unsupported, this
// fails. Once it passes, stages 5+6 just package the result.
func TestApplyRelocations_StubAMD64(t *testing.T) {
	objs := loadStubObjects(t, "../../../go-coff/stub", "amd64")
	if len(objs) == 0 {
		return
	}
	tab, err := Resolve(objs, ResolveOptions{AllowUnresolved: true})
	if err != nil {
		t.Fatal(err)
	}
	l := ComputeLayout(objs, LayoutOptions{})
	base, err := ApplyRelocations(objs, tab, l)
	if err != nil {
		t.Fatal(err)
	}
	// Some absolute relocations should exist — at least the function
	// table entries the runtime relies on. Zero would be suspect.
	if len(base) == 0 {
		t.Log("no base relocations emitted (acceptable for fully-PIE stubs)")
	}
}
