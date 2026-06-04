package linker

import (
	"bytes"
	"os"
	"testing"
)

// TestResolve_StubObjects exercises the resolver over the two .o files
// the cloud-boot pipeline actually link-feeds today (main + thunk).
// They must satisfy each other's externals end-to-end — that is the
// whole job of the linker.
func TestResolve_StubObjects(t *testing.T) {
	const stub = "../../../go-coff/stub"
	objs := loadStubObjects(t, stub, "arm64")
	if len(objs) == 0 {
		return // skipped inside helper
	}
	tab, err := Resolve(objs, ResolveOptions{AllowUnresolved: true})
	if err != nil {
		t.Fatal(err)
	}
	// The thunk-side symbol goLoadFile2 (defined in main) must resolve
	// from the thunk's POV, and loadFile2Ptr (defined in thunk) must
	// resolve from main's POV. If either is missing the linker can
	// never produce a working binary.
	for _, want := range []string{"goLoadFile2", "loadFile2Ptr", "_start"} {
		if _, ok := tab.Entries[want]; !ok {
			t.Errorf("symbol %q not resolved (entries=%d)", want, len(tab.Entries))
		}
	}
}

func TestResolve_UnresolvedExternal(t *testing.T) {
	// Synthetic object that references "missing_sym" without defining
	// it. The resolver must surface that as an error rather than panic.
	o := &Object{
		Name: "fake.o",
		Symbols: []*Symbol{
			{Name: "missing_sym", StorageClass: classExternal, Kind: SymUndefined},
		},
	}
	if _, err := Resolve([]*Object{o}, ResolveOptions{}); err == nil {
		t.Fatal("expected unresolved-external error")
	}
	// Same input, but with AllowUnresolved → symbol resolves to zero.
	tab, err := Resolve([]*Object{o}, ResolveOptions{AllowUnresolved: true})
	if err != nil {
		t.Fatalf("AllowUnresolved should swallow: %v", err)
	}
	if r := tab.Entries["missing_sym"]; r.Kind != SymAbsolute || r.Value != 0 {
		t.Errorf("AllowUnresolved should install absolute-zero, got %+v", r)
	}
}

func TestResolve_DuplicateDefinition(t *testing.T) {
	mk := func(name string) *Object {
		return &Object{
			Name: name + ".o",
			Symbols: []*Symbol{
				{Name: "dup", StorageClass: classExternal, Kind: SymDefined, SectionNumber: 1},
			},
		}
	}
	if _, err := Resolve([]*Object{mk("a"), mk("b")}, ResolveOptions{}); err == nil {
		t.Fatal("expected duplicate-definition error")
	}
}

func TestResolve_WeakFallsBackToZero(t *testing.T) {
	o := &Object{
		Name: "fake.o",
		Symbols: []*Symbol{
			{Name: "maybe", StorageClass: classWeakExternal, Kind: SymUndefined},
		},
	}
	tab, err := Resolve([]*Object{o}, ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	r, ok := tab.Entries["maybe"]
	if !ok {
		t.Fatal("weak external not installed")
	}
	if r.Kind != SymAbsolute || r.Value != 0 {
		t.Errorf("got %+v, want SymAbsolute / 0", r)
	}
}

// loadStubObjects returns the .o pair for an arch if both files are
// present locally; otherwise skips the calling test.
func loadStubObjects(t *testing.T, stubDir, arch string) []*Object {
	t.Helper()
	var coffArch string
	switch arch {
	case "amd64":
		coffArch = "amd64"
	case "arm64":
		coffArch = "arm64"
	default:
		t.Skipf("unknown arch %s", arch)
		return nil
	}
	paths := []string{stubDir + "/main-" + coffArch + ".o", stubDir + "/thunk-" + coffArch + ".o"}
	var objs []*Object
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Skipf("no local .o at %s — build the stub first", p)
			return nil
		}
		o, err := ReadObject(bytes.NewReader(data), p)
		if err != nil {
			t.Fatal(err)
		}
		objs = append(objs, o)
	}
	return objs
}
