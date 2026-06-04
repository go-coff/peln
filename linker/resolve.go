package linker

import (
	"fmt"
)

// SectionRef identifies one input section uniquely across all loaded
// objects. The pair (Object index, Section index) is stable for the
// lifetime of a Link() call, so downstream stages can use a SectionRef
// as a map key.
type SectionRef struct {
	ObjIdx int
	SecIdx int
}

// Resolved is one entry in the global symbol table: where the name
// concretely lives once we stop talking about input-relative offsets.
// Section is the input section that contains the symbol; Offset is the
// byte offset of the symbol inside that section. Resolved values are
// turned into absolute RVAs by the layout stage (see layout.go).
type Resolved struct {
	Section SectionRef
	Offset  uint32
	Kind    SymbolKind // SymDefined / SymAbsolute (never SymUndefined)
	Value   uint32     // absolute value when Kind == SymAbsolute
}

// SymTab is the post-resolve global symbol table.
type SymTab struct {
	Entries map[string]Resolved
}

// COFF storage-class constants we branch on. Names mirror the
// IMAGE_SYM_CLASS_* macros from <winnt.h>.
const (
	classExternal     uint8 = 2
	classStatic       uint8 = 3
	classWeakExternal uint8 = 105
)

// ResolveOptions tweaks how strict the resolver is. Mirrors the bits of
// lld-link's surface we actually relied on.
type ResolveOptions struct {
	// AllowUnresolved trades correctness for permissiveness: missing
	// externals are installed as absolute-zero (i.e. relocations target
	// address 0). This is what `lld-link /force:unresolved` does and is
	// what cloud-boot's stub relies on — TinyGo emits unused references
	// (abort, exit, putchar, VirtualAlloc, …) to libc / Windows
	// runtime functions that are never actually reached from _start,
	// so resolving them to 0 is harmless. With AllowUnresolved=false
	// the resolver returns an error listing every missing name.
	AllowUnresolved bool
}

// Resolve walks every loaded object and builds the global symbol table.
// Rules:
//
//   - A symbol with storage class STATIC stays local to its object and
//     never enters the global table. Relocations inside that object
//     still address it via the per-object Symbols slice.
//   - A symbol with class EXTERNAL must either define the name (have a
//     valid section) or be a forward reference resolved by another
//     object's EXTERNAL definition.
//   - Two EXTERNAL definitions of the same name in different objects is
//     an error (we do not implement COMDAT / one-definition rule
//     merging — TinyGo + clang outputs we consume here do not exercise
//     that path).
//   - Class WEAK_EXTERNAL is treated as EXTERNAL with a "use the alias
//     if found, else 0" relaxation. We mark a weak symbol as absolute-
//     value 0 if nothing supplies a definition. Good enough for the
//     stub today; tighter aliasing comes in a follow-up.
//
// On unresolved-external the function returns a single error listing
// every missing name (helpful for diagnostics), not just the first.
func Resolve(objs []*Object, opts ResolveOptions) (*SymTab, error) {
	tab := &SymTab{Entries: map[string]Resolved{}}

	// First pass: install every EXTERNAL definition. Bail on duplicates.
	for objIdx, o := range objs {
		for _, s := range o.Symbols {
			if s.StorageClass != classExternal {
				continue
			}
			if s.Kind == SymUndefined {
				continue // pass 2 handles forward refs
			}
			if prev, dup := tab.Entries[s.Name]; dup {
				return nil, fmt.Errorf("duplicate definition of %q (first in %s, also in %s)",
					s.Name, objs[prev.Section.ObjIdx].Name, o.Name)
			}
			r := Resolved{Kind: s.Kind, Value: s.Value}
			if s.Kind == SymDefined {
				r.Section = SectionRef{ObjIdx: objIdx, SecIdx: int(s.SectionNumber) - 1}
				r.Offset = s.Value
			}
			tab.Entries[s.Name] = r
		}
	}

	// Second pass: check every undefined EXTERNAL resolves, and install
	// weak externals as soft-fail zeros if nothing real defines them.
	var missing []string
	for _, o := range objs {
		for _, s := range o.Symbols {
			switch s.StorageClass {
			case classExternal:
				if s.Kind == SymUndefined {
					if _, ok := tab.Entries[s.Name]; !ok {
						if opts.AllowUnresolved {
							tab.Entries[s.Name] = Resolved{Kind: SymAbsolute, Value: 0}
						} else {
							missing = append(missing, fmt.Sprintf("%q (referenced by %s)", s.Name, o.Name))
						}
					}
				}
			case classWeakExternal:
				if _, ok := tab.Entries[s.Name]; !ok {
					tab.Entries[s.Name] = Resolved{Kind: SymAbsolute, Value: 0}
				}
			}
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("unresolved external symbols: %v", missing)
	}
	return tab, nil
}

// Lookup returns the resolved entry for a relocation that names a
// symbol via its (object, symbolIndex) pair. The two-step resolution
// (per-object symbol → global name → global resolved) keeps the public
// API straightforward: relocations reference symbol indices, and this
// helper hides the lookup chain.
//
// Section-relative relocations are common in COFF and target a symbol
// that just NAMES A SECTION (class STATIC, name == section name). In
// that case the per-object symbol carries its own section/offset and
// the global table is irrelevant — we synthesise a Resolved on the fly.
func (t *SymTab) Lookup(objs []*Object, objIdx int, symIdx uint32) (Resolved, error) {
	o := objs[objIdx]
	if int(symIdx) >= len(o.Symbols) {
		return Resolved{}, fmt.Errorf("%s: relocation references symbol %d, table size %d",
			o.Name, symIdx, len(o.Symbols))
	}
	s := o.Symbols[symIdx]

	// Static / section symbols stay object-local.
	if s.StorageClass == classStatic {
		if s.Kind == SymDefined {
			return Resolved{
				Section: SectionRef{ObjIdx: objIdx, SecIdx: int(s.SectionNumber) - 1},
				Offset:  s.Value,
				Kind:    SymDefined,
			}, nil
		}
		return Resolved{Kind: s.Kind, Value: s.Value}, nil
	}

	// External / weak: fall through to the global table.
	r, ok := t.Entries[s.Name]
	if !ok {
		return Resolved{}, fmt.Errorf("%s: relocation references unresolved symbol %q",
			o.Name, s.Name)
	}
	return r, nil
}
