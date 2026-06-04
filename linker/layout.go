package linker

import (
	"strings"
)

// IMAGE_SCN_* characteristics flags from <winnt.h>. We only need the
// handful that classify a section's purpose; the alignment bits get
// masked off because the output uses a fixed merge alignment.
const (
	scnCntCode              = 0x00000020
	scnCntInitializedData   = 0x00000040
	scnCntUninitializedData = 0x00000080
	scnAlignMask            = 0x00f00000 // IMAGE_SCN_ALIGN_*
	scnMemDiscardable       = 0x02000000
	scnMemExecute           = 0x20000000
	scnMemRead              = 0x40000000
	scnMemWrite             = 0x80000000
)

// LayoutOptions tweaks the placement pass. Sensible PE32+ defaults are
// applied when fields are zero.
type LayoutOptions struct {
	ImageBase        uint64 // default 0x10000 (matches lld-link's stub default)
	SectionAlignment uint32 // default 0x1000
	FileAlignment    uint32 // default 0x200
	// HeaderReserve is how many bytes the layout pass reserves at the
	// start of the file for the DOS stub + PE headers + section table.
	// Default 0x400 — enough for ~10 sections; bump it if you append
	// many UKI sections post-link via appender.Append().
	HeaderReserve uint32
}

// MergedSection is one output section: a concatenation of every input
// section that maps to the same canonical name (.text, .rdata, .data,
// .bss, or any user-named one like .cmdline). It carries the final RVA
// + file offset assigned by the layout pass.
type MergedSection struct {
	Name            string
	RVA             uint32
	FileOffset      uint32
	VirtualSize     uint32 // unaligned content size, including any BSS overlay
	RawSize         uint32 // file-padded size; 0 for pure-BSS sections
	Characteristics uint32
	Data            []byte // concatenated input bytes; nil for pure-BSS
}

// Layout is what stage 3 returns. Out is the final section list in
// output order; OffsetIn maps each input section to its byte offset
// within the merged output (so RVA(secRef, off) = Out[Where[secRef]].RVA +
// OffsetIn[secRef] + off).
type Layout struct {
	Opts     LayoutOptions
	Out      []*MergedSection
	Where    map[SectionRef]int    // → index into Out
	OffsetIn map[SectionRef]uint32 // → byte offset inside that merged section
}

// canonicalName collapses `.text$mn`, `.text$x` etc. to `.text`. COFF
// uses the `$` suffix for COMDAT subdivisions that the linker is
// expected to merge as one output section.
func canonicalName(n string) string {
	if i := strings.IndexByte(n, '$'); i >= 0 {
		return n[:i]
	}
	return n
}

// outputClass picks one of "text" / "rdata" / "data" / "bss" / "other"
// for a section. Merging is driven by canonical name (the part before
// `$`), not by characteristics: lld-link and link.exe both treat
// `.pdata` as a separate output section even though its flags are
// identical to `.rdata`, and downstream code (REL32 displacements
// computed by the compiler against section symbols) depends on each
// distinct section name keeping its own RVA. Characteristics are only
// consulted for `.text*` to catch the `.text$foo` COMDAT subdivisions.
func outputClass(name string, ch uint32) string {
	cn := canonicalName(name)
	switch cn {
	case ".text":
		return "text"
	case ".rdata", ".rodata", ".xdata":
		// .xdata is x86_64 unwind info; lld-link folds it into .rdata
		// even though some tools list it as a separate section. We
		// follow lld here so REL32 displacements to .xdata records
		// (referenced by .pdata RUNTIME_FUNCTION entries) line up.
		return "rdata"
	case ".data":
		return "data"
	case ".bss":
		return "bss"
	}
	// COMDAT subdivisions like `.text$mn` come through here. Fall back
	// to characteristics for them — anything executable joins .text;
	// anything else stays a distinct passthrough section so lld-link's
	// RVA assignments are reproducible.
	if ch&scnCntCode != 0 || ch&scnMemExecute != 0 {
		return "text"
	}
	return "other"
}

// outputCharacteristics returns the PE characteristics for a merged
// section based on its class. We deliberately strip the IMAGE_SCN_ALIGN_*
// bits because the output uses one consistent alignment per class.
func outputCharacteristics(class string) uint32 {
	switch class {
	case "text":
		return scnCntCode | scnMemExecute | scnMemRead
	case "rdata":
		return scnCntInitializedData | scnMemRead
	case "data":
		return scnCntInitializedData | scnMemRead | scnMemWrite
	case "bss":
		return scnCntUninitializedData | scnMemRead | scnMemWrite
	default:
		// Pass-through: keep the source bits minus alignment.
		return 0
	}
}

// outputName returns the merged section's displayed name. We collapse
// every `.text*` to `.text`, etc. — that's what lld-link does and what
// EFI firmware expects.
func outputName(class, srcName string) string {
	switch class {
	case "text":
		return ".text"
	case "rdata":
		return ".rdata"
	case "data":
		return ".data"
	case "bss":
		return ".bss"
	default:
		return canonicalName(srcName)
	}
}

// classOrder pins the order merged sections appear in the file. Code
// first (so .text RVA = SectionAlignment + headers), then rodata, then
// rw data, then BSS, then anything custom. The order matches what
// lld-link emits and what EFI loaders are used to.
var classOrder = []string{"text", "rdata", "data", "bss"}

// ComputeLayout walks every loaded object, groups sections by class +
// canonical name, and assigns RVAs / file offsets. Custom sections
// (anything not in {.text/.rdata/.data/.bss}) are emitted in the order
// they were first seen.
func ComputeLayout(objs []*Object, opts LayoutOptions) *Layout {
	o := opts
	if o.ImageBase == 0 {
		o.ImageBase = 0x10000
	}
	if o.SectionAlignment == 0 {
		o.SectionAlignment = 0x1000
	}
	if o.FileAlignment == 0 {
		o.FileAlignment = 0x200
	}
	if o.HeaderReserve == 0 {
		o.HeaderReserve = 0x400
	}

	// Bucket input sections by (class, canonical name). The map
	// preserves first-seen order via the customs slice.
	type key struct{ class, name string }
	buckets := map[key]*MergedSection{}
	var customs []key

	addToBucket := func(class, name string, ch uint32, ref SectionRef, sec *Section) (k key) {
		k = key{class, name}
		m, ok := buckets[k]
		if !ok {
			m = &MergedSection{
				Name:            name,
				Characteristics: outputCharacteristics(class),
			}
			if class == "other" {
				// Keep the source-side characteristics (minus alignment
				// bits) so unknown sections still get sensible R/W/X.
				m.Characteristics = ch &^ scnAlignMask
			}
			buckets[k] = m
			if class == "other" {
				customs = append(customs, k)
			}
		}
		return k
	}

	// Pass A: register one bucket per section, accumulating bytes.
	// We hold off on RVA / FileOffset until pass B.
	layout := &Layout{
		Opts:     o,
		Where:    map[SectionRef]int{},
		OffsetIn: map[SectionRef]uint32{},
	}

	// Order inputs within a bucket so the input whose canonical name
	// matches the bucket name comes first (matches lld-link). Within a
	// priority class we keep the natural (object, section) order.
	var entries []inputEntry
	for objIdx, obj := range objs {
		for secIdx, sec := range obj.Sections {
			if canonicalName(sec.Name) == ".drectve" {
				continue
			}
			if sec.Characteristics&scnMemDiscardable != 0 {
				continue
			}
			if sec.VirtualSize == 0 && len(sec.Data) == 0 {
				continue
			}
			class := outputClass(sec.Name, sec.Characteristics)
			bucketClass := class
			if class == "bss" {
				bucketClass = "data"
			}
			bucketName := outputName(bucketClass, sec.Name)
			pri := 1
			if canonicalName(sec.Name) == bucketName {
				pri = 0
			}
			entries = append(entries, inputEntry{objIdx, secIdx, pri})
		}
	}
	// Stable sort: primary key = bucket name, secondary = priority,
	// tertiary = (objIdx, secIdx) preserved.
	sortInputs(entries, objs)

	for _, e := range entries {
		objIdx, secIdx := e.objIdx, e.secIdx
		sec := objs[objIdx].Sections[secIdx]
		{
			class := outputClass(sec.Name, sec.Characteristics)
			// lld-link merges BSS inputs into the .data bucket: the
			// resulting section has Characteristics = INIT_DATA |
			// READ | WRITE and a VirtualSize that exceeds RawSize by
			// the BSS contribution. Anything resolving to a BSS-only
			// symbol therefore lands at .data RVA + dataBytes + bssOff,
			// which is what TinyGo's compiler-generated relocations
			// expect. Forcing class = "data" here keeps the BSS bytes
			// in the same bucket as the initialised data.
			bucketClass := class
			if class == "bss" {
				bucketClass = "data"
			}
			merged := outputName(bucketClass, sec.Name)
			k := addToBucket(bucketClass, merged, sec.Characteristics, SectionRef{objIdx, secIdx}, sec)

			m := buckets[k]
			isBSS := sec.Characteristics&scnCntUninitializedData != 0
			// No padding between inputs in the same bucket: lld-link
			// concatenates them flush, and we mirror that. The COFF
			// inputs themselves are already aligned to whatever the
			// arch requires (4 bytes for arm64/riscv64 instructions,
			// nothing for data). Pad-to-section-alignment happens at
			// the output section boundary, not between inputs.
			var off uint32
			if isBSS {
				// BSS bytes ride on top of any initialised data already
				// in the bucket, but contribute only to VirtualSize.
				off = m.VirtualSize
				m.VirtualSize += sec.VirtualSize
			} else {
				off = uint32(len(m.Data))
				m.Data = append(m.Data, sec.Data...)
				m.VirtualSize = uint32(len(m.Data))
			}
			layout.OffsetIn[SectionRef{objIdx, secIdx}] = off
			layout.Where[SectionRef{objIdx, secIdx}] = -1 // assigned in pass B
		}
	}

	// Pass B: order the merged sections, assign RVA + FileOffset.
	// Pass A's input filtering guarantees every bucket has at least one
	// non-empty input, so we can emit unconditionally.
	emit := func(k key) {
		layout.Out = append(layout.Out, buckets[k])
	}
	for _, c := range classOrder {
		// Class buckets are unique per (class, name) and the four standard
		// classes only ever produce one bucket each (.text / .rdata /
		// .data / .bss). Look them up by both keys to stay future-proof.
		for k := range buckets {
			if k.class == c {
				emit(k)
			}
		}
	}
	for _, k := range customs {
		emit(k)
	}

	// Resolve back-references now that Out is final. Pass A already
	// filtered .drectve / discardable / empty sections out of layout.Where,
	// so we only need to map each remaining ref to its merged output.
	for ref := range layout.Where {
		sec := objs[ref.ObjIdx].Sections[ref.SecIdx]
		class := outputClass(sec.Name, sec.Characteristics)
		if class == "bss" {
			class = "data" // mirror the pass A merge into the .data bucket
		}
		merged := outputName(class, sec.Name)
		for i, m := range layout.Out {
			if m.Name == merged {
				layout.Where[ref] = i
				break
			}
		}
	}

	// Pass C: stride RVAs (page-aligned) and file offsets (FA-aligned).
	rva := alignUp(o.HeaderReserve, o.SectionAlignment)
	foff := alignUp(o.HeaderReserve, o.FileAlignment)
	for _, m := range layout.Out {
		m.RVA = rva
		if m.Characteristics&scnCntUninitializedData != 0 {
			// BSS has no on-disk payload. FileOffset stays at the
			// current file pointer but the file size doesn't grow.
			m.FileOffset = foff
			m.RawSize = 0
		} else {
			m.FileOffset = foff
			m.RawSize = alignUp(uint32(len(m.Data)), o.FileAlignment)
			foff += m.RawSize
		}
		rva += alignUp(m.VirtualSize, o.SectionAlignment)
	}

	return layout
}

// ResolveRVA returns the final image-relative address of (sectionRef,
// offsetWithinInputSection). Useful for relocation fixups in stage 4.
func (l *Layout) ResolveRVA(ref SectionRef, offsetInInput uint32) uint32 {
	out := l.Out[l.Where[ref]]
	return out.RVA + l.OffsetIn[ref] + offsetInInput
}

// inputEntry is one (object, section) tuple plus its bucket priority,
// pre-computed by Pass A so sortInputs can stable-sort without
// re-classifying every entry.
type inputEntry struct {
	objIdx, secIdx int
	priority       int // 0 = canonical name matches bucket, 1 = alias
}

// sortInputs orders the (objIdx, secIdx, priority) tuples so that, within
// any given output bucket, entries whose canonical input name matches
// the bucket name come first. This mirrors lld-link's input order
// (.rdata bytes before .xdata bytes inside the .rdata bucket, .data
// bytes before .bss bytes inside the .data bucket). The sort is stable
// w.r.t. (objIdx, secIdx) so two same-priority entries keep their
// natural file order.
func sortInputs(es []inputEntry, objs []*Object) {
	// Build a bucket key (the merged output name) for each entry so the
	// primary sort axis is well-defined.
	bucket := func(e inputEntry) string {
		sec := objs[e.objIdx].Sections[e.secIdx]
		class := outputClass(sec.Name, sec.Characteristics)
		if class == "bss" {
			class = "data"
		}
		return outputName(class, sec.Name)
	}
	// Stable sort with three keys.
	for i := 1; i < len(es); i++ {
		for j := i; j > 0; j-- {
			a, b := es[j-1], es[j]
			ba, bb := bucket(a), bucket(b)
			if ba < bb {
				break
			}
			if ba > bb {
				es[j-1], es[j] = b, a
				continue
			}
			if a.priority < b.priority {
				break
			}
			if a.priority > b.priority {
				es[j-1], es[j] = b, a
				continue
			}
			// Same bucket, same priority: keep original (objIdx, secIdx)
			// order, which means a stays before b — we are sorted.
			break
		}
	}
}

func alignUp(v, a uint32) uint32 {
	return (v + a - 1) &^ (a - 1)
}
