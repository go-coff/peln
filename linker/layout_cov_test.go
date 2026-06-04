package linker

import (
	"testing"
)

// TestComputeLayout_SortInputs feeds ComputeLayout an object whose
// sections are deliberately out of canonical bucket order so the
// insertion sort in sortInputs must perform real reordering. This drives
// every comparison arm of sortInputs:
//
//   - ba > bb               (bucket swap: a later, smaller bucket name moves up)
//   - ba < bb               (break: entries already in bucket order)
//   - a.priority > b.priority (swap within a bucket: canonical before alias)
//   - a.priority < b.priority (break within a bucket: alias after canonical)
//
// Bucket names compare as strings: ".data" < ".rdata" < ".text".
// Within the .rdata bucket, ".rdata" has priority 0 and ".xdata" (which
// also folds into .rdata) has priority 1.
func TestComputeLayout_SortInputs(t *testing.T) {
	obj := &Object{
		Name:    "x.o",
		Machine: MachineAMD64,
		Sections: []*Section{
			// 0: .data bucket — already first; when later .rdata/.text are
			//    inserted they compare against it with ba(.data)<bb(.rdata/.text)
			//    and break immediately (drives the ba<bb break arm).
			{Name: ".data", Characteristics: scnCntInitializedData | scnMemWrite, Data: []byte{0xD0}, VirtualSize: 1},
			// 1: .text bucket — appears before .rdata though it sorts after,
			//    so .rdata must bubble in front of it (drives the ba>bb swap).
			{Name: ".text", Characteristics: scnCntCode | scnMemExecute, Data: []byte{0x90}, VirtualSize: 1},
			// 2: second .text, canonical name, same bucket + same priority as
			//    section 1 → the inner loop ends on the same-bucket/same-
			//    priority break (line 389), preserving natural order.
			{Name: ".text", Characteristics: scnCntCode | scnMemExecute, Data: []byte{0x91}, VirtualSize: 1},
			// 3: .rdata bucket, alias name → priority 1.
			{Name: ".xdata", Characteristics: scnCntInitializedData, Data: []byte{0xCC}, VirtualSize: 1},
			// 4: .rdata bucket, canonical name → priority 0; must move ahead
			//    of .xdata (drives the priority-swap arm) and bubble past the
			//    two .text entries (ba>bb) until it meets .data (ba>bb again).
			{Name: ".rdata", Characteristics: scnCntInitializedData, Data: []byte{0xC0}, VirtualSize: 1},
		},
	}
	l := ComputeLayout([]*Object{obj}, LayoutOptions{})

	// All three buckets must exist and follow classOrder (text, rdata, data).
	var textRVA, rdataRVA, dataRVA uint32
	var haveText, haveRdata, haveData bool
	var rdataData, textData []byte
	for _, m := range l.Out {
		switch m.Name {
		case ".text":
			textRVA, haveText, textData = m.RVA, true, m.Data
		case ".rdata":
			rdataRVA, haveRdata, rdataData = m.RVA, true, m.Data
		case ".data":
			dataRVA, haveData = m.RVA, true
		}
	}
	if !haveText || !haveRdata || !haveData {
		t.Fatalf("missing buckets: text=%v rdata=%v data=%v", haveText, haveRdata, haveData)
	}
	// classOrder pins text < rdata < data by RVA regardless of input order.
	if !(textRVA < rdataRVA && rdataRVA < dataRVA) {
		t.Errorf("bucket RVA order wrong: text=0x%x rdata=0x%x data=0x%x", textRVA, rdataRVA, dataRVA)
	}

	// Within the .rdata bucket, the canonical .rdata input (0xC0) must come
	// before the .xdata alias (0xCC) — proving the priority swap ran.
	if len(rdataData) != 2 || rdataData[0] != 0xC0 || rdataData[1] != 0xCC {
		t.Errorf(".rdata merged data = % x, want C0 CC (canonical before alias)", rdataData)
	}

	// The two same-bucket/same-priority .text inputs keep their natural
	// order (0x90 then 0x91) — the line-389 break path.
	if len(textData) != 2 || textData[0] != 0x90 || textData[1] != 0x91 {
		t.Errorf(".text merged data = % x, want 90 91 (stable natural order)", textData)
	}
}
