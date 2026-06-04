package linker

import (
	"encoding/binary"
	"sort"
)

// BuildRelocSection serialises a list of base relocations into the byte
// stream that goes inside the .reloc section.
//
// Format (PE/COFF Specification §6.6):
//
//	Block:
//	  uint32 page RVA  (page = 4 KiB)
//	  uint32 block byte size, including the two-word header
//	  uint16 entries[(blockSize-8)/2]
//	    each entry encodes (type<<12) | (offset_within_page & 0xfff)
//
// Blocks are emitted in ascending RVA order. Each block's size is
// padded to a 4-byte boundary with IMAGE_REL_BASED_ABSOLUTE entries
// (type 0, offset 0) so the next block starts aligned.
//
// Returns nil for an empty input — the caller suppresses the .reloc
// section in that case (the resulting PE is fully position-independent
// from the linker's perspective, and EDK2 happily loads it).
func BuildRelocSection(entries []BaseReloc) []byte {
	if len(entries) == 0 {
		return nil
	}
	// Sort by RVA so entries naturally fall into ascending page blocks.
	sorted := make([]BaseReloc, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].RVA < sorted[j].RVA
	})

	var buf []byte
	for i := 0; i < len(sorted); {
		pageRVA := sorted[i].RVA &^ 0xfff
		// Collect every entry that falls in this 4 KiB window.
		j := i
		for j < len(sorted) && sorted[j].RVA&^0xfff == pageRVA {
			j++
		}
		nEntries := j - i

		// Block size = 8-byte header + 2 bytes per entry, padded to 4.
		blockSize := 8 + 2*nEntries
		if blockSize%4 != 0 {
			blockSize += 2 // one IMAGE_REL_BASED_ABSOLUTE padding entry
		}

		hdr := make([]byte, 8)
		binary.LittleEndian.PutUint32(hdr[0:], pageRVA)
		binary.LittleEndian.PutUint32(hdr[4:], uint32(blockSize))
		buf = append(buf, hdr...)

		for k := i; k < j; k++ {
			e := uint16(sorted[k].Type)<<12 | uint16(sorted[k].RVA-pageRVA)&0xfff
			eb := make([]byte, 2)
			binary.LittleEndian.PutUint16(eb, e)
			buf = append(buf, eb...)
		}
		if 8+2*nEntries < blockSize {
			buf = append(buf, 0, 0) // ABSOLUTE padding
		}
		i = j
	}
	return buf
}
