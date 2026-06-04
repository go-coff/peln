package linker

import (
	"debug/elf"
	"fmt"
)

// parseRELA decodes a SHT_RELA section.
//
// On-disk format (ELF64, the only class our supported machines emit):
//
//	uint64 offset | uint64 info | int64 addend  (24 bytes per entry)
//
// info encodes (sym << 32 | type). Reloc type codes for every machine we
// support fit in a uint16, so we reject larger values rather than silently
// truncating. ELF32 input would trip the size-mismatch check below (each
// ELF32 entry is 12 bytes, not 24).
func parseRELA(ef *elf.File, es *elf.Section) ([]Reloc, error) {
	data, err := es.Data()
	if err != nil {
		return nil, fmt.Errorf("read rela.%s: %w", es.Name, err)
	}
	const entrySize = 24
	if len(data)%entrySize != 0 {
		return nil, fmt.Errorf("rela.%s: size %d not a multiple of %d", es.Name, len(data), entrySize)
	}
	bo := ef.ByteOrder
	out := make([]Reloc, 0, len(data)/entrySize)
	for i := 0; i+entrySize <= len(data); i += entrySize {
		off := bo.Uint64(data[i:])
		info := bo.Uint64(data[i+8:])
		addend := int64(bo.Uint64(data[i+16:]))
		symIdx := uint32(info >> 32)
		typ := uint32(info & 0xffffffff)
		if typ > 0xffff {
			return nil, fmt.Errorf("rela.%s entry %d: type 0x%x doesn't fit in uint16", es.Name, i/entrySize, typ)
		}
		out = append(out, Reloc{
			VirtualAddress: uint32(off),
			SymbolIndex:    symIdx,
			Type:           uint16(typ),
			Addend:         addend,
		})
	}
	return out, nil
}
