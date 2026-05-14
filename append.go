// Package pe is a tiny pure-Go appender for sections to a PE32/PE32+
// image. It is the equivalent of `objcopy --add-section`, restricted to the
// case that matters for UEFI Unified Kernel Images: appending new sections
// at the end of the file, leaving every existing section's RVA, file offset
// and data untouched.
//
// The package only depends on the standard library and is intentionally
// small so it can be vendored or audited in one sitting.
//
// References:
//   - Microsoft PE/COFF specification rev 11+
//   - systemd-stub PE annex
//
// Limitations:
//   - Section names are limited to 8 bytes (PE truncates longer names via a
//     string table that this package does not write).
//   - SizeOfHeaders is not grown, so the input PE must reserve enough header
//     padding to hold the added section-header entries. The systemd UEFI
//     stubs (`linux{x64,aa64,riscv64}.efi.stub`) all reserve plenty.
//   - The Optional Header CheckSum field is zeroed; UEFI does not enforce it
//     and recomputing requires the full PE checksum algorithm. Tools that
//     need a valid checksum (e.g. Secure Boot signers) should run their own
//     pass afterwards.
package pe

import (
	"encoding/binary"
	"fmt"
)

// IMAGE_SCN_* characteristics.
const (
	SCN_CNT_INITIALIZED_DATA uint32 = 0x00000040
	SCN_MEM_READ             uint32 = 0x40000000
	SCN_MEM_WRITE            uint32 = 0x80000000
	SCN_MEM_EXECUTE          uint32 = 0x20000000

	// DefaultCharacteristics is the set of flags objcopy applies to a
	// `--add-section` of an arbitrary binary blob: read-only initialised data.
	DefaultCharacteristics = SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ
)

// Section describes one new section to append.
type Section struct {
	Name            string // up to 8 bytes; longer names are rejected
	Data            []byte
	Characteristics uint32 // see SCN_* constants; DefaultCharacteristics is fine
}

// Append takes a PE32 / PE32+ binary `stub` and returns a new image with
// `sections` appended after the last existing section. Existing section data
// is preserved byte-for-byte; only NumberOfSections, SizeOfImage and the new
// section-table entries are written. The PE CheckSum field is zeroed.
//
// Returns an error if the section table cannot grow inside SizeOfHeaders,
// or if any input field is malformed.
func Append(stub []byte, sections []Section) ([]byte, error) {
	if len(stub) < 0x40 {
		return nil, fmt.Errorf("pe: input too short (%d bytes)", len(stub))
	}
	if stub[0] != 'M' || stub[1] != 'Z' {
		return nil, fmt.Errorf("pe: input is not a PE/MZ image")
	}
	pf, err := parse(stub)
	if err != nil {
		return nil, err
	}

	// Validate section names.
	for _, s := range sections {
		if len(s.Name) > 8 {
			return nil, fmt.Errorf("pe: section name %q exceeds 8 bytes", s.Name)
		}
	}

	// The section table starts immediately after the optional header.
	secTableStart := pf.optOff + int(pf.sizeOfOpt)
	secTableEndCurrent := secTableStart + int(pf.numSections)*40
	secTableEndNew := secTableEndCurrent + len(sections)*40
	if uint32(secTableEndNew) > pf.sizeOfHeaders {
		return nil, fmt.Errorf(
			"pe: section table would overflow SizeOfHeaders (need %d, available %d)",
			secTableEndNew, pf.sizeOfHeaders)
	}

	// Compute the next-available VirtualAddress and PointerToRawData.
	var (
		nextVA     uint32
		maxFileEnd uint32
	)
	for i := 0; i < int(pf.numSections); i++ {
		off := secTableStart + i*40
		va := binary.LittleEndian.Uint32(stub[off+12:])
		vs := binary.LittleEndian.Uint32(stub[off+8:])
		ptr := binary.LittleEndian.Uint32(stub[off+20:])
		size := binary.LittleEndian.Uint32(stub[off+16:])

		if end := alignUp(va+vs, pf.sectionAlign); end > nextVA {
			nextVA = end
		}
		if end := ptr + size; end > maxFileEnd {
			maxFileEnd = end
		}
	}
	if nextVA == 0 {
		nextVA = alignUp(pf.sizeOfHeaders, pf.sectionAlign)
	}
	nextFile := alignUp(maxFileEnd, pf.fileAlign)
	if nextFile < alignUp(pf.sizeOfHeaders, pf.fileAlign) {
		nextFile = alignUp(pf.sizeOfHeaders, pf.fileAlign)
	}

	// Construct new section headers + concatenated raw data.
	newHeaders := make([]byte, 0, len(sections)*40)
	appended := make([]byte, 0)
	for _, s := range sections {
		vs := uint32(len(s.Data))
		srd := alignUp(vs, pf.fileAlign)

		var hdr [40]byte
		copy(hdr[0:8], s.Name)
		binary.LittleEndian.PutUint32(hdr[8:12], vs)
		binary.LittleEndian.PutUint32(hdr[12:16], nextVA)
		binary.LittleEndian.PutUint32(hdr[16:20], srd)
		binary.LittleEndian.PutUint32(hdr[20:24], nextFile)
		// PointerToRelocations / Linenumbers, NumberOfRelocations / Linenumbers
		// remain zero — correct for image sections.
		binary.LittleEndian.PutUint32(hdr[36:40], s.Characteristics)
		newHeaders = append(newHeaders, hdr[:]...)

		appended = append(appended, s.Data...)
		if pad := int(srd) - len(s.Data); pad > 0 {
			appended = append(appended, make([]byte, pad)...)
		}

		nextVA = alignUp(nextVA+vs, pf.sectionAlign)
		nextFile += srd
	}

	// Build the output. We modify a copy of stub to avoid surprising the caller.
	out := make([]byte, len(stub))
	copy(out, stub)

	// NumberOfSections (COFF File Header offset 2..3, relative to COFF start).
	binary.LittleEndian.PutUint16(out[pf.coffOff+2:], pf.numSections+uint16(len(sections)))

	// SizeOfImage (optional header offset 56..59, PE32+ and PE32 share layout
	// up to that point).
	binary.LittleEndian.PutUint32(out[pf.optOff+56:], nextVA)

	// CheckSum — zero it (UEFI doesn't enforce it).
	binary.LittleEndian.PutUint32(out[pf.optOff+64:], 0)

	// Insert the new section headers into the section table.
	copy(out[secTableEndCurrent:], newHeaders)

	// Pad/truncate the body to nextFile (where the first appended section
	// starts) and append the new section data.
	aligned := nextFile - uint32(len(appended))
	switch {
	case uint32(len(out)) > aligned:
		out = out[:aligned]
	case uint32(len(out)) < aligned:
		out = append(out, make([]byte, int(aligned)-len(out))...)
	}
	out = append(out, appended...)
	return out, nil
}

// parsedPE is the small subset of fields we need to add sections.
type parsedPE struct {
	coffOff       int    // file offset of the COFF File Header
	optOff        int    // file offset of the Optional Header
	numSections   uint16 // COFF.NumberOfSections
	sizeOfOpt     uint16 // COFF.SizeOfOptionalHeader
	magic         uint16 // 0x10B = PE32, 0x20B = PE32+
	sectionAlign  uint32 // OptionalHeader.SectionAlignment
	fileAlign     uint32 // OptionalHeader.FileAlignment
	sizeOfHeaders uint32 // OptionalHeader.SizeOfHeaders
}

func parse(stub []byte) (*parsedPE, error) {
	elfanew := binary.LittleEndian.Uint32(stub[0x3C:])
	if int(elfanew)+24 > len(stub) {
		return nil, fmt.Errorf("pe: truncated PE header (e_lfanew=%d)", elfanew)
	}
	if string(stub[elfanew:elfanew+4]) != "PE\x00\x00" {
		return nil, fmt.Errorf("pe: missing PE signature at offset %d", elfanew)
	}
	// The earlier `elfanew+24 > len(stub)` check already ensures the full
	// 4-byte signature plus 20-byte COFF header fit, so coffOff+20 is in range.
	coffOff := int(elfanew) + 4
	numSections := binary.LittleEndian.Uint16(stub[coffOff+2:])
	sizeOfOpt := binary.LittleEndian.Uint16(stub[coffOff+16:])
	optOff := coffOff + 20
	if optOff+int(sizeOfOpt) > len(stub) {
		return nil, fmt.Errorf("pe: truncated optional header")
	}
	if sizeOfOpt < 68 {
		return nil, fmt.Errorf("pe: optional header too small (%d)", sizeOfOpt)
	}
	magic := binary.LittleEndian.Uint16(stub[optOff:])
	if magic != 0x10B && magic != 0x20B {
		return nil, fmt.Errorf("pe: unsupported PE magic 0x%04X", magic)
	}
	return &parsedPE{
		coffOff:       coffOff,
		optOff:        optOff,
		numSections:   numSections,
		sizeOfOpt:     sizeOfOpt,
		magic:         magic,
		sectionAlign:  binary.LittleEndian.Uint32(stub[optOff+32:]),
		fileAlign:     binary.LittleEndian.Uint32(stub[optOff+36:]),
		sizeOfHeaders: binary.LittleEndian.Uint32(stub[optOff+60:]),
	}, nil
}

func alignUp(v, align uint32) uint32 {
	if align == 0 {
		return v
	}
	rem := v % align
	if rem == 0 {
		return v
	}
	return v + (align - rem)
}
