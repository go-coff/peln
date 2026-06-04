// Package fwimg produces bare-metal / firmware images in pure Go, with no
// dependency on binutils (objcopy), srec_cat or U-Boot's mkimage.
//
// It complements go-coff/peln/linker (which targets UEFI PE32+/EFI) with
// the non-UEFI output formats a flat-loaded bare-metal target needs:
//
//   - Flatten: an ELF executable → a flat binary (objcopy -O binary),
//     for images a bootloader/ROM loads at a fixed address (Raspberry Pi
//     kernel.img, QEMU -kernel, flash images);
//   - SREC / IHEX: Motorola S-record and Intel HEX text encodings, for
//     flashing tools and ROM programmers;
//   - UImage: the legacy U-Boot image header, for boards booted via
//     `bootm` (e.g. NXP i.MX).
package fwimg

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"sort"
)

// FlattenOptions controls Flatten.
type FlattenOptions struct {
	// UseVaddr places each segment by its virtual address (p_vaddr)
	// instead of its load address (p_paddr, the objcopy default). For most
	// bare-metal ELFs the two are equal.
	UseVaddr bool
	// Pad is the byte used to fill gaps between segments (default 0).
	Pad byte
}

// Flatten converts an ELF executable into a flat binary image, mirroring
// `objcopy -O binary`: every PT_LOAD segment with file content is placed
// at its load address relative to the lowest such address, and the gaps
// between segments are filled with opts.Pad. Trailing zero-initialised
// memory (p_memsz > p_filesz, i.e. .bss) is not emitted.
//
// It returns the image bytes and the base load address the image starts
// at (the lowest segment address), so callers can feed SREC/IHEX/UImage.
func Flatten(r io.ReaderAt, opts FlattenOptions) ([]byte, uint64, error) {
	ef, err := elf.NewFile(r)
	if err != nil {
		return nil, 0, fmt.Errorf("parse ELF: %w", err)
	}
	addr := func(p *elf.Prog) uint64 {
		if opts.UseVaddr {
			return p.Vaddr
		}
		return p.Paddr
	}
	var loads []*elf.Prog
	for _, p := range ef.Progs {
		if p.Type == elf.PT_LOAD && p.Filesz > 0 {
			loads = append(loads, p)
		}
	}
	if len(loads) == 0 {
		return nil, 0, fmt.Errorf("no PT_LOAD segments with file content")
	}
	sort.Slice(loads, func(i, j int) bool { return addr(loads[i]) < addr(loads[j]) })

	base := addr(loads[0])
	var end uint64
	for _, p := range loads {
		if e := addr(p) + p.Filesz; e > end {
			end = e
		}
	}
	out := make([]byte, end-base)
	if opts.Pad != 0 {
		for i := range out {
			out[i] = opts.Pad
		}
	}
	for i, p := range loads {
		data := make([]byte, p.Filesz)
		if _, err := r.ReadAt(data, int64(p.Off)); err != nil {
			return nil, 0, fmt.Errorf("read segment %d: %w", i, err)
		}
		copy(out[addr(p)-base:], data)
	}
	return out, base, nil
}

// --- Motorola S-record (SREC) -------------------------------------------------

// SREC encodes data loaded at addr as Motorola S-records using 32-bit
// addresses (S3 data records, an S0 header carrying name, and an S7
// termination carrying entry). dataPerLine bytes are emitted per S3 record
// (default 16 when zero). The result ends with a trailing newline.
func SREC(addr uint32, data []byte, name string, entry uint32, dataPerLine int) []byte {
	if dataPerLine <= 0 {
		dataPerLine = 16
	}
	var out []byte
	// S0 header: address 0x0000, data = name bytes.
	out = srecLine(out, '0', 0, []byte(name))
	// S3 data records.
	for off := 0; off < len(data); off += dataPerLine {
		end := off + dataPerLine
		if end > len(data) {
			end = len(data)
		}
		out = srecLine(out, '3', addr+uint32(off), data[off:end])
	}
	// S7 termination with the entry address, no data.
	out = srecLine(out, '7', entry, nil)
	return out
}

// srecLine appends one S-record. For S0/S3/S7 the address is 4 bytes wide
// (S3-class); S0 conventionally uses a 2-byte address but a 4-byte address
// is accepted by every loader and keeps the encoder uniform.
func srecLine(out []byte, typ byte, addr uint32, data []byte) []byte {
	rec := make([]byte, 0, 4+len(data))
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], addr)
	rec = append(rec, a[:]...)
	rec = append(rec, data...)
	count := len(rec) + 1 // address + data + checksum
	sum := count
	for _, b := range rec {
		sum += int(b)
	}
	cksum := byte(^sum & 0xff)
	out = append(out, 'S', typ)
	out = appendHexByte(out, byte(count))
	out = appendHex(out, rec)
	out = appendHexByte(out, cksum)
	return append(out, '\n')
}

// --- Intel HEX (IHEX) ---------------------------------------------------------

// IHEX encodes data loaded at addr as Intel HEX, emitting Extended Linear
// Address (type 04) records whenever the upper 16 bits of the address
// change, then an EOF (type 01) record. dataPerLine bytes per data record
// (default 16). The result ends with a trailing newline.
func IHEX(addr uint32, data []byte, dataPerLine int) []byte {
	if dataPerLine <= 0 {
		dataPerLine = 16
	}
	var out []byte
	upper := uint16(0xffff) // force an initial type-04 unless addr<0x10000 and upper==0
	if addr>>16 == 0 {
		upper = 0
	}
	for off := 0; off < len(data); off += dataPerLine {
		cur := addr + uint32(off)
		hi := uint16(cur >> 16)
		if hi != upper {
			upper = hi
			var ext [2]byte
			binary.BigEndian.PutUint16(ext[:], hi)
			out = ihexRecord(out, 0, 0x04, ext[:])
		}
		end := off + dataPerLine
		if end > len(data) {
			end = len(data)
		}
		out = ihexRecord(out, uint16(cur), 0x00, data[off:end])
	}
	return ihexRecord(out, 0, 0x01, nil) // EOF
}

// ihexRecord appends one Intel HEX record.
func ihexRecord(out []byte, addr uint16, typ byte, data []byte) []byte {
	out = append(out, ':')
	out = appendHexByte(out, byte(len(data)))
	var a [2]byte
	binary.BigEndian.PutUint16(a[:], addr)
	out = appendHex(out, a[:])
	out = appendHexByte(out, typ)
	out = appendHex(out, data)
	sum := len(data) + int(a[0]) + int(a[1]) + int(typ)
	for _, b := range data {
		sum += int(b)
	}
	cksum := byte(-sum & 0xff)
	out = appendHexByte(out, cksum)
	return append(out, '\n')
}

// --- U-Boot legacy uImage -----------------------------------------------------

// uImage OS, architecture, image-type and compression codes (subset of
// U-Boot's image.h that a Go firmware image actually needs).
const (
	OSLinux        = 5
	OSUBoot        = 17
	ArchARM        = 2
	ArchARM64      = 22
	ArchX86_64     = 24
	ArchRISCV      = 26
	ArchLoongArch  = 27
	TypeStandalone = 1
	TypeKernel     = 2
	TypeFirmware   = 5
	CompNone       = 0
	CompGzip       = 1
)

const uImageMagic = 0x27051956

// UImageOptions controls UImage. Time is taken from the caller (default 0)
// to keep output reproducible.
type UImageOptions struct {
	Load  uint32
	Entry uint32
	Name  string // truncated to 31 bytes + NUL
	OS    byte   // default OSLinux
	Arch  byte   // default ArchARM
	Type  byte   // default TypeKernel
	Comp  byte   // default CompNone
	Time  uint32
}

// UImage wraps payload in a legacy U-Boot image header (64 bytes,
// big-endian) with correct header and data CRC32 (IEEE), so the result
// can be booted with `bootm`. Equivalent to `mkimage -A .. -O .. -T ..
// -C none -a load -e entry -n name -d payload`.
func UImage(payload []byte, opts UImageOptions) []byte {
	if opts.OS == 0 {
		opts.OS = OSLinux
	}
	if opts.Arch == 0 {
		opts.Arch = ArchARM
	}
	if opts.Type == 0 {
		opts.Type = TypeKernel
	}
	hdr := make([]byte, 64)
	binary.BigEndian.PutUint32(hdr[0:], uImageMagic)
	// hdr[4:8] = header CRC, filled last (computed over header with it zeroed)
	binary.BigEndian.PutUint32(hdr[8:], opts.Time)
	binary.BigEndian.PutUint32(hdr[12:], uint32(len(payload)))
	binary.BigEndian.PutUint32(hdr[16:], opts.Load)
	binary.BigEndian.PutUint32(hdr[20:], opts.Entry)
	binary.BigEndian.PutUint32(hdr[24:], crc32.ChecksumIEEE(payload)) // data CRC
	hdr[28] = opts.OS
	hdr[29] = opts.Arch
	hdr[30] = opts.Type
	hdr[31] = opts.Comp
	name := opts.Name
	if len(name) > 31 {
		name = name[:31]
	}
	copy(hdr[32:63], name)
	binary.BigEndian.PutUint32(hdr[4:], crc32.ChecksumIEEE(hdr)) // header CRC (field currently 0)
	return append(hdr, payload...)
}

// --- hex helpers --------------------------------------------------------------

const hexDigits = "0123456789ABCDEF"

func appendHexByte(out []byte, b byte) []byte {
	return append(out, hexDigits[b>>4], hexDigits[b&0xf])
}

func appendHex(out, b []byte) []byte {
	for _, x := range b {
		out = appendHexByte(out, x)
	}
	return out
}
