package linker

import (
	"encoding/binary"
	"fmt"
)

// R_X86_64_* relocation type codes from the System V psABI, x86-64
// supplement. Only the types we actually observe in TinyGo / clang
// output (with -ffreestanding) are implemented; the rest fail loudly.
const (
	rxNone   uint16 = 0
	rxAbs64  uint16 = 1  // R_X86_64_64       — 64-bit absolute (S + A)
	rxPC32   uint16 = 2  // R_X86_64_PC32     — 32-bit PC-relative (S + A - P)
	rxPLT32  uint16 = 4  // R_X86_64_PLT32    — Same as PC32 for static linking
	rxAbs32  uint16 = 10 // R_X86_64_32       — 32-bit absolute (zero-extended)
	rxAbs32S uint16 = 11 // R_X86_64_32S      — 32-bit absolute (sign-extended)
	rxPC64   uint16 = 24 // R_X86_64_PC64     — 64-bit PC-relative
	rxRelax  uint16 = 32 // R_X86_64_GOTPCRELX (informational; never resolved here)
)

// applyAMD64ELF patches one x86_64 ELF relocation. Differences from the
// COFF backend:
//
//   - Addend comes from Reloc.Addend (explicit) rather than the in-place
//     bytes. ELF/RELA convention.
//   - PC32 / PLT32 already account for the "next-instruction" offset via
//     the addend (usually −4 in TinyGo output), so we don't subtract 4
//     ourselves.
func applyAMD64ELF(t uint16, patchBytes []byte, patchVA, targetVA uint64, patchRVA uint32, imageBase uint64, addend int64) ([]BaseReloc, error) {
	switch t {

	case rxNone, rxRelax:
		return nil, nil

	case rxAbs64:
		if len(patchBytes) < 8 {
			return nil, fmt.Errorf("R_X86_64_64 needs 8 bytes")
		}
		binary.LittleEndian.PutUint64(patchBytes, uint64(int64(targetVA)+addend))
		return []BaseReloc{{RVA: patchRVA, Type: BaseRelocDir64}}, nil

	case rxAbs32, rxAbs32S:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_X86_64_32 needs 4 bytes")
		}
		binary.LittleEndian.PutUint32(patchBytes, uint32(int64(targetVA)+addend))
		return []BaseReloc{{RVA: patchRVA, Type: BaseRelocHighLow}}, nil

	case rxPC32, rxPLT32:
		if len(patchBytes) < 4 {
			return nil, fmt.Errorf("R_X86_64_PC32 needs 4 bytes")
		}
		disp := int64(targetVA) + addend - int64(patchVA)
		if disp < -0x80000000 || disp > 0x7fffffff {
			return nil, fmt.Errorf("R_X86_64_PC32 disp 0x%x out of range", disp)
		}
		binary.LittleEndian.PutUint32(patchBytes, uint32(int32(disp)))
		return nil, nil

	case rxPC64:
		if len(patchBytes) < 8 {
			return nil, fmt.Errorf("R_X86_64_PC64 needs 8 bytes")
		}
		disp := int64(targetVA) + addend - int64(patchVA)
		binary.LittleEndian.PutUint64(patchBytes, uint64(disp))
		return nil, nil
	}
	return nil, fmt.Errorf("unsupported x86_64 ELF reloc type %d", t)
}
