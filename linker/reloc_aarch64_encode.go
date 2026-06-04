package linker

import "encoding/binary"

// ARM64 instruction-encoding helpers shared by the COFF and ELF backends.
// Each function takes a patch site slice + the displacement/offset bits
// (already range-checked) and rewrites the instruction in place. Opcode
// bits outside the immediate field pass through untouched.

// encodeARM64Branch26 writes a 26-bit signed PC-relative branch
// displacement (B / BL). disp is in words (byte/4); bits[25:0].
func encodeARM64Branch26(b []byte, dispWords int64) {
	inst := binary.LittleEndian.Uint32(b)
	inst = (inst &^ 0x03FFFFFF) | (uint32(dispWords) & 0x03FFFFFF)
	binary.LittleEndian.PutUint32(b, inst)
}

// encodeARM64Branch19 writes a 19-bit signed PC-relative branch
// displacement (B.cond / CBZ / CBNZ) into bits[23:5].
func encodeARM64Branch19(b []byte, dispWords int64) {
	inst := binary.LittleEndian.Uint32(b)
	inst = (inst &^ (0x7FFFF << 5)) | ((uint32(dispWords) & 0x7FFFF) << 5)
	binary.LittleEndian.PutUint32(b, inst)
}

// encodeARM64TBranch14 writes a 14-bit signed PC-relative branch
// displacement (TBZ / TBNZ) into bits[18:5].
func encodeARM64TBranch14(b []byte, dispWords int64) {
	inst := binary.LittleEndian.Uint32(b)
	inst = (inst &^ (0x3FFF << 5)) | ((uint32(dispWords) & 0x3FFF) << 5)
	binary.LittleEndian.PutUint32(b, inst)
}

// encodeARM64ADRP writes a 21-bit page-relative displacement (ADRP).
// The 21 bits split into immlo (bits[30:29]) and immhi (bits[23:5]).
func encodeARM64ADRP(b []byte, pageDisp int64) {
	inst := binary.LittleEndian.Uint32(b)
	immLo := (uint32(pageDisp) & 0x3) << 29
	immHi := ((uint32(pageDisp) >> 2) & 0x7FFFF) << 5
	inst = (inst &^ ((0x3 << 29) | (0x7FFFF << 5))) | immLo | immHi
	binary.LittleEndian.PutUint32(b, inst)
}

// encodeARM64ADR writes a 21-bit byte-relative displacement (ADR), same
// bit layout as ADRP.
func encodeARM64ADR(b []byte, disp int64) {
	encodeARM64ADRP(b, disp)
}

// encodeARM64Imm12 writes a 12-bit immediate into an ADD/SUB instruction
// at bits[21:10].
func encodeARM64Imm12(b []byte, imm uint32) {
	inst := binary.LittleEndian.Uint32(b)
	inst = (inst &^ (0xFFF << 10)) | ((imm & 0xFFF) << 10)
	binary.LittleEndian.PutUint32(b, inst)
}
