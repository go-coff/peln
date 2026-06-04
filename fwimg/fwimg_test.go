package fwimg

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"strconv"
	"strings"
	"testing"
)

// --- minimal ELF64 builder (program headers only; Flatten ignores sections) ---

type seg struct {
	paddr, vaddr, off, filesz, memsz uint64
	data                             []byte
}

func buildELF(t *testing.T, machine elf.Machine, segs []seg) []byte {
	t.Helper()
	const phoff = 64
	size := uint64(0x400)
	for _, s := range segs {
		if e := s.off + uint64(len(s.data)); e > size {
			size = e
		}
	}
	buf := make([]byte, size)
	copy(buf, []byte{0x7f, 'E', 'L', 'F'})
	buf[4], buf[5], buf[6] = 2, 1, 1 // ELFCLASS64, LSB, EV_CURRENT
	binary.LittleEndian.PutUint16(buf[16:], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(buf[18:], uint16(machine))
	binary.LittleEndian.PutUint32(buf[20:], 1)
	binary.LittleEndian.PutUint64(buf[32:], phoff)
	binary.LittleEndian.PutUint16(buf[52:], 64) // e_ehsize
	binary.LittleEndian.PutUint16(buf[54:], 56) // e_phentsize
	binary.LittleEndian.PutUint16(buf[56:], uint16(len(segs)))
	for i, s := range segs {
		p := phoff + i*56
		binary.LittleEndian.PutUint32(buf[p:], uint32(elf.PT_LOAD))
		binary.LittleEndian.PutUint32(buf[p+4:], uint32(elf.PF_R|elf.PF_X))
		binary.LittleEndian.PutUint64(buf[p+8:], s.off)
		binary.LittleEndian.PutUint64(buf[p+16:], s.vaddr)
		binary.LittleEndian.PutUint64(buf[p+24:], s.paddr)
		binary.LittleEndian.PutUint64(buf[p+32:], s.filesz)
		binary.LittleEndian.PutUint64(buf[p+40:], s.memsz)
		binary.LittleEndian.PutUint64(buf[p+48:], 0x1000)
		copy(buf[s.off:], s.data)
	}
	return buf
}

// --- Flatten ------------------------------------------------------------------

func TestFlatten_GapAndPad(t *testing.T) {
	img := buildELF(t, elf.EM_AARCH64, []seg{
		{paddr: 0x1000, off: 0x200, filesz: 4, memsz: 4, data: []byte("AAAA")},
		{paddr: 0x1008, off: 0x300, filesz: 4, memsz: 4, data: []byte("BBBB")},
	})
	out, base, err := Flatten(bytes.NewReader(img), FlattenOptions{Pad: 0xff})
	if err != nil {
		t.Fatal(err)
	}
	if base != 0x1000 {
		t.Errorf("base = 0x%x, want 0x1000", base)
	}
	want := []byte{'A', 'A', 'A', 'A', 0xff, 0xff, 0xff, 0xff, 'B', 'B', 'B', 'B'}
	if !bytes.Equal(out, want) {
		t.Errorf("flat = % x, want % x", out, want)
	}
}

func TestFlatten_UseVaddrZeroPad(t *testing.T) {
	img := buildELF(t, elf.EM_X86_64, []seg{
		{paddr: 0x9000, vaddr: 0x2000, off: 0x200, filesz: 2, memsz: 2, data: []byte("hi")},
	})
	out, base, err := Flatten(bytes.NewReader(img), FlattenOptions{UseVaddr: true})
	if err != nil {
		t.Fatal(err)
	}
	if base != 0x2000 || !bytes.Equal(out, []byte("hi")) {
		t.Errorf("base=0x%x out=%q", base, out)
	}
}

func TestFlatten_NoLoadable(t *testing.T) {
	img := buildELF(t, elf.EM_AARCH64, []seg{{paddr: 0x1000, off: 0x200, filesz: 0, memsz: 8}})
	if _, _, err := Flatten(bytes.NewReader(img), FlattenOptions{}); err == nil || !strings.Contains(err.Error(), "no PT_LOAD") {
		t.Fatalf("err = %v, want no-PT_LOAD", err)
	}
}

func TestFlatten_BadELF(t *testing.T) {
	if _, _, err := Flatten(bytes.NewReader([]byte("not elf")), FlattenOptions{}); err == nil || !strings.Contains(err.Error(), "parse ELF") {
		t.Fatalf("err = %v, want parse-ELF", err)
	}
}

type failAt struct {
	r       *bytes.Reader
	failOff int64
}

func (f failAt) ReadAt(p []byte, off int64) (int, error) {
	if off == f.failOff {
		return 0, errors.New("synthetic failure")
	}
	return f.r.ReadAt(p, off)
}

func TestFlatten_SegmentReadError(t *testing.T) {
	img := buildELF(t, elf.EM_AARCH64, []seg{{paddr: 0x1000, off: 0x200, filesz: 4, memsz: 4, data: []byte("AAAA")}})
	r := failAt{r: bytes.NewReader(img), failOff: 0x200}
	if _, _, err := Flatten(r, FlattenOptions{}); err == nil || !strings.Contains(err.Error(), "read segment") {
		t.Fatalf("err = %v, want read-segment", err)
	}
}

// --- SREC ---------------------------------------------------------------------

// parseSREC validates each record's checksum and reconstructs the address
// of the first S3 record + the concatenated S3 data and the S7 entry.
func parseSREC(t *testing.T, b []byte) (addr uint32, data []byte, entry uint32, name string) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if len(line) < 4 || line[0] != 'S' {
			t.Fatalf("bad SREC line %q", line)
		}
		typ := line[1]
		raw := hexBytes(t, line[2:])
		count := int(raw[0])
		if count+1 != len(raw) {
			t.Fatalf("SREC count %d vs len %d in %q", count, len(raw), line)
		}
		sum := 0
		for _, x := range raw[:len(raw)-1] {
			sum += int(x)
		}
		if byte(^sum&0xff) != raw[len(raw)-1] {
			t.Fatalf("SREC checksum mismatch in %q", line)
		}
		body := raw[1 : len(raw)-1] // strip count + checksum
		a := binary.BigEndian.Uint32(body[:4])
		payload := body[4:]
		switch typ {
		case '0':
			name = string(payload)
		case '3':
			if data == nil {
				addr = a
			}
			data = append(data, payload...)
		case '7':
			entry = a
		default:
			t.Fatalf("unexpected SREC type %c", typ)
		}
	}
	return
}

func TestSREC_RoundTrip(t *testing.T) {
	in := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	out := SREC(0x08000000, in, "hello", 0x08000004, 2) // 2 bytes/line → 3 S3 records
	addr, data, entry, name := parseSREC(t, out)
	if addr != 0x08000000 || entry != 0x08000004 || name != "hello" {
		t.Errorf("addr=0x%x entry=0x%x name=%q", addr, entry, name)
	}
	if !bytes.Equal(data, in) {
		t.Errorf("data = % x, want % x", data, in)
	}
}

func TestSREC_DefaultLineLen(t *testing.T) {
	out := SREC(0, bytes.Repeat([]byte{0xAB}, 40), "", 0, 0) // dataPerLine<=0 → 16
	_, data, _, _ := parseSREC(t, out)
	if len(data) != 40 {
		t.Errorf("len = %d, want 40", len(data))
	}
}

// --- IHEX ---------------------------------------------------------------------

func parseIHEX(t *testing.T, b []byte) (out map[uint32]byte, sawEOF bool) {
	t.Helper()
	out = map[uint32]byte{}
	var upper uint32
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if len(line) < 11 || line[0] != ':' {
			t.Fatalf("bad IHEX line %q", line)
		}
		raw := hexBytes(t, line[1:])
		ll := int(raw[0])
		if len(raw) != ll+5 {
			t.Fatalf("IHEX length mismatch %q", line)
		}
		sum := 0
		for _, x := range raw {
			sum += int(x)
		}
		if sum&0xff != 0 {
			t.Fatalf("IHEX checksum nonzero in %q", line)
		}
		addr := binary.BigEndian.Uint16(raw[1:3])
		typ := raw[3]
		payload := raw[4 : 4+ll]
		switch typ {
		case 0x00:
			for i, x := range payload {
				out[upper|uint32(addr)+uint32(i)] = x
			}
		case 0x04:
			upper = uint32(binary.BigEndian.Uint16(payload)) << 16
		case 0x01:
			sawEOF = true
		default:
			t.Fatalf("unexpected IHEX type 0x%02x", typ)
		}
	}
	return
}

func TestIHEX_CrossesLinearBoundary(t *testing.T) {
	// Start just below a 64 KiB boundary so a second type-04 record is needed.
	const start = 0x0001FFF0
	in := make([]byte, 64)
	for i := range in {
		in[i] = byte(i)
	}
	out := IHEX(start, in, 16)
	mem, eof := parseIHEX(t, out)
	if !eof {
		t.Error("no EOF record")
	}
	for i, b := range in {
		if mem[start+uint32(i)] != b {
			t.Fatalf("byte at 0x%x = 0x%x, want 0x%x", start+uint32(i), mem[start+uint32(i)], b)
		}
	}
}

func TestIHEX_LowAddrDefaultLineLen(t *testing.T) {
	in := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	out := IHEX(0x10, in, 0) // addr>>16==0 path, default 16/line
	mem, eof := parseIHEX(t, out)
	if !eof {
		t.Error("no EOF")
	}
	for i, b := range in {
		if mem[0x10+uint32(i)] != b {
			t.Errorf("byte %d", i)
		}
	}
}

// --- UImage -------------------------------------------------------------------

func TestUImage_DefaultsAndCRC(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5A}, 100)
	img := UImage(payload, UImageOptions{Load: 0x80000, Entry: 0x80000, Name: "vmlinuz"})
	if len(img) != 64+len(payload) {
		t.Fatalf("len = %d", len(img))
	}
	h := img[:64]
	if binary.BigEndian.Uint32(h[0:]) != uImageMagic {
		t.Error("bad magic")
	}
	if binary.BigEndian.Uint32(h[12:]) != uint32(len(payload)) {
		t.Error("bad size")
	}
	if binary.BigEndian.Uint32(h[16:]) != 0x80000 || binary.BigEndian.Uint32(h[20:]) != 0x80000 {
		t.Error("bad load/entry")
	}
	if binary.BigEndian.Uint32(h[24:]) != crc32.ChecksumIEEE(payload) {
		t.Error("bad data CRC")
	}
	if h[28] != OSLinux || h[29] != ArchARM || h[30] != TypeKernel || h[31] != CompNone {
		t.Errorf("defaults wrong: os=%d arch=%d type=%d comp=%d", h[28], h[29], h[30], h[31])
	}
	if !bytes.Equal(img[64:], payload) {
		t.Error("payload not appended")
	}
	// Header CRC: recompute over header with the hcrc field zeroed.
	hcrc := binary.BigEndian.Uint32(h[4:])
	check := append([]byte(nil), h...)
	binary.BigEndian.PutUint32(check[4:], 0)
	if crc32.ChecksumIEEE(check) != hcrc {
		t.Error("bad header CRC")
	}
}

func TestUImage_ExplicitFieldsAndNameTruncation(t *testing.T) {
	long := strings.Repeat("x", 40)
	img := UImage([]byte{1}, UImageOptions{
		OS: OSUBoot, Arch: ArchLoongArch, Type: TypeStandalone, Comp: CompGzip,
		Time: 12345, Name: long,
	})
	h := img[:64]
	if h[28] != OSUBoot || h[29] != ArchLoongArch || h[30] != TypeStandalone || h[31] != CompGzip {
		t.Error("explicit fields not honoured")
	}
	if binary.BigEndian.Uint32(h[8:]) != 12345 {
		t.Error("time not set")
	}
	name := string(bytes.TrimRight(h[32:63], "\x00"))
	if len(name) != 31 || name != long[:31] {
		t.Errorf("name = %q (len %d), want 31-char truncation", name, len(name))
	}
}

// --- hex helpers --------------------------------------------------------------

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	if len(s)%2 != 0 {
		t.Fatalf("odd hex %q", s)
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		v, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			t.Fatalf("bad hex %q: %v", s, err)
		}
		out[i] = byte(v)
	}
	return out
}

func TestAppendHexHelpers(t *testing.T) {
	if got := string(appendHexByte(nil, 0xAB)); got != "AB" {
		t.Errorf("appendHexByte = %q", got)
	}
	if got := string(appendHex(nil, []byte{0x01, 0xFE})); got != "01FE" {
		t.Errorf("appendHex = %q", got)
	}
}
