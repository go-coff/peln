<p align="center"><img src="https://raw.githubusercontent.com/go-coff/brand/main/social/go-coff.png" alt="go-coff/peln" width="720"></p>

# go-coff/peln

[![CI](https://github.com/go-coff/peln/actions/workflows/ci.yml/badge.svg)](https://github.com/go-coff/peln/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)](https://github.com/go-coff/peln/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-coff/peln.svg)](https://pkg.go.dev/github.com/go-coff/peln)

Pure-Go PE/COFF tooling for building **UEFI applications** without binutils or
LLD. Zero third-party dependencies, 100 % test coverage.

Two packages:

| Package | Import | Job |
| ------- | ------ | --- |
| [`linker`](linker) | `github.com/go-coff/peln/linker` | turn relocatable objects (or a PIE) into a PE32+/EFI image — the pure-Go replacement for `lld-link /subsystem:efi_application` |
| [`appender`](appender) | `github.com/go-coff/peln/appender` | add sections to an existing PE (UKI assembly) — the equivalent of `objcopy --add-section` |
| [`fwimg`](fwimg) | `github.com/go-coff/peln/fwimg` | **non-UEFI** bare-metal images: ELF→flat binary (`objcopy -O binary`), Motorola SREC, Intel HEX, and U-Boot uImage (`mkimage`) |

A reference CLI lives in [`github.com/go-coff/pectl`](https://github.com/go-coff/pectl).

## Install

```sh
go get github.com/go-coff/peln
```

## linker — objects → PE/EFI

`linker.Link` merges one or more COFF/PE or ELF **relocatable** objects (`.o`,
`ET_REL` — e.g. from TinyGo or clang with a `*-pc-windows-gnu` / ELF target)
into a self-contained PE32+ EFI application. The machine is taken from the first
object; supported: amd64, arm64, riscv64, loongarch64.

```go
import "github.com/go-coff/peln/linker"

data, _ := os.ReadFile("main-riscv64.o")
obj, _ := linker.ReadObject(bytes.NewReader(data), "main-riscv64.o")
out, err := linker.Link([]*linker.Object{obj}, linker.LinkOptions{
    AllowUnresolved: true, // zero-fill externals the EFI runtime ignores
})
if err != nil { log.Fatal(err) }
_ = os.WriteFile("BOOTRISCV64.EFI", out, 0o644)
```

It motivated by riscv64 and loongarch64, which LLD's COFF driver does not
support. The pipeline is `Resolve → ComputeLayout → ApplyRelocations → emit`;
each architecture has its own relocation backend (`reloc_x86_64*.go`,
`reloc_aarch64*.go`, `reloc_rv64.go`, `reloc_loongarch64.go`).

### LinkPIE — a position-independent ELF → PE/EFI

`linker.LinkPIE` converts an already-linked **position-independent
executable** (`ET_DYN`, as produced by `go build -buildmode=pie` for a
bare-metal `GOOS` such as **TamaGo**) into a PE32+/EFI image. Such an image is
self-contained — its only dynamic relocations are the architecture's `RELATIVE`
type — so there is nothing to resolve; LinkPIE just:

- maps each `PT_LOAD` segment to a PE section at `RVA = p_vaddr − ImageBase`;
- pre-applies every `R_*_RELATIVE` (writing the absolute target VA into the
  image) and records an equivalent `IMAGE_REL_BASED_DIR64` base relocation, so
  UEFI firmware rebases the image correctly at load;
- takes the entry point from `e_entry`.

```go
elf, _ := os.ReadFile("hello-pie.elf") // GOOS=tamago GOARCH=loong64 -buildmode=pie
out, err := linker.LinkPIE(bytes.NewReader(elf), linker.PIEOptions{})
if err != nil { log.Fatal(err) }
_ = os.WriteFile("BOOTLOONG64.EFI", out, 0o644)
```

Supported machines: amd64, arm64, riscv64, loongarch64. This is the route for
turning a pure-Go TamaGo bare-metal binary into a UEFI `.efi` with no external
linker. (`debug/pe` cannot *read* machine 0x6264, but the bytes are a valid
PE32+; firmware and `objdump`/`llvm-readobj` parse it.)

## appender — add sections to a PE

`appender.Append` adds new sections at the end of an existing PE32/PE32+ image
while leaving every existing section's RVA, file offset and contents untouched —
exactly the constraint for assembling UEFI **Unified Kernel Images** (UKIs):
take a systemd UEFI stub and add `.linux`, `.initrd`, `.cmdline`, `.osrel`,
`.uname`.

```go
import "github.com/go-coff/peln/appender"

stub, _ := os.ReadFile("linuxx64.efi.stub")
out, err := appender.Append(stub, []appender.Section{
    {Name: ".osrel",   Data: osrelBytes,   Characteristics: appender.DefaultCharacteristics},
    {Name: ".cmdline", Data: cmdlineBytes, Characteristics: appender.DefaultCharacteristics},
    {Name: ".linux",   Data: kernelBytes,  Characteristics: appender.DefaultCharacteristics},
    {Name: ".initrd",  Data: initrdBytes,  Characteristics: appender.DefaultCharacteristics},
})
if err != nil { log.Fatal(err) }
_ = os.WriteFile("BOOTX64.EFI", out, 0o644)
```

The stub must reserve enough header padding to absorb the new section-table
entries (`SizeOfHeaders` is not grown); all systemd UEFI stubs do.

## fwimg — non-UEFI bare-metal images

Not every bare-metal target is UEFI. For images loaded at a fixed address by
a bootloader or ROM, `fwimg` converts an ELF executable into the relevant
flat/firmware format, again with no binutils/`mkimage`/`srec_cat`:

```go
import "github.com/go-coff/peln/fwimg"

elf, _ := os.ReadFile("kernel.elf")
flat, base, _ := fwimg.Flatten(bytes.NewReader(elf), fwimg.FlattenOptions{}) // objcopy -O binary
_ = os.WriteFile("kernel.img", flat, 0o644)                                  // e.g. Raspberry Pi

hex := fwimg.IHEX(uint32(base), flat, 0)         // Intel HEX for a flasher
srec := fwimg.SREC(uint32(base), flat, "fw", 0, 0)
uimg := fwimg.UImage(flat, fwimg.UImageOptions{  // U-Boot bootm payload
    Load: 0x80000, Entry: 0x80000, Name: "linux", Arch: fwimg.ArchARM64,
})
```

The CLI exposes this as `pectl objcopy -O binary|srec|ihex|uimage`.

## Why not call binutils / LLD?

To remove a host build-time dependency on binutils/LLD for tools that build
UEFI images in Go (custom installers, boot managers, embedded pipelines), and to
cover targets LLD's COFF driver doesn't (riscv64, loongarch64).
Cross-compiling Go to a host that doesn't ship binutils (macOS, Alpine minimal)
is otherwise painful.

## License

[BSD 3-Clause](LICENSE).
