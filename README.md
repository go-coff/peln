# go-coff/pe

Pure-Go appender for PE/COFF sections — the equivalent of
`objcopy --add-section`, restricted to the case that matters for UEFI Unified
Kernel Images (UKIs): adding new sections at the end of an existing PE32 or
PE32+ image while leaving every existing section's RVA, file offset and
contents untouched.

Zero third-party dependencies. The whole library is ~250 lines.

## Use case

UKI assembly: take a UEFI stub (e.g. `linuxx64.efi.stub` from systemd) and add
`.linux`, `.initrd`, `.cmdline`, `.osrel`, `.uname` sections to produce a
single bootable `BOOTX64.EFI`. The stub reserves enough header padding to
absorb the new section-table entries, which is exactly the constraint this
library checks for.

## Install

```sh
go get github.com/go-coff/pe
```

## Library

```go
import "github.com/go-coff/pe"

stub, _ := os.ReadFile("linuxx64.efi.stub")
out, err := pe.Append(stub, []pe.Section{
    {Name: ".osrel",   Data: osrelBytes,   Characteristics: pe.DefaultCharacteristics},
    {Name: ".cmdline", Data: cmdlineBytes, Characteristics: pe.DefaultCharacteristics},
    {Name: ".linux",   Data: kernelBytes,  Characteristics: pe.DefaultCharacteristics},
    {Name: ".initrd",  Data: initrdBytes,  Characteristics: pe.DefaultCharacteristics},
})
if err != nil { log.Fatal(err) }
_ = os.WriteFile("BOOTX64.EFI", out, 0o644)
```

## CLI

A reference command-line front-end lives in a separate repository,
[`github.com/go-coff/pec`](https://github.com/go-coff/pec). It is a thin
wrapper that exposes `pe.Append` as `pec --add-section name=path …`.

## What is written

For each new section the library writes:

| Field | Value |
| ----- | ----- |
| Name | up to 8 bytes (the spec; longer names rejected) |
| VirtualSize | `len(Data)` |
| VirtualAddress | first free RVA, aligned to `SectionAlignment` |
| SizeOfRawData | `VirtualSize` rounded up to `FileAlignment` |
| PointerToRawData | first free file offset, aligned to `FileAlignment` |
| Characteristics | as provided |
| PointerToRelocations / Linenumbers | 0 |

Image-level fields updated:

- `COFF.NumberOfSections` += `len(sections)`
- `Optional.SizeOfImage` = highest aligned end-of-section RVA
- `Optional.CheckSum` is zeroed (UEFI doesn't enforce it; if you need a
  signable image, recompute the checksum with a separate tool afterwards)

## Limitations

- **Section name** capped at 8 bytes (long names via the COFF string table
  are not supported — none of the systemd UEFI stubs need them).
- **SizeOfHeaders is not grown**, so the input stub must reserve enough
  header padding for the added entries. All systemd UEFI stubs do.
- **No re-link** of existing data; existing RVAs and file offsets are
  preserved verbatim. This is the right behaviour for UKIs but not for
  general linker-style PE editing.

## Why not call `objcopy`?

To remove a host build-time dependency on binutils for tools that assemble
UKIs in Go (initrd-as-a-service, custom installers, embedded build pipelines).
Cross-compiling Go to a host that doesn't ship binutils (macOS, Alpine
minimal) is otherwise painful.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
