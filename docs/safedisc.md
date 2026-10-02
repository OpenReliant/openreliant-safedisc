# SafeDisc 1 and the payload executable

The retail release is protected with Macrovision SafeDisc version 1. The program that the user
launches, `LANCER.EXE`, is not the game: it is a protection loader. The game is `LANCER.ICD`, a
complete PE image whose code and data sections are encrypted.

OpenReliant's analysis reads a readable copy of that image from `game/decrypted/LANCER.EXE`.
`safedisc decrypt` writes it.

## The two files

| File | Size | Linker | Entry point | Role |
|---|---|---|---|---|
| `LANCER.EXE` | 249,119 | 5.0 | `0x00416840` | SafeDisc loader |
| `LANCER.ICD` | 1,151,021 | 6.0 | `0x004D1210` | The game, encrypted |

Both are installed by `LANCER.CAB` into the game directory, and both are also present on disc 1
under `GAME/CAB/`.

The loader is built from three code sections: `.txt` (encrypted, decrypted by the loader itself at
startup), `.text` and `.txt2` (both plaintext, holding the decryption machinery). Its overlay
retains build paths from the SafeDisc data-preparation tool
(`C:\PROGRAM FILES\C-DILLA\SAFEDISC\DATA PREPARATION\...`), which identify the protection and its
vendor.

The loader's supporting files ship beside it on disc 1: `DPLAYERX.DLL` (API resolution, see
[Imports](#imports)), `CLCD16.DLL`, `CLCD32.DLL`, `CLOKSPL.EXE`, `DRVMGT.DLL` and `SECDRV.SYS`, the
kernel driver that modern Windows no longer loads.

## Section encryption

Sections of the `.icd` are encrypted with **TEA** (Wheeler and Needham, 1994) in **ECB** mode,
**32 cycles** per block, little-endian words. A trailing partial block is left in the clear.

The loader's decrypt routine is at `0x00421891` in `LANCER.EXE`, reachable without decrypting
anything because it sits in the plaintext `.txt2` section. It reads its parameters from `.rdata`:

| Address | Value | Meaning |
|---|---|---|
| `0x0042800C` | `0x9E3779B9` | TEA delta |
| `0x00428010` | `32` | cycles per block |

The sum is initialised to `delta << 5`, consistent with 32 cycles. `0x00421FC2` installs the
128-bit key into the buffer at `0x0042EAD0`; called with a null pointer it fills that buffer with
the bytes `00 01 02 ... 0F`, which is the key used for the loader's own `.txt`, not for the
payload.

In `LANCER.ICD` exactly two sections are encrypted:

| Section | Virtual address | Raw size | Entropy encrypted | Entropy decrypted |
|---|---|---|---|---|
| `.text` | `0x00401000` | `0xDB000` | 8.00 | 6.63 |
| `.data` | `0x004E0000` | `0x36000` | 7.65 | 4.73 |

`.rdata`, `CONST` and `.rsrc` are stored in the clear.

## The key

The key is 128 bits, but its four 32-bit words are all equal, which is how SafeDisc 1.3x and 1.4x
store keys. That leaves 32 bits of key material.

For this release the word is:

```
0x434B4DAD
```

so the full key is `AD 4D 4B 43` repeated four times. Both encrypted sections use it.

`0xC34B4DAD` decrypts identically. TEA has equivalent keys: flipping the top bit of both words of
either half of the key leaves the cipher unchanged, and with all four words equal both halves flip
together. `safedisc` reports the smaller of the pair.

### Recovering it from the files

The key is recovered by brute force over the 32-bit space, with no disc read and no execution of
the loader. The search needs one block of known plaintext, which the image supplies: in ECB mode
the most frequent ciphertext block is the encryption of the most frequent plaintext block, and in
a compiled section that is alignment padding. `safedisc` takes the most repeated block of the most
encrypted-looking section and accepts any key that maps it to `00`, `0xCC` (MSVC `int3` padding)
or `0x90` filler.

In `.data` the most repeated block is the encryption of eight zero bytes; in `.text` it is a block
that is not one of those three fillers, so `.data` is what the search keys on. A full scan takes
seconds:

```bash
zig-out/bin/safedisc decrypt <game>/install/LANCER.ICD <openreliant>/game/decrypted/LANCER.EXE
```

To skip the search when the key is already known:

```bash
zig-out/bin/safedisc decrypt LANCER.ICD LANCER.EXE --key 434B4DAD
```

Decryption is self-checking. A section is decrypted only if doing so lowers its entropy; a wrong
key raises it, and the section is restored instead of being corrupted.

## Imports

The `kernel32` and `user32` import tables are obscured; the other ten libraries are untouched.

| Library | Entries a PE reader sees |
|---|---|
| `KERNEL32.dll` | 0 (emptied) |
| `USER32.dll` | 0 (emptied) |
| `GDI32`, `ADVAPI32`, `SHELL32`, `ole32`, `WINMM`, `VERSION`, `DINPUT`, `binkw32`, `mss32`, `srmemory` | intact |

Four things are done to those two tables. The first three are reversible from the file; the fourth
is not.

### 1. Thunks are XORed with the key

Every entry of both the lookup table and the address table is XORed with the key word
`0x434B4DAD`, leaving a value far too large to be an RVA. XORing again yields the hint/name RVA:
all 127 surviving entries land inside `.rdata`.

### 2. The first thunk of each table is zeroed

That terminates each table where it begins, so a PE reader sees no imports. The hint/name entry it
pointed at is still in `.rdata`, unreferenced. Scanning the name region for decodable entries no
thunk points at yields exactly two, and each sits among one table's surviving names:

| Table | Recovered first entry |
|---|---|
| `KERNEL32.dll` | `WriteFile` |
| `USER32.dll` | `FindWindowA` |

### 3. API names are encrypted

Each name byte is XORed with the previous *ciphertext* byte, the first with a seed of `0xE8`. A
name's NUL terminator therefore appears as a repeat of the byte before it, which is the visible
signature of the scheme.

The seed is the XOR of the four key bytes (`0x43 ^ 0x4B ^ 0x4D ^ 0xAD`), though that derivation is
**unverified** beyond this release, so `safedisc` measures the seed instead of assuming it: only the
first character of a name depends on it, and the seed that decodes every name is unique up to
`0x20`, the ASCII case bit. Win32 names are overwhelmingly capitalised, which settles the tie, and
`lstrlenA` survives as the expected lowercase exception.

This recovers the complete name set: **95 for `kernel32`, 34 for `user32`**.

```bash
safedisc imports LANCER.ICD
```

### 4. Call sites are redirected

The slot a call goes through does not name its API. The payload's C runtime (see
[`runtime.md`](https://github.com/OpenReliant/openreliant/blob/main/docs/binary/runtime.md)) is library code whose calls are fixed by what each of its functions
does, and it reaches different APIs through the same slot:

| Slot | Call site | Caller | API | Arguments |
|---|---|---|---|---|
| `0x004DC0D8` | `0x004A8B43` | `WinMain` | `CreateMutexA` | `NULL, TRUE, "StarlancerRunning"` |
| | `0x004D0373` | `_free` | `HeapFree` | `__crtheap, 0, block` |
| `0x004DC10C` | `0x004D1236` | `_WinMainCRTStartup` | `GetVersion` | none |
| | `0x004D2BF1` | `__getptd` | `TlsSetValue` | `___tlsindex, data` |
| | `0x004D5531` | `___sbh_free_block` | `HeapFree` | `__crtheap, 0, region` |
| `0x004DC19C` | `0x004D4E26` | `__write_lk` | `WriteFile` | five |
| | `0x004D1760` | `__strlwr` | `InterlockedDecrement` | `&___unguarded_readlc_active` |
| | `0x004D85C7` | `__wctomb_lk` | `WideCharToMultiByte` | eight |

These APIs remove their own arguments from the stack, so no one function behind a slot could serve
calls with none, two and three. What a call reaches is decided per call site, presumably from its
return address, and one API is reached through several slots: `HeapFree` through `0x004DC0D8` and
`0x004DC10C` above, `TlsSetValue` through `0x004DC10C` and, from `__mtinit`, `0x004DC114`. The
obscured tables were therefore not merely reordered: there is no permutation of slots to recover,
but an API for each call site.

These call sites are confirmed by their arguments:

| Call site | Slot | API | Evidence |
|---|---|---|---|
| `0x0047794A` | `0x004DC02C` | `LoadLibraryA` | `"DINPUT.DLL"` |
| `0x004A2716` | `0x004DC02C` | `LoadLibraryA` | `"winvfx8.dll"` or `"winvfx16.dll"` |
| `0x004DA3C3` | `0x004DC02C` | `LoadLibraryA` | `"user32.dll"`, in `___crtMessageBoxA` |
| `0x00477972` | `0x004DC050` | `GetProcAddress` | `"DirectInputCreateA"` |
| `0x004D188B` | `0x004DC050` | `GetProcAddress` | `"IsProcessorFeaturePresent"`, in `__ms_p5_mp_test_fdiv` |
| `0x00431AD1` | `0x004DC084` | `GetDateFormatA` | the picture string `"ddd',' MMM dd yyyy"` |
| `0x0047798A` | `0x004DC09C` | `OutputDebugStringA` | `"Couldn't GetProcAddress DInputCreate\r\n"` |
| `0x004A8B43` | `0x004DC0D8` | `CreateMutexA` | `NULL, TRUE, "StarlancerRunning"` |
| `0x004D187B` | `0x004DC100` | `GetModuleHandleA` | `"KERNEL32"` |
| `0x004D12E4` | `0x004DC100` | `GetModuleHandleA` | `NULL`, for `WinMain`'s instance |
| `0x004D12C1` | `0x004DC104` | `GetStartupInfoA` | the runtime's start-up, one argument, before `WinMain` |
| `0x004D1296` | `0x004DC108` | `GetCommandLineA` | the runtime's start-up, no arguments |
| `0x004D1236` | `0x004DC10C` | `GetVersion` | the first API the runtime's entry point calls |

Since a slot stands for no one API, `safedisc` **does not write the recovered names back into the
image**: any name on a slot would mislabel some of its call sites.

Consequences:

- **Static analysis is unaffected** except that `kernel32` and `user32` call targets show as bare
  IAT addresses, which say nothing of the API. All code and data are readable, and the other ten
  libraries resolve normally.
- **A runnable image** needs each call site's API.

**Open:** recovering each call site's API. Arity and argument types constrain it but do not
determine it, since many APIs share a signature, and the runtime's call sites, whose APIs its code
fixes, check any recovered mapping. `DPLAYERX.DLL` resolves an `(api index, library index)` pair to
an address at run time; how a call site leads to its pair is **unknown**. The loader and its
support files (`install/LANCER.EXE`, and `DPLAYERX.DLL`, `CLCD32.DLL`, `DRVMGT.DLL` and
`SECDRV.SYS` from disc 1) import into Ghidra like any other program.

## Reproducing

```bash
safedisc info <icd>            # sections, encryption state, import state
safedisc key <icd>             # recover the key by search
safedisc decrypt <icd> <out>   # write the readable image
safedisc imports <icd>         # recover the API names
```

## Verifying a decrypted image

The recovered image should satisfy all of the following:

- 1,151,021 bytes, the same size as the `.icd`: decryption is in place.
- Entry point `0x004D1210`, the C runtime's `_WinMainCRTStartup` (see [`runtime.md`](https://github.com/OpenReliant/openreliant/blob/main/docs/binary/runtime.md)).
- Build paths such as `C:\lancer\surrender\surrenderlib\srAPI.cpp` in `.rdata`.
- The 33 `TT_*` mission trigger names, and diagnostics including `StarlancerRunning`,
  `FATAL: SR Assertion Failed`, `DPInit: CoCreateInstance DirectPlay` and `dmodes.bin`.

## Prior art

The structure of SafeDisc 1 is publicly documented. Two sources describe the scheme in general
terms; the values in this document were derived from this release's own files.

- ArthaXerXes, "An overview of Safedisc versions": key structure per version, the emptied
  `kernel32`/`user32` tables, and the index-pair call stubs.
  <https://fravia.accessroot.com/artha_safedisc.htm>
- Luca D'Amico, "Midtown Madness / Safedisc 1.07" (2022): the loader-and-payload process
  relationship and the `DPLAYERX` resolution stubs.
  <https://www.lucadamico.dev/papers/drms/safedisc/MidtownMadness.pdf>
