# openreliant-safedisc

Private. Recovers StarLancer's game executable from its SafeDisc 1 wrapper, for the
[OpenReliant](https://github.com/vdmkenny/openreliant) analysis: the Ghidra project and the tables
`tablegen` derives read it from `game/decrypted/LANCER.EXE`. The OpenReliant engine itself never
needs it; it reads only the game's data files.

This is kept out of the public repository on purpose. Do not publish it.

```bash
zig build                       # zig-out/bin/safedisc
zig build test                  # the tests build their own inputs and need no game files
zig-out/bin/safedisc decrypt <game>/install/LANCER.ICD <openreliant>/game/decrypted/LANCER.EXE
```

| Command | Does |
|---|---|
| `safedisc info <icd>` | Sections, encryption state, import state |
| `safedisc key <icd>` | Recovers the key by searching all 2^32 |
| `safedisc decrypt <icd> <out> [--key <hex>]` | Writes the readable image |
| `safedisc imports <icd> [--key <hex>]` | Recovers the API names SafeDisc hides |

[`docs/safedisc.md`](docs/safedisc.md) describes the scheme, the key recovery, the hidden imports
and what a runnable image still needs. `src/pe.zig` is a copy of OpenReliant's PE reader.

## The key

This release's recovered TEA key is `0x434B4DAD`. The full 128-bit key is that word four times, so
its bytes are `AD 4D 4B 43` per word. It is kept here so it need not be searched for again, and
because it is the one value the purge took out of the public repository:

```bash
safedisc decrypt LANCER.ICD LANCER.EXE --key 434B4DAD
```

Licensed under the [Mozilla Public License 2.0](LICENSE).
