# The `.ljar` format, version 1

All integers are unsigned LEB128 varints unless noted. Signed values are
zigzag-mapped first (`(v << 1) ^ (v >> 63)`). `bytes` means a varint length
followed by that many bytes.

## File

```text
+---------------------------+
| header      8 bytes       |  "LOGJAR\0" 0x01
+---------------------------+
| segment 0                 |
| segment 1                 |
| ...                       |
+---------------------------+
| footer                    |  index of streams and segments
+---------------------------+
| trailer     20 bytes      |  footer offset (u64 LE) | footer length (u32 LE)
|                           |  | crc32 of footer (u32 LE) | "LJF1"
+---------------------------+
```

Appending writes new segments and a new footer + trailer *after* the
previous trailer; older footers become dead bytes. The live footer is the one
named by the trailer at end of file. If the last 20 bytes are not a valid
trailer (crash, or a writer mid-append), a reader scans backwards for the
newest `"LJF1"` whose trailer is self-consistent and whose footer CRC
verifies. A writer opening the file truncates anything after that trailer.

A trailer is valid when `offset + length == trailer position`, the offset is
past the header, the CRC matches, the footer decodes completely, and every
segment it lists ends before the footer.

## Footer

```text
stream count
  per stream:   name: bytes (UTF-8, relative path, '/'-separated)
                unterminated: u8   (1 = last line has no trailing '\n')
segment count
  per segment:  offset, length, stream id, line count, raw bytes
                has_time: u8, then if 1: min_ns (signed), max_ns (signed)
```

Segments of one stream appear in line order. `raw bytes` counts newlines.
`min_ns`/`max_ns` cover lines whose timestamp format includes a year; a
segment with no such line has `has_time = 0`.

## Segment

```text
directory length
directory:      5 x (raw length, compressed length)
5 blocks, back to back, each an independent zstd frame with content checksum
```

Blocks, in order:

### 0. meta

```text
spec count
  per spec:      spec text: bytes        e.g. "%Y-%m-%d %H:%M:%S,%3"
template count
  per template:  template: bytes, row count, offset into the vars block
```

### 1. dict

```text
entry count
  per entry: bytes
```

Dictionary ids are assigned in first-seen order within the segment.

### 2. events

One template id per line.

### 3. times

First, one spec id per line (0 = no timestamp; otherwise 1-based index into
the meta block's specs). Then, for each line with a spec id, the signed
delta of its native value from the previous such line (the first delta is
from 0).

A native value is seconds since 1970-01-01T00:00:00 UTC multiplied by
10^f, where f is 3, 6 or 9 if the spec contains `%3`, `%6` or `%9`, else 0.

### 4. vars

For each template, in template-id order, at its recorded offset: for each
slot in the template, left to right, one column holding that slot's value
for every row of the template, in line order.

Integer and dictionary columns begin with a mode varint:

* `0` raw: each value as stored (integers zigzagged, dictionary ids as is)
* `1` delta: each value is the zigzagged difference from the previous row's
  value (first row from 0)

Float columns have no mode; each row is two varints, `digits` then `meta`.

## Templates

A template is the line's message (after the timestamp) with each variable
replaced by a placeholder byte:

| byte | meaning |
|------|---------|
| 0x11 | integer variable |
| 0x12 | float variable |
| 0x13 | dictionary variable |
| 0x14 | escape: the next byte is literal |

Literal bytes 0x11 to 0x14 in the input are written as 0x14 followed by the
byte.

### Tokens and variables

A delimiter is any byte `<= 0x20`, `0x7f`, or ASCII punctuation other than
`. - _ +`. A token is a maximal run of non-delimiters. A token containing an
ASCII digit is a variable:

* **integer**: `-?(0|[1-9][0-9]*)` fitting an i64, excluding `-0`.
  Stored zigzagged.
* **float**: `-?[0-9]+\.[0-9]+` with at most 19 digits. Stored as the digits
  read as one integer, plus `meta = digit_count << 6 | fraction_digits << 1 | negative`.
  Leading and trailing zeros survive because the digit count is stored.
* **dictionary**: any other token with a digit. Stored as a dictionary id.

### Timestamp specs

| code | meaning |
|------|---------|
| `%Y` | 4-digit year |
| `%y` | 2-digit year (< 70 means 20xx) |
| `%m` `%d` `%H` `%M` `%S` | 2-digit fields |
| `%e` | day, space-padded to 2 |
| `%b` | `Jan` .. `Dec` |
| `%a` | `Sun` .. `Sat` (must agree with the date) |
| `%3` `%6` `%9` | fraction digits |

Any other byte is literal. A timestamp is only extracted if formatting the
parsed value reproduces the input bytes exactly, so decoding is lossless by
construction. Specs without a year decode in 1970.

## Reconstructing a line

1. If the line's spec id is non-zero, format its native value with the spec.
2. Walk the template: copy literal bytes, undo escapes, and for each
   placeholder take the next row from that slot's column and write it out
   (integer in decimal, float from digits/meta, dictionary entry verbatim).
3. Append `\n`, except after the last line of a stream marked unterminated.
