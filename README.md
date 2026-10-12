# Blind SQL Injection Extractor

A small, dependency-light tool that extracts data through a **boolean-based
blind SQL injection** — one character at a time — using a binary search over
ASCII codes.

It was written while working through the
[PortSwigger Web Security Academy](https://portswigger.net/web-security/sql-injection/blind)
blind SQL injection labs, as a way to understand the technique end to end
rather than relying on `sqlmap`.

> ⚠️ **For authorised testing and education only.** Run this only against
> systems you own or have explicit written permission to test. Using it
> against third-party systems without authorisation is illegal.

---

## What "blind" means here

In an in-band injection (e.g. a `UNION` attack) the query result is printed
back in the page, so you can read the data directly.

In a **blind** injection the result is never returned. What leaks instead is
the application's *behaviour*: in the "conditional response" case the page
looks one way when an injected condition is **true** and another way when it
is **false** (for example, a `Welcome back` message appears or disappears).

That single observable difference is a **yes/no oracle**. By asking the
database a long series of yes/no questions about the target value, we can
reconstruct it bit by bit.

## How it works

1. **Calibrate the oracle.** Send a known-true condition (`1=1`) and a
   known-false one (`1=2`) and record how the responses differ — either by a
   marker string (`--true-string "Welcome back"`) or, by default, by response
   length (a threshold halfway between the true and false lengths).
2. **Find the length** of the target value with a binary search:
   `LENGTH((<query>)) > N`.
3. **Extract each character** with a binary search over its ASCII code:
   `ASCII(SUBSTRING((<query>), pos, 1)) > N`. ~7 requests per character
   instead of ~95 for a linear scan.

The injection point in this tool is a **cookie** whose value is concatenated
into the query. The raw `Cookie` header is built by hand so that the spaces,
quotes and comment dashes in the payload reach the server intact.

## Requirements

- Python 3.8+
- `pip install -r requirements.txt`

## Usage

```bash
python3 blind_sqli.py \
  --url "https://TARGET/filter?category=Gifts" \
  --inject-cookie TrackingId \
  --seed "YOUR_VALID_TRACKINGID" \
  --cookie "session=YOUR_SESSION" \
  --true-string "Welcome back"
```

Minimal example using the default length-based oracle (no marker needed):

```bash
python3 blind_sqli.py \
  --url "https://TARGET/filter?category=Gifts" \
  --seed "YOUR_VALID_TRACKINGID" \
  --cookie "session=YOUR_SESSION"
```

### Key options

| Option | Meaning |
| --- | --- |
| `--url` | Target URL that reflects the oracle |
| `--inject-cookie` | Name of the injectable cookie (default `TrackingId`) |
| `--seed` | A valid value of that cookie; the breakout `' AND ` is added automatically |
| `--cookie name=value` | Extra cookie sent unchanged (repeatable, e.g. `session=...`) |
| `--query` | The sub-query to extract (default: the `administrator` password) |
| `--length` | Known value length; `0` = auto-detect |
| `--true-string` | Decide truth by this marker instead of response length |
| `--min-code` / `--max-code` | ASCII search range (default `32`–`126`) |

Run `python3 blind_sqli.py -h` for the full list.

## Example output

```
[*] Calibrating oracle...
[calib] true_len=5594 false_len=5533 threshold=5563 (length mode)
[*] Auto-detecting value length...
[*] Length = 20
[*] Extracting value...
[+] char  1: 'a'   ->   a
[+] char  2: 'b'   ->   ab
...
[*] DONE. Extracted value = <password>
```

## Defence

This class of bug is prevented and contained by:

- **Parameterised queries / prepared statements** — the fix. User input is
  sent to the database separately from the query template, so a quote in the
  input can never break out into code.
- **Uniform responses** for success and failure — removes the boolean oracle.
- **Query timeouts** — break time-based variants (`SLEEP`).
- **Least privilege** for the application's DB account — limits the blast
  radius even if injection occurs.
- **Monitoring** for the tell-tale pattern of thousands of near-identical
  requests differing by a single character.

## Notes

- `--true-string` (marker mode) is the most robust oracle when a reliable
  marker exists; length mode is a good default otherwise.
- The payload comments out the rest of the query with `--`, so the injected
  condition should end on a non-quote (the defaults handle this).
- A production-grade tool (e.g. `sqlmap`) adds threading, DBMS fingerprinting
  and many evasion techniques; this project favours readability.
