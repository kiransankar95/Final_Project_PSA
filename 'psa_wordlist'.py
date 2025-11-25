#!/usr/bin/env python3
"""
pwtool.py

Password Strength Analyzer + Custom Wordlist Generator
- CLI via argparse and optional simple Tkinter GUI
- Uses zxcvbn for password strength (zxcvbn-python package)
- Generates leetspeak, year-appended, special-char variants from user-provided tokens
- Exports wordlist to .txt suitable for use with cracking tools

Ethics: Use only on systems/accounts you own or where you have permission.
"""

import argparse
import itertools
import json
import os
import random
import string
import sys
import time
from collections import OrderedDict

# zxcvbn import with fallback message if not installed
try:
    from zxcvbn import zxcvbn
except Exception:
    zxcvbn = None

# tkinter optional import
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    TK_AVAILABLE = True
except Exception:
    TK_AVAILABLE = False

# small built-in common passwords sample to enrich wordlists (not exhaustive)
COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "abc123", "monkey", "letmein", "dragon",
    "111111", "baseball", "iloveyou", "trustno1", "sunshine", "master", "welcome", "shadow"
]

# leetspeak mappings - include reasonable alternatives
LEET_MAP = {
    'a': ['4', '@'],
    'b': ['8'],
    'e': ['3'],
    'i': ['1', '!'],
    'l': ['1', '|'],
    'o': ['0'],
    's': ['5', '$'],
    't': ['7'],
    'g': ['9'],
    'z': ['2']
}

SPECIALS = ['!', '@', '#', '$', '%', '&', '*', '?']

# Default settings for combinatorics limits (to avoid explosion)
DEFAULT_LIMITS = {
    "max_results": 50000,      # maximum words to write to file unless overridden
    "max_token_combination": 3,  # combine up to this many tokens
    "year_range_limit": 30      # maximum years appended (if using a large range)
}

# -------------------------
# Utility and generation functions
# -------------------------

def analyze_password(password):
    """Analyze a password with zxcvbn if available; otherwise provide simple entropy estimate."""
    if zxcvbn:
        try:
            res = zxcvbn(password)
            # Extract useful fields
            score = res.get('score')  # 0-4
            guesses = res.get('guesses')
            entropy = res.get('entropy')
            warning = res.get('feedback', {}).get('warning', '')
            suggestions = res.get('feedback', {}).get('suggestions', [])
            return {
                'password': password,
                'score': score,
                'guesses': guesses,
                'entropy': entropy,
                'warning': warning,
                'suggestions': suggestions,
                'matched_sequence': res.get('sequence', [])
            }
        except Exception as e:
            # fallback
            pass

    # Fallback simple estimate: character set size * length => bits = length * log2(charset)
    charset = 0
    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(not c.isalnum() for c in password):
        # approximate printable punctuation
        charset += 32
    if charset == 0:
        entropy = 0.0
    else:
        import math
        entropy = round(len(password) * math.log2(charset), 2)
    # crude scoring
    if entropy < 28:
        score = 0
    elif entropy < 36:
        score = 1
    elif entropy < 60:
        score = 2
    elif entropy < 128:
        score = 3
    else:
        score = 4
    return {
        'password': password,
        'score': score,
        'guesses': None,
        'entropy': entropy,
        'warning': "zxcvbn not available; using simple entropy estimate" if zxcvbn is None else '',
        'suggestions': [],
        'matched_sequence': []
    }

def make_case_variants(token):
    """Return case variants of token (lower, upper, capitalize, alt-case)."""
    variants = {token, token.lower(), token.upper(), token.capitalize()}
    # also include toggled alternating case for short tokens
    if len(token) <= 8:
        alt = ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(token))
        variants.add(alt)
    return sorted(variants)

def apply_leets(token, max_variants=8):
    """Return a set of leetspeak variants of token (limit size)."""
    # We'll build by replacing some letters with leet substitutions; limit exponential blow-up.
    positions = []
    for i, ch in enumerate(token.lower()):
        if ch in LEET_MAP:
            positions.append((i, LEET_MAP[ch]))
    variants = set()
    # always include original
    variants.add(token)
    # produce variants by trying 1..k substitutions; cap total results
    # generate substitution masks
    max_subs = min(len(positions), 3)  # don't substitute too many
    for r in range(1, max_subs + 1):
        for combo in itertools.combinations(positions, r):
            # for each choice of replacement values
            lists = []
            idxs = []
            for pos, repls in combo:
                lists.append(repls)
                idxs.append(pos)
            for prod in itertools.product(*lists):
                arr = list(token)
                for i_, replacement in enumerate(prod):
                    arr[idxs[i_]] = replacement
                variants.add(''.join(arr))
                if len(variants) >= max_variants:
                    return sorted(variants)
    return sorted(variants)

def append_years(token, start_year=2000, end_year=2025):
    """Return list of token + year where year in range [start_year, end_year]."""
    years = []
    for y in range(start_year, end_year + 1):
        years.append(f"{token}{y}")
        years.append(f"{token}{str(y)[-2:]}")  # two-digit
    return years

def attach_specials(token, max_suffix=3):
    """Attach 0..max_suffix special chars to token (suffixes and prefixes)."""
    variants = set()
    variants.add(token)
    for n in range(1, max_suffix + 1):
        for combo in itertools.product(SPECIALS, repeat=n):
            s = ''.join(combo)
            variants.add(token + s)
            variants.add(s + token)
    return sorted(variants)

def generate_combinations(tokens, max_comb=3, max_results=50000):
    """Generate token combinations (permutations) up to length max_comb.
       Returns generator yielding combinations; the output is de-duplicated preserving insertion order.
    """
    seen = OrderedDict()
    count = 0
    tokens_unique = list(dict.fromkeys([t for t in tokens if t]))  # preserve order, drop empty
    for r in range(1, max_comb + 1):
        if count >= max_results:
            break
        # permutations to mimic ordering combinations like JohnSmith vs SmithJohn
        for perm in itertools.permutations(tokens_unique, r):
            w = ''.join(perm)
            if w not in seen:
                seen[w] = None
                count += 1
                yield w
            if count >= max_results:
                break

def limit_list(items, limit):
    if limit is None:
        return items
    return items[:limit]

# -------------------------
# Main wordlist builder
# -------------------------

def build_wordlist(
    names=None,
    dates=None,
    pets=None,
    custom=None,
    include_common=True,
    leets=True,
    append_years_opt=True,
    start_year=None,
    end_year=None,
    attach_specials_opt=True,
    max_results=None,
    max_combination=3
):
    """
    Build and return a list of wordlist tokens based on inputs and options.
    This function is careful about combinatorial explosion by enforcing max_results.
    """
    max_results = max_results or DEFAULT_LIMITS['max_results']
    tokens = []

    # collect base tokens (strip, unique)
    def extend_unique(lst):
        for x in lst or []:
            s = str(x).strip()
            if s and s not in tokens:
                tokens.append(s)

    extend_unique(names or [])
    extend_unique(dates or [])
    extend_unique(pets or [])
    extend_unique(custom or [])

    if include_common:
        extend_unique(COMMON_PASSWORDS)

    # create variants
    variants = OrderedDict()
    # Add single token case/leets/special/year variants
    for t in tokens:
        # base case variants
        for v in make_case_variants(t):
            variants[v] = None
            if leets:
                for lv in apply_leets(v):
                    variants[lv] = None
            # years
            if append_years_opt:
                if start_year is None:
                    start_year = time.localtime().tm_year - 10
                if end_year is None:
                    end_year = time.localtime().tm_year + 1
                # cap year range
                if (end_year - start_year) > DEFAULT_LIMITS['year_range_limit']:
                    # shrink to reasonable bound
                    start_year = end_year - DEFAULT_LIMITS['year_range_limit']
                for yv in append_years(v, start_year, end_year):
                    variants[yv] = None
            # specials
            if attach_specials_opt:
                for sv in attach_specials(v, max_suffix=2):
                    variants[sv] = None

    # include raw tokens too
    for t in tokens:
        variants[t] = None

    # Combine tokens (permutations)
    combined_count = 0
    for combo in generate_combinations(tokens, max_comb=max_combination, max_results=max_results):
        # For each combo, apply some simple variant expansions (case, leet, year)
        if len(variants) >= max_results:
            break
        # add plain combo
        if combo not in variants:
            variants[combo] = None
        # small set of variants for combo to avoid explosion
        if leets:
            for lv in apply_leets(combo, max_variants=4):
                variants[lv] = None
        if append_years_opt:
            # use a small year window for combined tokens
            sy = (start_year or (time.localtime().tm_year - 5))
            ey = (end_year or time.localtime().tm_year)
            for yv in append_years(combo, sy, ey):
                variants[yv] = None
        if attach_specials_opt:
            for sv in attach_specials(combo, max_suffix=1):
                variants[sv] = None
        combined_count += 1

    # convert to list and cap
    results = list(variants.keys())
    if len(results) > max_results:
        results = results[:max_results]
    return results

def write_wordlist(wordlist, outpath):
    """Write wordlist (iterable) to outpath (text file)."""
    outdir = os.path.dirname(outpath)
    if outdir and not os.path.exists(outdir):
        os.makedirs(outdir, exist_ok=True)
    with open(outpath, 'w', encoding='utf-8', errors='ignore') as f:
        for w in wordlist:
            f.write(w + '\n')
    return outpath

# -------------------------
# CLI
# -------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Password Strength Analyzer and Custom Wordlist Generator"
    )
    # analysis
    p.add_argument('--analyze', '-a', help="Password to analyze (quote it).", metavar='PASSWORD')
    # wordlist generation inputs
    p.add_argument('--name', '-n', action='append', help="Name(s) to include (can repeat).")
    p.add_argument('--date', '-d', action='append', help="Date(s) or numbers to include (YYYY or DDMM).")
    p.add_argument('--pet', '-p', action='append', help="Pet/other words to include (can repeat).")
    p.add_argument('--custom', '-c', action='append', help="Custom token(s) to include (can repeat).")
    p.add_argument('--no-common', action='store_true', help="Do not include built-in common passwords.")
    p.add_argument('--no-leet', action='store_true', help="Disable leetspeak variants.")
    p.add_argument('--no-years', action='store_true', help="Do not append years to tokens.")
    p.add_argument('--start-year', type=int, default=None, help="Start year for append (inclusive).")
    p.add_argument('--end-year', type=int, default=None, help="End year for append (inclusive).")
    p.add_argument('--no-specials', action='store_true', help="Do not add special char prefixes/suffixes.")
    p.add_argument('--max-results', type=int, default=DEFAULT_LIMITS['max_results'], help="Maximum number of words in final list.")
    p.add_argument('--max-combine', type=int, default=DEFAULT_LIMITS['max_token_combination'], help="Max tokens to combine in permutations.")
    p.add_argument('--output', '-o', default='wordlist.txt', help="Output .txt filepath.")
    p.add_argument('--gui', action='store_true', help="Launch GUI instead of CLI (tkinter required).")
    return p.parse_args()

def run_cli(args):
    # If analyze only
    if args.analyze:
        res = analyze_password(args.analyze)
        print("Password analysis:")
        print(json.dumps(res, indent=2))
        # continue to wordlist generation if other params present

    # If any generation parameter is present, generate
    generation_requested = any([args.name, args.date, args.pet, args.custom])
    if generation_requested:
        print("Building wordlist with settings:")
        print(f" names={args.name}, dates={args.date}, pets={args.pet}, custom={args.custom}")
        wl = build_wordlist(
            names=args.name,
            dates=args.date,
            pets=args.pet,
            custom=args.custom,
            include_common=not args.no_common,
            leets=(not args.no_leet),
            append_years_opt=(not args.no_years),
            start_year=args.start_year,
            end_year=args.end_year,
            attach_specials_opt=(not args.no_specials),
            max_results=args.max_results,
            max_combination=args.max_combine
        )
        print(f"Generated {len(wl)} entries (capped at {args.max_results}). Writing to {args.output} ...")
        write_wordlist(wl, args.output)
        print("Done.")
    else:
        if not args.analyze:
            print("No action specified. Use --analyze or supply --name/--date/--pet/--custom to generate wordlist.")
            print("Use --help for options.")

# -------------------------
# Simple Tkinter GUI
# -------------------------

def run_gui():
    if not TK_AVAILABLE:
        print("Tkinter not available; cannot launch GUI. Use CLI instead.")
        return

    root = tk.Tk()
    root.title("Password Strength Analyzer & Wordlist Generator")
    root.geometry("700x500")

    frame = ttk.Frame(root, padding=10)
    frame.pack(fill='both', expand=True)

    # Input text boxes
    ttk.Label(frame, text="Names (comma separated)").grid(row=0, column=0, sticky='w')
    names_var = tk.StringVar()
    ttk.Entry(frame, textvariable=names_var, width=60).grid(row=0, column=1, sticky='w')

    ttk.Label(frame, text="Dates / Numbers (comma separated)").grid(row=1, column=0, sticky='w')
    dates_var = tk.StringVar()
    ttk.Entry(frame, textvariable=dates_var, width=60).grid(row=1, column=1, sticky='w')

    ttk.Label(frame, text="Pets / Other tokens (comma separated)").grid(row=2, column=0, sticky='w')
    pets_var = tk.StringVar()
    ttk.Entry(frame, textvariable=pets_var, width=60).grid(row=2, column=1, sticky='w')

    ttk.Label(frame, text="Custom tokens (comma separated)").grid(row=3, column=0, sticky='w')
    custom_var = tk.StringVar()
    ttk.Entry(frame, textvariable=custom_var, width=60).grid(row=3, column=1, sticky='w')

    # Analysis field
    ttk.Label(frame, text="Password to analyze").grid(row=4, column=0, sticky='w')
    analyze_var = tk.StringVar()
    ttk.Entry(frame, textvariable=analyze_var, show='*', width=40).grid(row=4, column=1, sticky='w')

    # Options
    no_common_var = tk.BooleanVar(value=False)
    tk.Checkbutton(frame, text="Exclude common passwords", variable=no_common_var).grid(row=5, column=0, sticky='w')
    no_leet_var = tk.BooleanVar(value=False)
    tk.Checkbutton(frame, text="Disable leetspeak", variable=no_leet_var).grid(row=5, column=1, sticky='w')
    no_years_var = tk.BooleanVar(value=False)
    tk.Checkbutton(frame, text="Disable year appends", variable=no_years_var).grid(row=6, column=0, sticky='w')
    no_specials_var = tk.BooleanVar(value=False)
    tk.Checkbutton(frame, text="Disable special chars", variable=no_specials_var).grid(row=6, column=1, sticky='w')

    ttk.Label(frame, text="Start year").grid(row=7, column=0, sticky='w')
    start_year_var = tk.StringVar(value=str(time.localtime().tm_year - 10))
    ttk.Entry(frame, textvariable=start_year_var, width=10).grid(row=7, column=1, sticky='w')

    ttk.Label(frame, text="End year").grid(row=8, column=0, sticky='w')
    end_year_var = tk.StringVar(value=str(time.localtime().tm_year))
    ttk.Entry(frame, textvariable=end_year_var, width=10).grid(row=8, column=1, sticky='w')

    ttk.Label(frame, text="Max results").grid(row=9, column=0, sticky='w')
    max_results_var = tk.StringVar(value=str(DEFAULT_LIMITS['max_results']))
    ttk.Entry(frame, textvariable=max_results_var, width=12).grid(row=9, column=1, sticky='w')

    ttk.Label(frame, text="Max tokens combined").grid(row=10, column=0, sticky='w')
    max_comb_var = tk.StringVar(value=str(DEFAULT_LIMITS['max_token_combination']))
    ttk.Entry(frame, textvariable=max_comb_var, width=12).grid(row=10, column=1, sticky='w')

    output_var = tk.StringVar(value="wordlist.txt")
    ttk.Label(frame, text="Output file").grid(row=11, column=0, sticky='w')
    ttk.Entry(frame, textvariable=output_var, width=40).grid(row=11, column=1, sticky='w')

    # Result text area
    res_text = tk.Text(frame, height=12, width=80)
    res_text.grid(row=12, column=0, columnspan=2, pady=10)

    def do_analyze():
        pw = analyze_var.get().strip()
        if not pw:
            messagebox.showinfo("Info", "Enter a password to analyze.")
            return
        res = analyze_password(pw)
        res_text.insert('end', "Password analysis:\n")
        res_text.insert('end', json.dumps(res, indent=2) + "\n\n")
        res_text.see('end')

    def do_generate():
        names = [x.strip() for x in names_var.get().split(',') if x.strip()]
        dates = [x.strip() for x in dates_var.get().split(',') if x.strip()]
        pets = [x.strip() for x in pets_var.get().split(',') if x.strip()]
        custom = [x.strip() for x in custom_var.get().split(',') if x.strip()]
        try:
            sy = int(start_year_var.get())
            ey = int(end_year_var.get())
            mr = int(max_results_var.get())
            mc = int(max_comb_var.get())
        except Exception:
            messagebox.showerror("Error", "Start/end year, max results and max combine must be integers.")
            return
        wl = build_wordlist(
            names=names, dates=dates, pets=pets, custom=custom,
            include_common=(not no_common_var.get()),
            leets=(not no_leet_var.get()),
            append_years_opt=(not no_years_var.get()),
            start_year=sy, end_year=ey,
            attach_specials_opt=(not no_specials_var.get()),
            max_results=mr,
            max_combination=mc
        )
        out = output_var.get() or "wordlist.txt"
        write_wordlist(wl, out)
        res_text.insert('end', f"Generated {len(wl)} words and saved to {out}\n")
        res_text.see('end')

    btn_frame = ttk.Frame(frame)
    btn_frame.grid(row=13, column=0, columnspan=2, pady=6)
    ttk.Button(btn_frame, text="Analyze Password", command=do_analyze).grid(row=0, column=0, padx=4)
    ttk.Button(btn_frame, text="Generate Wordlist", command=do_generate).grid(row=0, column=1, padx=4)
    ttk.Button(btn_frame, text="Quit", command=root.quit).grid(row=0, column=2, padx=4)

    root.mainloop()

# -------------------------
# Entrypoint
# -------------------------
def main():
    args = parse_args()
    if args.gui:
        run_gui()
    else:
        run_cli(args)

if __name__ == '__main__':
    main()
