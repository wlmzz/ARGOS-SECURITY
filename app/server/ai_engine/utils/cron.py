"""
ARGOS — Cron Expression Parser
Adapted from Claude Code utils/cron.ts (Anthropic Inc.)

Minimal 5-field cron parser and next-run calculator.
Supports: minute hour day-of-month month day-of-week

Field syntax:
  *         wildcard (every value)
  N         single value
  */N       step
  N-M       range
  N-M/S     range with step
  A,B,C     comma list (combinations of the above)

No L, W, ?, or name aliases. All times in local timezone.

ARGOS use: scheduled threat scans, credential rotation checks.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Set

# ─── FIELD RANGES ─────────────────────────────────────────────────────────────

_FIELD_RANGES = [
    (0, 59),   # minute
    (0, 23),   # hour
    (1, 31),   # day-of-month
    (1, 12),   # month
    (0, 6),    # day-of-week (0=Sunday; 7 accepted as alias)
]

_DAY_NAMES = ["Sunday", "Monday", "Tuesday", "Wednesday",
               "Thursday", "Friday", "Saturday"]


@dataclass
class CronFields:
    minute:       list[int]
    hour:         list[int]
    day_of_month: list[int]
    month:        list[int]
    day_of_week:  list[int]


# ─── FIELD EXPANSION ──────────────────────────────────────────────────────────

def _expand_field(field: str, fmin: int, fmax: int) -> Optional[list[int]]:
    """
    Parse a single cron field into a sorted list of matching values.
    Returns None if the field is invalid.
    """
    out: Set[int] = set()
    is_dow = (fmin == 0 and fmax == 6)

    for part in field.split(","):
        # wildcard or */N
        m = re.match(r"^\*(?:/(\d+))?$", part)
        if m:
            step = int(m.group(1)) if m.group(1) else 1
            if step < 1:
                return None
            for i in range(fmin, fmax + 1, step):
                out.add(i)
            continue

        # N-M or N-M/S
        m = re.match(r"^(\d+)-(\d+)(?:/(\d+))?$", part)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2))
            step = int(m.group(3)) if m.group(3) else 1
            eff_max = 7 if is_dow else fmax
            if lo > hi or step < 1 or lo < fmin or hi > eff_max:
                return None
            for i in range(lo, hi + 1, step):
                out.add(0 if (is_dow and i == 7) else i)
            continue

        # plain N
        m = re.match(r"^\d+$", part)
        if m:
            n = int(part)
            if is_dow and n == 7:
                n = 0
            if n < fmin or n > fmax:
                return None
            out.add(n)
            continue

        return None  # unrecognised token

    if not out:
        return None
    return sorted(out)


# ─── PUBLIC API ───────────────────────────────────────────────────────────────

def parse_cron_expression(expr: str) -> Optional[CronFields]:
    """
    Parse a 5-field cron expression into expanded number lists.
    Returns None for invalid or unsupported expressions.
    """
    parts = expr.strip().split()
    if len(parts) != 5:
        return None

    expanded = []
    for i, part in enumerate(parts):
        fmin, fmax = _FIELD_RANGES[i]
        result = _expand_field(part, fmin, fmax)
        if result is None:
            return None
        expanded.append(result)

    return CronFields(
        minute       = expanded[0],
        hour         = expanded[1],
        day_of_month = expanded[2],
        month        = expanded[3],
        day_of_week  = expanded[4],
    )


def compute_next_cron_run(fields: CronFields, from_dt: datetime) -> Optional[datetime]:
    """
    Compute the next datetime strictly after `from_dt` that matches `fields`.
    All calculations in local timezone. Bounded at 366 days.
    Returns None if no match found (impossible for valid cron, guards against bugs).

    Standard OR semantics: if both dom and dow are constrained, EITHER matching
    is sufficient.
    """
    minute_set = set(fields.minute)
    hour_set   = set(fields.hour)
    dom_set    = set(fields.day_of_month)
    month_set  = set(fields.month)
    dow_set    = set(fields.day_of_week)

    dom_wild = len(fields.day_of_month) == 31
    dow_wild = len(fields.day_of_week)  == 7

    # Round up to the next whole minute (strictly after from_dt)
    t = from_dt.replace(second=0, microsecond=0) + timedelta(minutes=1)

    max_iter = 366 * 24 * 60
    for _ in range(max_iter):
        # Month check
        if t.month not in month_set:
            # Jump to start of next month
            if t.month == 12:
                t = t.replace(year=t.year + 1, month=1, day=1, hour=0, minute=0)
            else:
                t = t.replace(month=t.month + 1, day=1, hour=0, minute=0)
            continue

        # Day check (dom vs dow OR semantics)
        dom = t.day
        dow = t.weekday()          # Mon=0…Sun=6
        dow_cron = (dow + 1) % 7   # convert to cron convention (Sun=0)

        if dom_wild and dow_wild:
            day_matches = True
        elif dom_wild:
            day_matches = dow_cron in dow_set
        elif dow_wild:
            day_matches = dom in dom_set
        else:
            day_matches = (dom in dom_set) or (dow_cron in dow_set)

        if not day_matches:
            t = (t + timedelta(days=1)).replace(hour=0, minute=0)
            continue

        if t.hour not in hour_set:
            t = (t + timedelta(hours=1)).replace(minute=0)
            continue

        if t.minute not in minute_set:
            t += timedelta(minutes=1)
            continue

        return t

    return None


# ─── HUMAN-READABLE DESCRIPTION ───────────────────────────────────────────────

def cron_to_human(cron: str) -> str:
    """
    Convert common cron patterns to a human-readable description.
    Falls back to the raw cron string for unsupported patterns.
    """
    parts = cron.strip().split()
    if len(parts) != 5:
        return cron

    minute, hour, dom, month, dow = parts

    # Every N minutes: */N * * * *
    m = re.match(r"^\*/(\d+)$", minute)
    if m and hour == "*" and dom == "*" and month == "*" and dow == "*":
        n = int(m.group(1))
        return "Every minute" if n == 1 else f"Every {n} minutes"

    # Every hour at :mm: mm * * * *
    if re.match(r"^\d+$", minute) and hour == "*" and dom == "*" and month == "*" and dow == "*":
        mm = int(minute)
        if mm == 0:
            return "Every hour"
        return f"Every hour at :{mm:02d}"

    # Every N hours: mm */N * * *
    m2 = re.match(r"^\*/(\d+)$", hour)
    if re.match(r"^\d+$", minute) and m2 and dom == "*" and month == "*" and dow == "*":
        n = int(m2.group(1))
        mm = int(minute)
        suffix = f" at :{mm:02d}" if mm != 0 else ""
        return f"Every hour{suffix}" if n == 1 else f"Every {n} hours{suffix}"

    # Need fixed hour + minute for remaining cases
    if not re.match(r"^\d+$", minute) or not re.match(r"^\d+$", hour):
        return cron

    mm, hh = int(minute), int(hour)
    time_str = datetime(2000, 1, 1, hh, mm).strftime("%-I:%M %p")

    # Daily: mm hh * * *
    if dom == "*" and month == "*" and dow == "*":
        return f"Every day at {time_str}"

    # Specific weekday: mm hh * * D
    m3 = re.match(r"^\d$", dow)
    if dom == "*" and month == "*" and m3:
        day_idx = int(dow) % 7
        return f"Every {_DAY_NAMES[day_idx]} at {time_str}"

    # Weekdays: mm hh * * 1-5
    if dom == "*" and month == "*" and dow == "1-5":
        return f"Weekdays at {time_str}"

    return cron
