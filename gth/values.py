"""Shared JSON value checks. These checks do not classify radio activity."""
import math


def finite(value):
    try:return isinstance(value,(int,float)) and not isinstance(value,bool) and math.isfinite(value)
    except (OverflowError,ValueError):return False


def count(value):
    return int(value) if finite(value) and value>=0 else None


def mapping(value):
    return value if isinstance(value,dict) else {}


def timestamp(value):
    # UTC years 1970 through 9999. This is a format bound, not an attack limit.
    return isinstance(value,(int,float)) and not isinstance(value,bool) and 0<=value<253402300800 and finite(value)
