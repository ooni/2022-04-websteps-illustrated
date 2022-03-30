"""
Submodule of dataformat that contains type wrappers.

We extensively use type wrappers for parsing and ensuring that we
are passed the correct data types for fields.

Each type wrapper constructor takes in input Any and asserts
whether such an Any is actually of the required type.

Each type wrapper has a method called unwrap that allows you to
get the underlying value using the expected type.

The DictWrapper type contains several more accessors to get
values for string keys and ensure that they're of the correct type.

When a type assertion fails, we raise ValueError exceptions.
"""

from __future__ import annotations

from typing import (
    Any,
    Dict,
    List,
    Optional,
)


class IntWrapper:
    """Wrapper for int."""

    def __init__(self, value: Any):
        if not isinstance(value, int):
            raise ValueError("expected an integer")
        self._value = int(value)

    def unwrap(self) -> int:
        return self._value


class FloatWrapper:
    """Wrapper for float."""

    def __init__(self, value: Any):
        if not isinstance(value, float):
            raise ValueError("expected a float")
        self._value = float(value)

    def unwrap(self) -> float:
        return self._value


class StrWrapper:
    """Wrapper for str."""

    def __init__(self, value: Any):
        if not isinstance(value, str):
            raise ValueError("expected a string")
        self._value = str(value)

    def unwrap(self) -> str:
        return self._value


class ListWrapper:
    """Wrapper for list."""

    def __init__(self, value: Any):
        if not isinstance(value, list):
            raise ValueError("expected a list")
        self._value = list(value)

    def unwrap(self) -> List:
        return self._value


class BoolWrapper:
    """Wrapper for bool."""

    def __init__(self, value: Any):
        if not isinstance(value, bool):
            raise ValueError("expected a bool")
        self._value = bool(value)

    def unwrap(self) -> bool:
        return self._value


class DictWrapper:
    """Wrapper for dict."""

    def __init__(self, value: Any):
        if not isinstance(value, dict):
            raise ValueError("expected a dictionary")
        self._value = dict(value)

    def getinteger(self, key: Any) -> int:
        return IntWrapper(self._value.get(StrWrapper(key).unwrap(), 0) or 0).unwrap()

    def getstring(self, key: Any) -> str:
        return StrWrapper(self._value.get(StrWrapper(key).unwrap(), "") or "").unwrap()

    def getoptionalstring(self, key: Any) -> Optional[str]:
        v = self._value.get(StrWrapper(key).unwrap())
        if v is None:
            return None
        return StrWrapper(v).unwrap()

    def getfailure(self, key: Any) -> Optional[str]:
        # A failure is a OONI data type in the archival data format
        # that corresponds to an optional string.
        return self.getoptionalstring(key)

    def getfloat(self, key: Any) -> float:
        return FloatWrapper(
            self._value.get(StrWrapper(key).unwrap(), 0.0) or 0.0
        ).unwrap()

    def getdictionary(self, key: Any) -> DictWrapper:
        return DictWrapper(self._value.get(StrWrapper(key).unwrap(), {}) or {})

    def getlist(self, key: Any) -> List:
        return ListWrapper(self._value.get(StrWrapper(key).unwrap(), []) or []).unwrap()

    def getoptionalbool(self, key: Any) -> Optional[bool]:
        v = self._value.get(StrWrapper(key).unwrap())
        if v is None:
            return None
        return BoolWrapper(v).unwrap()

    def getbool(self, key: Any) -> bool:
        return BoolWrapper(
            self._value.get(StrWrapper(key).unwrap(), False) or False
        ).unwrap()

    def getany(self, key: Any) -> Any:
        # Sometimes you need to obtain the given key as Any.
        return self._value.get(StrWrapper(key).unwrap())

    def unwrap(self) -> Dict:
        return self._value
