"""Type annotations and markers for zero-leakage PII boundaries.

Provides Vaulted[T] for data models requiring in-memory validation detokenisation
without persistent storage, and Detokenise[T] for authorised tool parameters.
"""

import types
from typing import Annotated, Union, get_args, get_origin


class VaultedMarker:
    """Metadata marker for fields containing vaulted PII tokens."""

    def __repr__(self) -> str:
        return "VaultedMarker()"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, VaultedMarker)

    def __hash__(self) -> int:
        return hash(self.__class__.__name__)


class DetokeniseMarker:
    """Metadata marker for tool parameters authorised to receive detokenised values."""

    def __repr__(self) -> str:
        return "DetokeniseMarker()"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, DetokeniseMarker)

    def __hash__(self) -> int:
        return hash(self.__class__.__name__)


# PEP 695 Type Aliases for Vaulted and Detokenise
type Vaulted[T] = Annotated[T, VaultedMarker()]
type Detokenise[T] = Annotated[T, DetokeniseMarker()]


def is_vaulted(annotation: object) -> bool:
    """Check whether an annotation is marked with or contains Vaulted[T]."""
    if annotation is Vaulted or isinstance(annotation, VaultedMarker):
        return True
    origin = get_origin(annotation)
    if origin is Vaulted:
        return True
    if origin in (Union, types.UnionType):
        return any(is_vaulted(arg) for arg in get_args(annotation))
    if origin is Annotated:
        args = get_args(annotation)
        return any(
            isinstance(arg, VaultedMarker)
            or (isinstance(arg, type) and issubclass(arg, VaultedMarker))
            for arg in args[1:]
        )
    if hasattr(annotation, "__value__"):
        return is_vaulted(annotation.__value__)
    return False


def is_detokenise(annotation: object) -> bool:
    """Check whether an annotation is marked with or contains Detokenise[T]."""
    if annotation is Detokenise or isinstance(annotation, DetokeniseMarker):
        return True
    origin = get_origin(annotation)
    if origin is Detokenise:
        return True
    if origin in (Union, types.UnionType):
        return any(is_detokenise(arg) for arg in get_args(annotation))
    if origin is Annotated:
        args = get_args(annotation)
        return any(
            isinstance(arg, DetokeniseMarker)
            or (isinstance(arg, type) and issubclass(arg, DetokeniseMarker))
            for arg in args[1:]
        )
    if hasattr(annotation, "__value__"):
        return is_detokenise(annotation.__value__)
    return False


def get_vaulted_inner_type(annotation: object) -> object:
    """Extract the inner type wrapped by Vaulted[T], inspecting Union and Optional types."""
    origin = get_origin(annotation)
    if origin in (Union, types.UnionType):
        for arg in get_args(annotation):
            if is_vaulted(arg):
                return get_vaulted_inner_type(arg)
        return annotation
    args = get_args(annotation)
    if args:
        return args[0]
    if hasattr(annotation, "__value__"):
        inner_args = get_args(annotation.__value__)
        if inner_args:
            return inner_args[0]
    return annotation


def get_detokenise_inner_type(annotation: object) -> object:
    """Extract the inner type wrapped by Detokenise[T], inspecting Union and Optional types."""
    origin = get_origin(annotation)
    if origin in (Union, types.UnionType):
        for arg in get_args(annotation):
            if is_detokenise(arg):
                return get_detokenise_inner_type(arg)
        return annotation
    args = get_args(annotation)
    if args:
        return args[0]
    if hasattr(annotation, "__value__"):
        inner_args = get_args(annotation.__value__)
        if inner_args:
            return inner_args[0]
    return annotation


__all__: list[str] = [
    "Detokenise",
    "DetokeniseMarker",
    "Vaulted",
    "VaultedMarker",
    "get_detokenise_inner_type",
    "get_vaulted_inner_type",
    "is_detokenise",
    "is_vaulted",
]
