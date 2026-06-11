# -*- coding: utf-8 -*-
from typing import Any, Iterable
from datetime import date, datetime

type DomainKeys = str | int | float | bool | date | datetime | Iterable[DomainKeys] | None
type DomainLeaf = tuple[str, str, DomainKeys]
type Domain = list[DomainLeaf]
