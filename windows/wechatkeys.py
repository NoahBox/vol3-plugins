# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import dataclasses
import hashlib
import hmac
import logging
import os
import re
import struct
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class _DatabaseRecord:
    rel_path: str
    path: str
    size: int
    salt_hex: str
    page1: bytes


@dataclasses.dataclass
class _KeyHit:
    pid: int
    process_name: str
    offset: int
    match_type: str
    enc_key_hex: str
    candidate_salt_hex: Optional[str]
    count: int = 1


@dataclasses.dataclass(frozen=True)
class _OutputRow:
    pid: int
    process_name: str
    offset: int
    match_type: str
    source: str
    enc_key_hex: str
    candidate_salt_hex: Optional[str]
    db_salt_hex: Optional[str]
    databases: Optional[str]


class WeChatKeys(interfaces.plugins.PluginInterface):
    """Extracts WeChat SQLCipher raw keys from process memory."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    _TARGET_PROCESS_NAMES = {"weixin.exe", "wechat.exe"}
    _PAGE_SIZE = 4096
    _KEY_SIZE = 32
    _SALT_SIZE = 16
    _MAX_MATCH_SIZE = 256
    _HEX_PATTERN_RE = re.compile(rb"x'([0-9a-fA-F]{64,192})'")

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="regex_scanner",
                component=scanners.RegExScanner,
                version=(1, 0, 0),
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include (all other processes are excluded)",
                optional=True,
            ),
            requirements.StringRequirement(
                name="db-dir",
                description="Optional WeChat db_storage directory used to verify keys",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="include-unverified",
                description="Include memory candidates that do not validate against db-dir",
                default=False,
                optional=True,
            ),
        ]

    @classmethod
    def _verify_enc_key(cls, enc_key: bytes, db_page1: bytes) -> bool:
        salt = db_page1[: cls._SALT_SIZE]
        mac_salt = bytes(value ^ 0x3A for value in salt)
        mac_key = hashlib.pbkdf2_hmac(
            "sha512", enc_key, mac_salt, 2, dklen=cls._KEY_SIZE
        )
        hmac_data = db_page1[cls._SALT_SIZE : cls._PAGE_SIZE - 80 + 16]
        stored_hmac = db_page1[cls._PAGE_SIZE - 64 : cls._PAGE_SIZE]
        verifier = hmac.new(mac_key, hmac_data, hashlib.sha512)
        verifier.update(struct.pack("<I", 1))
        return verifier.digest() == stored_hmac

    @classmethod
    def _parse_candidate(cls, raw_hex: str) -> Tuple[str, Optional[str], str]:
        hex_length = len(raw_hex)
        enc_key_hex = raw_hex[:64].lower()

        if hex_length == 64:
            return enc_key_hex, None, "64hex"
        if hex_length == 96:
            return enc_key_hex, raw_hex[64:].lower(), "96hex"
        if hex_length > 96 and hex_length % 2 == 0:
            return enc_key_hex, raw_hex[-32:].lower(), "longhex"

        raise ValueError(f"Unsupported WeChat key candidate length: {hex_length}")

    @classmethod
    def _collect_databases(
        cls, db_dir: str
    ) -> Tuple[List[_DatabaseRecord], Dict[str, List[_DatabaseRecord]]]:
        db_dir = os.path.abspath(os.path.expanduser(db_dir))
        if not os.path.isdir(db_dir):
            raise ValueError(f"Database directory does not exist: {db_dir}")

        db_records: List[_DatabaseRecord] = []
        salt_to_records: Dict[str, List[_DatabaseRecord]] = {}

        for root, _dirs, files in os.walk(db_dir):
            for name in files:
                if not name.lower().endswith(".db"):
                    continue

                path = os.path.join(root, name)
                try:
                    size = os.path.getsize(path)
                    if size < cls._PAGE_SIZE:
                        continue

                    with open(path, "rb") as file_handle:
                        page1 = file_handle.read(cls._PAGE_SIZE)
                except OSError as excp:
                    vollog.debug(f"Unable to read database {path}: {excp}")
                    continue

                if len(page1) < cls._PAGE_SIZE or page1.startswith(b"SQLite format 3"):
                    continue

                rel_path = os.path.relpath(path, db_dir)
                salt_hex = page1[: cls._SALT_SIZE].hex()
                record = _DatabaseRecord(rel_path, path, size, salt_hex, page1)
                db_records.append(record)
                salt_to_records.setdefault(salt_hex, []).append(record)

        return db_records, salt_to_records

    @staticmethod
    def _hit_sort_key(hit: _KeyHit) -> Tuple[int, int, int, str]:
        return (-hit.count, hit.pid, hit.offset, hit.process_name.lower())

    @classmethod
    def _choose_source_hit(
        cls, hits_for_key: Iterable[_KeyHit], db_salt_hex: str
    ) -> Tuple[_KeyHit, str]:
        hits = sorted(hits_for_key, key=cls._hit_sort_key)

        for hit in hits:
            if hit.candidate_salt_hex == db_salt_hex:
                return hit, "direct"

        for hit in hits:
            if hit.candidate_salt_hex is None:
                return hit, "direct"

        return hits[0], "cross"

    @classmethod
    def _memory_row_from_hit(cls, hit: _KeyHit) -> _OutputRow:
        return _OutputRow(
            pid=hit.pid,
            process_name=hit.process_name,
            offset=hit.offset,
            match_type=hit.match_type,
            source="memory",
            enc_key_hex=hit.enc_key_hex,
            candidate_salt_hex=hit.candidate_salt_hex,
            db_salt_hex=None,
            databases=None,
        )

    def _list_target_processes(self) -> List[interfaces.objects.ObjectInterface]:
        pid_filter = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        def filter_func(proc: interfaces.objects.ObjectInterface) -> bool:
            process_name = utility.array_to_string(proc.ImageFileName).lower()
            return pid_filter(proc) or process_name not in self._TARGET_PROCESS_NAMES

        return list(
            pslist.PsList.list_processes(
                context=self.context,
                kernel_module_name=self.config["kernel"],
                filter_func=filter_func,
            )
        )

    def _collect_hits(
        self, procs: Iterable[interfaces.objects.ObjectInterface]
    ) -> List[_KeyHit]:
        hits: Dict[Tuple[int, str, str, str, str], _KeyHit] = {}

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)
            proc_id = int(proc.UniqueProcessId)

            try:
                proc_layer_name = proc.add_process_layer()
                vad_root = proc.get_vad_root()
            except exceptions.InvalidAddressException as excp:
                vollog.debug(
                    f"Process {proc_id}: invalid address {excp.invalid_address} in layer {excp.layer_name}"
                )
                continue

            if not proc_layer_name:
                continue

            proc_layer = self.context.layers[proc_layer_name]
            sections = []

            try:
                for vad in vad_root.traverse():
                    size = vad.get_size()
                    if size:
                        sections.append((vad.get_start(), size))
            except exceptions.InvalidAddressException as excp:
                vollog.debug(
                    f"Process {proc_id}: unable to enumerate VADs due to invalid address {excp.invalid_address}"
                )
                continue

            if not sections:
                continue

            try:
                for offset in proc_layer.scan(
                    context=self.context,
                    scanner=scanners.RegExScanner(self._HEX_PATTERN_RE.pattern),
                    sections=sections,
                    progress_callback=self._progress_callback,
                ):
                    match_data = proc_layer.read(offset, self._MAX_MATCH_SIZE, pad=True)
                    match = self._HEX_PATTERN_RE.match(match_data)
                    if not match:
                        continue

                    raw_hex = match.group(1).decode("ascii").lower()
                    try:
                        enc_key_hex, candidate_salt_hex, match_type = (
                            self._parse_candidate(raw_hex)
                        )
                    except ValueError:
                        continue

                    identity = (
                        proc_id,
                        process_name,
                        match_type,
                        enc_key_hex,
                        candidate_salt_hex or "",
                    )
                    if identity in hits:
                        hits[identity].count += 1
                        continue

                    hits[identity] = _KeyHit(
                        pid=proc_id,
                        process_name=process_name,
                        offset=offset,
                        match_type=match_type,
                        enc_key_hex=enc_key_hex,
                        candidate_salt_hex=candidate_salt_hex,
                    )
            except exceptions.InvalidAddressException as excp:
                vollog.debug(
                    f"Process {proc_id}: scan failed due to invalid address {excp.invalid_address} in layer {excp.layer_name}"
                )

        return sorted(hits.values(), key=self._hit_sort_key)

    def _build_rows(self) -> List[_OutputRow]:
        target_processes = self._list_target_processes()
        if not target_processes:
            vollog.warning(
                "No WeChat processes found. Use --pid to target a specific process if needed."
            )
            return []

        hits = self._collect_hits(target_processes)
        if not hits:
            vollog.warning("No WeChat SQLCipher key candidates found in process memory")
            return []

        db_dir = self.config.get("db-dir")
        if not db_dir:
            return [self._memory_row_from_hit(hit) for hit in hits]

        db_records, salt_to_records = self._collect_databases(db_dir)
        if not db_records:
            vollog.warning(f"No encrypted WeChat databases found under: {db_dir}")
            if self.config.get("include-unverified", False):
                return [self._memory_row_from_hit(hit) for hit in hits]
            return []

        hits_by_key: Dict[str, List[_KeyHit]] = {}
        for hit in hits:
            hits_by_key.setdefault(hit.enc_key_hex, []).append(hit)

        rows: List[_OutputRow] = []
        matched_keys = set()

        for enc_key_hex, hits_for_key in hits_by_key.items():
            enc_key = bytes.fromhex(enc_key_hex)
            matched_salts = []

            for salt_hex, salt_records in sorted(salt_to_records.items()):
                if not self._verify_enc_key(enc_key, salt_records[0].page1):
                    continue

                source_hit, source = self._choose_source_hit(hits_for_key, salt_hex)
                rows.append(
                    _OutputRow(
                        pid=source_hit.pid,
                        process_name=source_hit.process_name,
                        offset=source_hit.offset,
                        match_type=source_hit.match_type,
                        source=source,
                        enc_key_hex=enc_key_hex,
                        candidate_salt_hex=source_hit.candidate_salt_hex,
                        db_salt_hex=salt_hex,
                        databases=", ".join(
                            record.rel_path
                            for record in sorted(
                                salt_records, key=lambda record: record.rel_path
                            )
                        ),
                    )
                )
                matched_salts.append(salt_hex)

            if matched_salts:
                matched_keys.add(enc_key_hex)

        if self.config.get("include-unverified", False):
            for hit in hits:
                if hit.enc_key_hex not in matched_keys:
                    rows.append(self._memory_row_from_hit(hit))

        return rows

    def _generator(
        self,
    ) -> Iterator[
        Tuple[int, Tuple[int, str, format_hints.Hex, str, str, str, str, str, str]]
    ]:
        source_order = {"direct": 0, "cross": 1, "memory": 2}
        rows = sorted(
            self._build_rows(),
            key=lambda row: (
                source_order.get(row.source, 99),
                row.pid,
                row.offset,
                row.db_salt_hex or "",
                row.enc_key_hex,
            ),
        )

        for row in rows:
            yield (
                0,
                (
                    row.pid,
                    row.process_name,
                    format_hints.Hex(row.offset),
                    row.match_type,
                    row.source,
                    row.enc_key_hex,
                    row.candidate_salt_hex or renderers.NotApplicableValue(),
                    row.db_salt_hex or renderers.NotApplicableValue(),
                    row.databases or renderers.NotApplicableValue(),
                ),
            )

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Offset", format_hints.Hex),
                ("Match", str),
                ("Source", str),
                ("EncKey", str),
                ("CandidateSalt", str),
                ("DatabaseSalt", str),
                ("Databases", str),
            ],
            self._generator(),
        )
