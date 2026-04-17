# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import contextlib
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
    pages: Tuple[bytes, ...]


@dataclasses.dataclass
class _KeyHit:
    pid: int
    process_name: str
    offset: int
    candidate: str
    count: int = 1


@dataclasses.dataclass(frozen=True)
class _OutputRow:
    pid: int
    process_name: str
    offset: int
    count: int
    length: int
    source: str
    candidate: str
    hmac_algorithm: Optional[str]
    databases: Optional[str]


class NTQQKey(interfaces.plugins.PluginInterface):
    """Extracts NTQQ SQLCipher passphrases from process memory."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    _TARGET_PROCESS_NAMES = {"qq.exe"}
    _TARGET_MODULE_NAME = "wrapper.node"
    _KEY_PATTERN_RE = re.compile(
        rb"([\x20-\x7e]{16}|[\x20-\x7e]{20}|[\x20-\x7e]{32})\x00"
    )

    _NTQQ_WRAPPER_SIZE = 1024
    _PAGE_SIZE = 4096
    _SALT_SIZE = 16
    _AES_KEY_SIZE = 32
    _IV_SIZE = 16
    _KDF_ITER = 4000
    _FAST_KDF_ITER = 2
    _MAX_MATCH_SIZE = 96
    _MAX_PAGES_TO_VERIFY = 3
    _WRAPPER_HINTS = (b"QQ_NT DB", b"SQLite header 3")
    _HMAC_ALGORITHMS = (
        ("HMAC_SHA1", hashlib.sha1),
        ("HMAC_SHA256", hashlib.sha256),
    )

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
                description="Optional NTQQ nt_db directory used to verify candidate keys",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="include-unverified",
                description="Include memory candidates that do not validate against db-dir",
                default=False,
                optional=True,
            ),
        ]

    @staticmethod
    def _align16(value: int) -> int:
        return (value + 15) & ~15

    @staticmethod
    def _is_printable_ascii(byte_value: int) -> bool:
        return 0x20 <= byte_value <= 0x7E

    @classmethod
    def _derive_hmac_key(cls, passphrase: bytes, salt: bytes) -> bytes:
        encryption_key = hashlib.pbkdf2_hmac(
            "sha512",
            passphrase,
            salt,
            cls._KDF_ITER,
            dklen=cls._AES_KEY_SIZE,
        )
        hmac_salt = bytes(value ^ 0x3A for value in salt)
        return hashlib.pbkdf2_hmac(
            "sha512",
            encryption_key,
            hmac_salt,
            cls._FAST_KDF_ITER,
            dklen=cls._AES_KEY_SIZE,
        )

    @classmethod
    def _verify_page_hmac(
        cls,
        page: bytes,
        page_number: int,
        hmac_key: bytes,
        digestmod,
    ) -> bool:
        if len(page) != cls._PAGE_SIZE:
            return False

        digest_len = digestmod().digest_size
        reserve_size = cls._align16(cls._IV_SIZE + digest_len)
        usable_size = cls._PAGE_SIZE - reserve_size

        if page_number == 1:
            data_offset = cls._SALT_SIZE
            data_size = usable_size - cls._SALT_SIZE
        else:
            data_offset = 0
            data_size = usable_size

        iv_offset = data_offset + data_size
        mac_offset = iv_offset + cls._IV_SIZE
        mac_end = mac_offset + digest_len
        if mac_end > cls._PAGE_SIZE:
            return False

        mac_input = page[data_offset : iv_offset + cls._IV_SIZE]
        stored_hmac = page[mac_offset:mac_end]
        page_bytes = struct.pack("<I", page_number)
        computed_hmac = hmac.new(hmac_key, mac_input + page_bytes, digestmod).digest()
        return hmac.compare_digest(computed_hmac, stored_hmac)

    @classmethod
    def _verify_candidate_pages(
        cls, passphrase: bytes, pages: Tuple[bytes, ...]
    ) -> Optional[str]:
        if not pages or len(pages[0]) != cls._PAGE_SIZE:
            return None

        salt = pages[0][: cls._SALT_SIZE]
        hmac_key = cls._derive_hmac_key(passphrase, salt)

        for algorithm_name, digestmod in cls._HMAC_ALGORITHMS:
            if all(
                cls._verify_page_hmac(page, page_number, hmac_key, digestmod)
                for page_number, page in enumerate(pages, start=1)
            ):
                return algorithm_name

        return None

    @classmethod
    def _looks_like_ntqq_database(cls, header: bytes, page1: bytes) -> bool:
        if len(page1) != cls._PAGE_SIZE:
            return False
        if page1.startswith(b"SQLite format 3\x00"):
            return False
        if any(wrapper_hint in header for wrapper_hint in cls._WRAPPER_HINTS):
            return True
        return True

    @classmethod
    def _collect_databases(cls, db_dir: str) -> List[_DatabaseRecord]:
        db_dir = os.path.abspath(os.path.expanduser(db_dir))
        if not os.path.isdir(db_dir):
            raise ValueError(f"Database directory does not exist: {db_dir}")

        db_records: List[_DatabaseRecord] = []

        for root, _dirs, files in os.walk(db_dir):
            for name in files:
                if not name.lower().endswith(".db"):
                    continue

                path = os.path.join(root, name)
                try:
                    size = os.path.getsize(path)
                    if size < cls._NTQQ_WRAPPER_SIZE + cls._PAGE_SIZE:
                        continue

                    page_count = min(
                        cls._MAX_PAGES_TO_VERIFY,
                        (size - cls._NTQQ_WRAPPER_SIZE) // cls._PAGE_SIZE,
                    )
                    if page_count <= 0:
                        continue

                    with open(path, "rb") as file_handle:
                        header = file_handle.read(cls._NTQQ_WRAPPER_SIZE)
                        pages = tuple(
                            file_handle.read(cls._PAGE_SIZE) for _ in range(page_count)
                        )
                except OSError as excp:
                    vollog.debug(f"Unable to read NTQQ database {path}: {excp}")
                    continue

                if not pages or not cls._looks_like_ntqq_database(header, pages[0]):
                    continue

                rel_path = os.path.relpath(path, db_dir)
                db_records.append(_DatabaseRecord(rel_path, path, size, pages))

        return sorted(db_records, key=lambda record: record.rel_path)

    @staticmethod
    def _hit_sort_key(hit: _KeyHit) -> Tuple[int, int, int, str]:
        return (-hit.count, hit.pid, hit.offset, hit.process_name.lower())

    @classmethod
    def _choose_source_hit(cls, hits_for_candidate: Iterable[_KeyHit]) -> _KeyHit:
        return sorted(hits_for_candidate, key=cls._hit_sort_key)[0]

    @staticmethod
    def _memory_row_from_hit(hit: _KeyHit) -> _OutputRow:
        return _OutputRow(
            pid=hit.pid,
            process_name=hit.process_name,
            offset=hit.offset,
            count=hit.count,
            length=len(hit.candidate),
            source="memory",
            candidate=hit.candidate,
            hmac_algorithm=None,
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

    def _collect_scan_sections(
        self, proc: interfaces.objects.ObjectInterface
    ) -> Tuple[List[Tuple[int, int]], bool, bool]:
        sections: List[Tuple[int, int]] = []
        has_wrapper_node = False
        saw_mapped_file = False

        for vad in proc.get_vad_root().traverse():
            size = vad.get_size()
            if not size:
                continue

            with contextlib.suppress(
                AttributeError, exceptions.InvalidAddressException
            ):
                file_name = vad.get_file_name()
                if isinstance(file_name, str):
                    saw_mapped_file = True
                    if file_name.lower().endswith(self._TARGET_MODULE_NAME):
                        has_wrapper_node = True

            is_private = True
            with contextlib.suppress(AttributeError):
                is_private = bool(vad.get_private_memory())

            if is_private:
                sections.append((vad.get_start(), size))

        return sections, has_wrapper_node, saw_mapped_file

    def _collect_hits(
        self, procs: Iterable[interfaces.objects.ObjectInterface]
    ) -> List[_KeyHit]:
        hits: Dict[Tuple[int, str], _KeyHit] = {}
        scanner = scanners.RegExScanner(self._KEY_PATTERN_RE.pattern)

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)
            proc_id = int(proc.UniqueProcessId)

            try:
                proc_layer_name = proc.add_process_layer()
                sections, has_wrapper_node, saw_mapped_file = (
                    self._collect_scan_sections(proc)
                )
            except exceptions.InvalidAddressException as excp:
                vollog.debug(
                    f"Process {proc_id}: invalid address {excp.invalid_address} in layer {excp.layer_name}"
                )
                continue

            if not proc_layer_name or not sections:
                continue

            if saw_mapped_file and not has_wrapper_node:
                vollog.debug(
                    f"Process {proc_id} ({process_name}) does not appear to map wrapper.node; skipping"
                )
                continue

            proc_layer = self.context.layers[proc_layer_name]

            for section_start, section_size in sections:
                try:
                    for offset in proc_layer.scan(
                        context=self.context,
                        scanner=scanner,
                        sections=[(section_start, section_size)],
                        progress_callback=self._progress_callback,
                    ):
                        match_data = proc_layer.read(
                            offset, self._MAX_MATCH_SIZE, pad=True
                        )
                        match = self._KEY_PATTERN_RE.match(match_data)
                        if not match:
                            continue

                        if offset > section_start:
                            prefix = proc_layer.read(offset - 1, 1, pad=True)
                            if prefix and self._is_printable_ascii(prefix[0]):
                                continue

                        candidate = match.group(1).decode("ascii", errors="strict")
                        identity = (proc_id, candidate)
                        if identity in hits:
                            hits[identity].count += 1
                            continue

                        hits[identity] = _KeyHit(
                            pid=proc_id,
                            process_name=process_name,
                            offset=offset,
                            candidate=candidate,
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
                "No QQ.exe processes found. Use --pid to target a specific process if needed."
            )
            return []

        hits = self._collect_hits(target_processes)
        if not hits:
            vollog.warning(
                "No NTQQ key candidates found in QQ.exe private memory sections"
            )
            return []

        db_dir = self.config.get("db-dir")
        if not db_dir:
            return [self._memory_row_from_hit(hit) for hit in hits]

        db_records = self._collect_databases(db_dir)
        if not db_records:
            vollog.warning(f"No NTQQ encrypted databases found under: {db_dir}")
            if self.config.get("include-unverified", False):
                return [self._memory_row_from_hit(hit) for hit in hits]
            return []

        hits_by_candidate: Dict[str, List[_KeyHit]] = {}
        for hit in hits:
            hits_by_candidate.setdefault(hit.candidate, []).append(hit)

        rows: List[_OutputRow] = []
        matched_candidates = set()

        for candidate, hits_for_candidate in hits_by_candidate.items():
            source_hit = self._choose_source_hit(hits_for_candidate)
            verified_by_algorithm: Dict[str, List[str]] = {}
            candidate_bytes = candidate.encode("ascii")

            for record in db_records:
                algorithm = self._verify_candidate_pages(candidate_bytes, record.pages)
                if not algorithm:
                    continue

                verified_by_algorithm.setdefault(algorithm, []).append(record.rel_path)

            if verified_by_algorithm:
                matched_candidates.add(candidate)
                for algorithm, database_paths in sorted(verified_by_algorithm.items()):
                    rows.append(
                        _OutputRow(
                            pid=source_hit.pid,
                            process_name=source_hit.process_name,
                            offset=source_hit.offset,
                            count=source_hit.count,
                            length=len(candidate),
                            source="verified",
                            candidate=candidate,
                            hmac_algorithm=algorithm,
                            databases=", ".join(sorted(database_paths)),
                        )
                    )

        if self.config.get("include-unverified", False):
            for hit in hits:
                if hit.candidate not in matched_candidates:
                    rows.append(self._memory_row_from_hit(hit))

        return rows

    def _generator(
        self,
    ) -> Iterator[
        Tuple[int, Tuple[int, str, format_hints.Hex, int, int, str, str, str, str]]
    ]:
        source_order = {"verified": 0, "memory": 1}
        rows = sorted(
            self._build_rows(),
            key=lambda row: (
                source_order.get(row.source, 99),
                row.pid,
                row.offset,
                row.length,
                row.candidate,
            ),
        )

        for row in rows:
            yield (
                0,
                (
                    row.pid,
                    row.process_name,
                    format_hints.Hex(row.offset),
                    row.count,
                    row.length,
                    row.source,
                    row.candidate,
                    row.hmac_algorithm or renderers.NotApplicableValue(),
                    row.databases or renderers.NotApplicableValue(),
                ),
            )

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Offset", format_hints.Hex),
                ("Count", int),
                ("Length", int),
                ("Source", str),
                ("Candidate", str),
                ("HMAC", str),
                ("Databases", str),
            ],
            self._generator(),
        )
