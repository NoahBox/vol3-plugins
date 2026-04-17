import logging
import os
import re
from typing import Iterator, List, Set, Tuple

from volatility3.framework import constants, exceptions, interfaces, renderers, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.framework.objects import utility
from volatility3.framework.symbols import intermed
from volatility3.plugins.windows import info, poolscanner, pslist


vollog = logging.getLogger(__name__)

Row = Tuple[str, str, str, str, str, str, str]


class Bitlocker(interfaces.plugins.PluginInterface):
    """Recovers BitLocker FVEKs, VMKs, and plaintext recovery passwords from memory."""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    BLMode = {
        "00": "AES 128-bit with Diffuser",
        "01": "AES 256-bit with Diffuser",
        "02": "AES 128-bit",
        "03": "AES 256-bit",
        "10": "AES 128-bit (Win 8+)",
        "20": "AES 256-bit (Win 8+)",
        "30": "AES-XTS 128 bit (Win 10+)",
        "40": "AES-XTS 256 bit (Win 10+)",
    }

    PoolSize = {
        "Cngb128": 632,
        "Cngb256": 672,
        "None128": 1230,
        "None256": 1450,
    }

    _RECOVERY_PASSWORD_ASCII_RE = re.compile(rb"(?:[0-9]{6}-){7}[0-9]{6}")
    _RECOVERY_PASSWORD_UTF16LE_RE = re.compile(
        rb"(?:(?:[0-9]\x00){6}-\x00){7}(?:[0-9]\x00){6}"
    )
    _RECOVERY_PASSWORD_LENGTH = 55
    _RECOVERY_PASSWORD_UTF16LE_LENGTH = 110

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.VersionRequirement(
                name="info", component=info.Info, version=(2, 0, 0)
            ),
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="poolscanner", component=poolscanner.PoolScanner, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="regex_scanner",
                component=scanners.RegExScanner,
                version=(1, 0, 0),
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter recovery-password searches to specific process IDs",
                element_type=int,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="scan-recovery-passwords",
                description="Scan process memory for plaintext 48-digit BitLocker recovery passwords",
                default=False,
                optional=True,
            ),
        ]

    @staticmethod
    def create_bitlocker_table(
        context: interfaces.context.ContextInterface,
        symbol_table: str,
        config_path: str,
        symbol_filename: str,
    ) -> str:
        return intermed.IntermediateSymbolTable.create(
            context, config_path, os.path.join("windows", "bitlocker"), symbol_filename
        )

    @staticmethod
    def create_bitlockervmk_table(
        context: interfaces.context.ContextInterface,
        symbol_table: str,
        config_path: str,
    ) -> str:
        return intermed.IntermediateSymbolTable.create(
            context, config_path, os.path.join("windows", "bitlockervmk"), "x64"
        )

    def get_os_version(self, kernel_module_name: str) -> Tuple[int, int, int]:
        kuser = info.Info.get_kuser_structure(self.context, kernel_module_name)
        nt_major_version = int(kuser.NtMajorVersion)
        nt_minor_version = int(kuser.NtMinorVersion)
        vers = info.Info.get_version_structure(self.context, kernel_module_name)
        build = vers.MinorVersion
        return nt_major_version, nt_minor_version, build

    @staticmethod
    def _format_offset(offset: int) -> str:
        return f"0x{offset:x}"

    @staticmethod
    def _format_extracted_key(fvek: bytes, tweak: bytes = b"") -> str:
        fvek_hex = fvek.hex()
        if tweak:
            return f"{fvek_hex}:{tweak.hex()}"
        return fvek_hex

    @staticmethod
    def _build_dislocker_hex(algorithm: int, raw_key: bytes) -> str:
        return algorithm.to_bytes(2, byteorder="little").hex() + raw_key.hex()

    @staticmethod
    def _build_row(
        location: str,
        material_type: str,
        cipher: str,
        key: str,
        direct_use: str,
        tool: str,
        context: str,
    ) -> Row:
        return (location, material_type, cipher, key, direct_use, tool, context)

    def _read_member_bytes(
        self,
        memory_object: interfaces.objects.ObjectInterface,
        member_name: str,
        length: int,
    ) -> bytes:
        relative_offset = self.context.symbol_space.get_type(
            memory_object.vol.type_name
        ).relative_child_offset(member_name)
        return self.context.layers[memory_object.vol.layer_name].read(
            memory_object.vol.offset + relative_offset, length, pad=True
        )

    def _build_fvek_row(
        self,
        location: str,
        context: str,
        cipher: str,
        fvek: bytes,
        tweak: bytes,
        algorithm: int,
        raw_key: bytes,
    ) -> Row:
        return self._build_row(
            location=location,
            material_type="FVEK",
            cipher=cipher,
            key=self._format_extracted_key(fvek, tweak),
            direct_use=self._build_dislocker_hex(algorithm, raw_key),
            tool="dislocker -k (hex->bin)",
            context=context,
        )

    @staticmethod
    def _recovery_block_is_valid(block: str) -> bool:
        if len(block) != 6 or not block.isdigit():
            return False

        value = int(block)
        if value % 11 != 0 or value >= 720896:
            return False

        check_digit = (
            int(block[0])
            - int(block[1])
            + int(block[2])
            - int(block[3])
            + int(block[4])
        ) % 11

        return check_digit == int(block[5])

    @classmethod
    def _is_valid_recovery_password(cls, candidate: str) -> bool:
        blocks = candidate.split("-")
        return len(blocks) == 8 and all(
            cls._recovery_block_is_valid(block) for block in blocks
        )

    def _processes_to_scan(self):
        pid_list = self.config.get("pid", None)
        if pid_list:
            filter_func = pslist.PsList.create_pid_filter(pid_list)
        else:
            filter_func = pslist.PsList.create_active_process_filter()

        return pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            filter_func=filter_func,
        )

    def _scan_recovery_pattern(
        self,
        proc_layer,
        sections,
        process_name: str,
        proc_id: int,
        pattern: bytes,
        compiled_pattern: re.Pattern,
        read_size: int,
        encoding: str,
    ) -> Iterator[Row]:
        try:
            for offset in proc_layer.scan(
                context=self.context,
                scanner=scanners.RegExScanner(pattern),
                sections=sections,
                progress_callback=self._progress_callback,
            ):
                try:
                    match_data = proc_layer.read(offset, read_size, pad=True)
                except exceptions.InvalidAddressException:
                    continue

                match = compiled_pattern.match(match_data)
                if not match:
                    continue

                try:
                    candidate = match.group(0).decode(encoding)
                except UnicodeDecodeError:
                    continue

                if not self._is_valid_recovery_password(candidate):
                    continue

                yield self._build_row(
                    location=self._format_offset(offset),
                    material_type="RecoveryPassword",
                    cipher="",
                    key=candidate,
                    direct_use=candidate,
                    tool="dislocker -p / bdemount -r",
                    context=f"{encoding} in process {process_name} ({proc_id})",
                )
        except exceptions.InvalidAddressException:
            return

    def _scan_recovery_passwords(self) -> Iterator[Row]:
        for proc in self._processes_to_scan():
            process_name = utility.array_to_string(proc.ImageFileName)
            proc_id = int(proc.UniqueProcessId)

            try:
                proc_layer_name = proc.add_process_layer()
                vad_root = proc.get_vad_root()
            except exceptions.InvalidAddressException as excp:
                vollog.debug(
                    f"Unable to prepare process {proc_id} ({process_name}) for recovery-password scanning: {excp}"
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
                    f"Unable to enumerate VADs for process {proc_id} ({process_name}): {excp}"
                )
                continue

            if not sections:
                continue

            yield from self._scan_recovery_pattern(
                proc_layer=proc_layer,
                sections=sections,
                process_name=process_name,
                proc_id=proc_id,
                pattern=self._RECOVERY_PASSWORD_ASCII_RE.pattern,
                compiled_pattern=self._RECOVERY_PASSWORD_ASCII_RE,
                read_size=self._RECOVERY_PASSWORD_LENGTH,
                encoding="ascii",
            )
            yield from self._scan_recovery_pattern(
                proc_layer=proc_layer,
                sections=sections,
                process_name=process_name,
                proc_id=proc_id,
                pattern=self._RECOVERY_PASSWORD_UTF16LE_RE.pattern,
                compiled_pattern=self._RECOVERY_PASSWORD_UTF16LE_RE,
                read_size=self._RECOVERY_PASSWORD_UTF16LE_LENGTH,
                encoding="utf-16le",
            )

    def _scan_vmks(self) -> Iterator[Row]:
        kernel = self.context.modules[self.config["kernel"]]
        if not symbols.symbol_table_is_64bit(self.context, kernel.symbol_table_name):
            return

        symbol_table_name = self.create_bitlockervmk_table(
            self.context, kernel.symbol_table_name, self.config_path
        )
        constraint = poolscanner.PoolConstraint(
            tag=b"FVEl",
            size=(64, 64),
            page_type=poolscanner.PoolType.NONPAGED | poolscanner.PoolType.PAGED,
            type_name=symbol_table_name + constants.BANG + "vmk_pool",
        )

        for (
            _constraint,
            vmk_pool,
            _header,
        ) in poolscanner.PoolScanner.generate_pool_scan(
            self.context, self.config["kernel"], [constraint]
        ):
            vmk = bytes(vmk_pool.vmk)
            yield self._build_row(
                location=self._format_offset(vmk_pool.vol.offset),
                material_type="VMK",
                cipher="",
                key=vmk.hex(),
                direct_use=vmk.hex(),
                tool="dislocker -K (hex->bin)",
                context="kernel pool FVEl",
            )

    def _scan_fveks_win10_x64(self) -> Iterator[Row]:
        kernel = self.context.modules[self.config["kernel"]]
        symbol_table_name = self.create_bitlocker_table(
            self.context,
            kernel.symbol_table_name,
            self.config_path,
            "win-6-4-10241-x64",
        )
        constraint = poolscanner.PoolConstraint(
            tag=b"None",
            size=(self.PoolSize["None128"], self.PoolSize["None256"]),
            page_type=poolscanner.PoolType.NONPAGED,
            type_name=symbol_table_name + constants.BANG + "fvek_pool_x64",
        )

        for (
            _constraint,
            fvek_pool,
            _header,
        ) in poolscanner.PoolScanner.generate_pool_scan(
            self.context, self.config["kernel"], [constraint]
        ):
            f1 = self._read_member_bytes(fvek_pool, "fvek10", 64)
            f2 = self._read_member_bytes(fvek_pool, "fvek20", 64)
            f3 = self._read_member_bytes(fvek_pool, "fvek30", 64)
            location = self._format_offset(fvek_pool.vol.offset)
            context = "kernel pool None"

            if f1[0:16] == f2[0:16]:
                if f1[16:32] == f2[16:32]:
                    yield self._build_fvek_row(
                        location,
                        context,
                        self.BLMode["40"],
                        f1[0:32],
                        b"",
                        0x8005,
                        f1,
                    )
                else:
                    yield self._build_fvek_row(
                        location,
                        context,
                        self.BLMode["30"],
                        f1[0:16],
                        b"",
                        0x8004,
                        f1,
                    )

            if f1[0:16] == f3[0:16]:
                if f1[16:32] == f3[16:32]:
                    yield self._build_fvek_row(
                        location,
                        context,
                        self.BLMode["20"],
                        f1[0:32],
                        b"",
                        0x8003,
                        f1,
                    )
                else:
                    yield self._build_fvek_row(
                        location,
                        context,
                        self.BLMode["10"],
                        f1[0:16],
                        b"",
                        0x8002,
                        f1,
                    )

    def _scan_fveks_win8(self) -> Iterator[Row]:
        kernel = self.context.modules[self.config["kernel"]]
        pool_symbol_name = (
            "fvek_pool_x64"
            if symbols.symbol_table_is_64bit(self.context, kernel.symbol_table_name)
            else "fvek_pool_x86"
        )
        symbol_table_name = self.create_bitlocker_table(
            self.context, kernel.symbol_table_name, self.config_path, "win-6-2"
        )
        constraint = poolscanner.PoolConstraint(
            tag=b"Cngb",
            size=(self.PoolSize["Cngb128"], self.PoolSize["Cngb256"]),
            page_type=poolscanner.PoolType.NONPAGED,
            type_name=symbol_table_name + constants.BANG + pool_symbol_name,
        )

        for (
            _constraint,
            fvek_pool,
            _header,
        ) in poolscanner.PoolScanner.generate_pool_scan(
            self.context, self.config["kernel"], [constraint]
        ):
            f1 = bytes(fvek_pool.fvek10)
            f2 = bytes(fvek_pool.fvek20)
            location = self._format_offset(fvek_pool.vol.offset)
            context = "kernel pool Cngb"

            if f1[0:16] != f2[0:16]:
                continue

            if f1[16:32] == f2[16:32]:
                yield self._build_fvek_row(
                    location,
                    context,
                    self.BLMode["20"],
                    f1[0:32],
                    b"",
                    0x8003,
                    f1,
                )
            else:
                yield self._build_fvek_row(
                    location,
                    context,
                    self.BLMode["10"],
                    f1[0:16],
                    b"",
                    0x8002,
                    f1,
                )

    def _scan_fveks_vista(self) -> Iterator[Row]:
        kernel = self.context.modules[self.config["kernel"]]
        symbol_table_name = self.create_bitlocker_table(
            self.context, kernel.symbol_table_name, self.config_path, "win-6-0"
        )

        constraints = []
        if symbols.symbol_table_is_64bit(self.context, kernel.symbol_table_name):
            constraints.append(
                poolscanner.PoolConstraint(
                    b"FVEc",
                    size=(1008, 1008),
                    page_type=poolscanner.PoolType.NONPAGED
                    | poolscanner.PoolType.PAGED,
                    type_name=symbol_table_name
                    + constants.BANG
                    + "fvek_pool_X64_aes_diff",
                )
            )
            constraints.append(
                poolscanner.PoolConstraint(
                    b"FVEc",
                    size=(528, 528),
                    page_type=poolscanner.PoolType.NONPAGED
                    | poolscanner.PoolType.PAGED,
                    type_name=symbol_table_name
                    + constants.BANG
                    + "fvek_pool_X64_aes_only",
                )
            )
        else:
            constraints.append(
                poolscanner.PoolConstraint(
                    b"FVEc",
                    size=(976, 976),
                    page_type=poolscanner.PoolType.NONPAGED
                    | poolscanner.PoolType.PAGED,
                    type_name=symbol_table_name
                    + constants.BANG
                    + "fvek_pool_X86_aes_diff",
                )
            )
            constraints.append(
                poolscanner.PoolConstraint(
                    b"FVEc",
                    size=(504, 504),
                    page_type=poolscanner.PoolType.NONPAGED
                    | poolscanner.PoolType.PAGED,
                    type_name=symbol_table_name
                    + constants.BANG
                    + "fvek_pool_X86_aes_only",
                )
            )

        for constraint in constraints:
            for (
                _constraint,
                fvek_pool,
                _header,
            ) in poolscanner.PoolScanner.generate_pool_scan(
                self.context, self.config["kernel"], [constraint]
            ):
                cid = bytes(fvek_pool.cid)
                if cid[1] != 0x80 or cid[0] > 0x03:
                    continue

                f1 = bytes(fvek_pool.fvek10)
                f2 = bytes(fvek_pool.fvek20)
                mode = f"{cid[0]:02x}"
                length = 16 if cid[0] in (0x00, 0x02) else 32
                tweak = f2[0:length] if mode in ("00", "01") else b""
                yield self._build_fvek_row(
                    location=self._format_offset(fvek_pool.vol.offset),
                    context="kernel pool FVEc",
                    cipher=self.BLMode[mode],
                    fvek=f1[0:length],
                    tweak=tweak,
                    algorithm=int.from_bytes(cid, byteorder="little"),
                    raw_key=f1 + f2,
                )

    def _scan_fveks(self) -> Iterator[Row]:
        kernel = self.context.modules[self.config["kernel"]]
        version = self.get_os_version(self.config["kernel"])

        if version >= (10, 0, 10241) and symbols.symbol_table_is_64bit(
            self.context, kernel.symbol_table_name
        ):
            yield from self._scan_fveks_win10_x64()
        elif version >= (6, 2, 0):
            if version >= (10, 0, 10241):
                vollog.warning(
                    "Falling back to the Windows 8+ BitLocker pool layout for a non-x64 Windows 10+ kernel"
                )
            yield from self._scan_fveks_win8()
        elif version >= (6, 0, 0):
            yield from self._scan_fveks_vista()
        else:
            vollog.warning(
                "BitLocker key scanning is only supported on Windows Vista and later"
            )

    def _generator(self) -> Iterator[Tuple[int, Row]]:
        seen: Set[Tuple[str, str]] = set()

        for row in self._scan_fveks():
            key = (row[1], row[4])
            if key in seen:
                continue
            seen.add(key)
            yield 0, row

        for row in self._scan_vmks():
            key = (row[1], row[4])
            if key in seen:
                continue
            seen.add(key)
            yield 0, row

        if self.config.get("scan-recovery-passwords", False):
            for row in self._scan_recovery_passwords():
                key = (row[1], row[4])
                if key in seen:
                    continue
                seen.add(key)
                yield 0, row

    def run(self):
        return renderers.TreeGrid(
            [
                ("Location", str),
                ("Type", str),
                ("Cipher", str),
                ("Key", str),
                ("DirectUse", str),
                ("Tool", str),
                ("Context", str),
            ],
            self._generator(),
        )
