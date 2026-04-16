import os
from typing import List, Tuple, Iterator

from volatility3.framework import interfaces, renderers, constants, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.symbols import intermed
from volatility3.plugins.windows import info
from volatility3.plugins.windows import poolscanner


class Bitlocker(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    BLMode = {
        '00': 'AES 128-bit with Diffuser',
        '01': 'AES 256-bit with Diffuser',
        '02': 'AES 128-bit',
        '03': 'AES 256-bit',
        '10': 'AES 128-bit (Win 8+)',
        '20': 'AES 256-bit (Win 8+)',
        '30': 'AES-XTS 128 bit (Win 10+)',
        '40': 'AES-XTS 256 bit (Win 10+)',
    }

    PoolSize = {
        'Fvec128': 508,
        'Fvec256': 1008,
        'Cngb128': 632,
        'Cngb256': 672,
        'None128': 1230,
        'None256': 1450,
    }

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.VersionRequirement(name='info', component=info.Info, version=(1, 0, 0)),
            requirements.ModuleRequirement(name='kernel', description='Windows kernel',
                                           architectures=["Intel32", "Intel64"]),
            requirements.VersionRequirement(name='poolscanner',
                                            component=poolscanner.PoolScanner,
                                            version=(1, 0, 0)),
        ]

    @staticmethod
    def create_bitlocker_table(context: interfaces.context.ContextInterface, symbol_table: str,
                               config_path: str, symbol_filename: str) -> str:
        return intermed.IntermediateSymbolTable.create(context,
                                                       config_path,
                                                       os.path.join("windows", "bitlocker"),
                                                       symbol_filename)

    def get_os_version(self, kernel) -> Tuple[int, int, int]:
        """Returns the complete OS version (MAJ,MIN,BUILD)

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols

        Returns:
            A tuple with (MAJ,MIN,BUILD)
        """
        context = self.context
        layer_name = kernel.layer_name
        symbol_table = kernel.symbol_table_name
        kuser = info.Info.get_kuser_structure(context, layer_name, symbol_table)
        nt_major_version = int(kuser.NtMajorVersion)
        nt_minor_version = int(kuser.NtMinorVersion)
        vers = info.Info.get_version_structure(context, layer_name, symbol_table)
        build = vers.MinorVersion
        return nt_major_version, nt_minor_version, build

    def _generator(self) -> Iterator[Tuple[int, Tuple[str, str, str, str]]]:
        kernel = self.context.modules[self.config['kernel']]
        version = self.get_os_version(kernel)
        if version >= (10, 0, 10241):
            return self._generator_6_4_10241_x64()
        elif version > (6, 2):
            return self._generator_6_2()
        elif version > (6, 0):
            return self._generator_6_0()

    def _generator_6_4_10241_x64(self) -> Iterator[Tuple[int, Tuple[str, str, str, str]]]:
        tag = b"None"
        pool_size = (Bitlocker.PoolSize['None128'], Bitlocker.PoolSize['None256'])
        kernel = self.context.modules[self.config['kernel']]
        symbol_filename = "win-6-4-10241-x64"
        symbol_table_name = self.create_bitlocker_table(self.context, kernel.symbol_table_name,
                                                        self.config_path, symbol_filename)
        constraint = poolscanner.PoolConstraint(tag,
                                                size=pool_size,
                                                page_type=poolscanner.PoolType.NONPAGED | poolscanner.PoolType.PAGED,
                                                type_name=symbol_table_name + constants.BANG + 'fvek_pool_x64')
        for result in poolscanner.PoolScanner.generate_pool_scan(self.context, kernel.layer_name,
                                                                 kernel.symbol_table_name, [constraint]):
            _constraint, fvek_pool, _header = result
            f1 = fvek_pool.fvek10
            f2 = fvek_pool.fvek20
            f3 = fvek_pool.fvek30
            if f1[0:16] == f2[0:16]:
                if f1[16:32] == f2[16:32]:
                    yield 0, (Bitlocker.BLMode['40'], bytes(f1[0:32]).hex(), "")
                else:
                    yield 0, (Bitlocker.BLMode['30'], bytes(f1[0:16]).hex(), "")
            if f1[0:16] == f3[0:16]:  # Should be AES-CBC
                if f1[16:32] == f3[16:32]:
                    yield 0, (Bitlocker.BLMode['20'], bytes(f1[0:32]).hex(), "")
                else:
                    yield 0, (Bitlocker.BLMode['10'], bytes(f1[0:16]).hex(), "")

    def _generator_6_2(self) -> Iterator[Tuple[int, Tuple[str, str, str, str]]]:
        tag = b"Cngb"
        pool_size = (Bitlocker.PoolSize['Cngb128'], Bitlocker.PoolSize['Cngb256'])
        kernel = self.context.modules[self.config['kernel']]

        is_64bit = symbols.symbol_table_is_64bit(self.context, kernel.symbol_table_name)
        if is_64bit:
            pool_symbol_name = "fvek_pool_x64"
        else:
            pool_symbol_name = "fvek_pool_x86"

        symbol_filename = "win-6-2"
        symbol_table_name = self.create_bitlocker_table(self.context, kernel.symbol_table_name,
                                                        self.config_path, symbol_filename)
        constraint = poolscanner.PoolConstraint(tag,
                                                size=pool_size,
                                                page_type=poolscanner.PoolType.NONPAGED | poolscanner.PoolType.PAGED,
                                                type_name=symbol_table_name + constants.BANG + pool_symbol_name)

        for result in poolscanner.PoolScanner.generate_pool_scan(self.context, kernel.layer_name,
                                                                 kernel.symbol_table_name, [constraint]):
            _constraint, fvek_pool, _header = result
            f1 = fvek_pool.fvek10
            f2 = fvek_pool.fvek20
            if f1[0:16] == f2[0:16]:
                if f1[16:32] == f2[16:32]:
                    yield 0, (Bitlocker.BLMode['20'], bytes(f1[0:32]).hex(), "")
                else:
                    yield 0, (Bitlocker.BLMode['10'], bytes(f1[0:16]).hex(), "")

    def _generator_6_0(self) -> Iterator[Tuple[int, Tuple[str, str, str, str]]]:
        kernel = self.context.modules[self.config['kernel']]

        symbol_filename = "win-6-0"
        symbol_table_name = self.create_bitlocker_table(self.context, kernel.symbol_table_name,
                                                        self.config_path, symbol_filename)

        pool_size_x86_aes_diff = 976
        pool_size_x86_aes_only = 504
        pool_size_x64_aes_diff = 1008
        pool_size_x64_aes_only = 528
        tag = b"FVEc"
        constraints = []
        if symbols.symbol_table_is_64bit(self.context, kernel.symbol_table_name):
            constraints.append(poolscanner.PoolConstraint(tag, size=(pool_size_x64_aes_diff, pool_size_x64_aes_diff),
                                                  page_type=poolscanner.PoolType.NONPAGED | poolscanner.PoolType.PAGED,
                                                  type_name=symbol_table_name + constants.BANG + "fvek_pool_X64_aes_diff"))
            constraints.append(poolscanner.PoolConstraint(tag, size=(pool_size_x64_aes_only, pool_size_x64_aes_only),
                                                  page_type=poolscanner.PoolType.NONPAGED | poolscanner.PoolType.PAGED,
                                                  type_name=symbol_table_name + constants.BANG + "fvek_pool_X64_aes_only"))
        else:
            constraints.append(poolscanner.PoolConstraint(tag, size=(pool_size_x86_aes_diff, pool_size_x86_aes_diff),
                                                    page_type=poolscanner.PoolType.NONPAGED | poolscanner.PoolType.PAGED,
                                                    type_name=symbol_table_name + constants.BANG + "fvek_pool_X86_aes_diff"))
            constraints.append(poolscanner.PoolConstraint(tag, size=(pool_size_x86_aes_only, pool_size_x86_aes_only),
                                                  page_type=poolscanner.PoolType.NONPAGED | poolscanner.PoolType.PAGED,
                                                  type_name=symbol_table_name + constants.BANG + "fvek_pool_X86_aes_only"))
        for constant in constraints:
            for result in poolscanner.PoolScanner.generate_pool_scan(self.context, kernel.layer_name,
                                                                        kernel.symbol_table_name, [constant]):
                _constraint, fvek_pool, header = result
                cid = fvek_pool.cid
                f1 = fvek_pool.fvek10
                f2 = fvek_pool.fvek20
                if int(cid[1]) == 0x80 and int(cid[0]) <= 0x03:
                    if int(cid[0]) == 0x02 or int(cid[0]) == 0x00:
                        length = 16
                    else:
                        length = 32
                    mode = '{:02x}'.format(int(cid[0]))
                    if mode != "02" and mode != "03":
                        tweak = f2[0:length]
                    else:
                        tweak = b""
                    fvek = f1[0:length]
                    yield 0, (Bitlocker.BLMode[mode], bytes(fvek).hex(), bytes(tweak).hex())

    def run(self):
        return renderers.TreeGrid([
            ('Cipher', str),
            ("Fvek", str),
            ("TweakKey", str),
        ], self._generator())
