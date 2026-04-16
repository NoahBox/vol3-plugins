import os
from typing import List, Tuple, Iterator

from volatility3.framework import interfaces, renderers, constants, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.symbols import intermed
from volatility3.plugins.windows import info
from volatility3.plugins.windows import poolscanner


class BitlockerVmk(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

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
                                                       os.path.join("windows", "bitlockervmk"),
                                                       symbol_filename)

    def _generator(self) -> Iterator[Tuple[int, Tuple[str]]]:
        tag = b"FVEl"
        pool_size = (64,64)
        kernel = self.context.modules[self.config['kernel']]
        symbol_filename = "x64"
        symbol_table_name = self.create_bitlocker_table(self.context, kernel.symbol_table_name,
                                                        self.config_path, symbol_filename)
        constraint = poolscanner.PoolConstraint(tag,
                                                size = pool_size,
                                                page_type=poolscanner.PoolType.NONPAGED | poolscanner.PoolType.PAGED,
                                                type_name=symbol_table_name + constants.BANG + 'vmk_pool')
        for result in poolscanner.PoolScanner.generate_pool_scan(self.context, kernel.layer_name,
                                                                 kernel.symbol_table_name, [constraint]):
            _constraint, vmk_pool, _header = result
            yield (0,(bytes(vmk_pool.vmk).hex(),))

    def run(self):
        return renderers.TreeGrid([
            ('Vmk', str)
        ], self._generator())
