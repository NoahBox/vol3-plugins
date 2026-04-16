import os
from typing import List, Optional, Iterable, Tuple, Iterator

from volatility3.framework import interfaces, renderers, constants, symbols, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.symbols import intermed
from volatility3.plugins.windows import driverscan
from volatility3.framework.renderers import format_hints


class VeraCrypt(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name='kernel', description='Windows kernel',
                                           architectures=["Intel32", "Intel64"]),
            requirements.PluginRequirement(
                name='driverscan', plugin=driverscan.DriverScan, version=(1, 0, 0)),
        ]

    @staticmethod
    def create_truecrypt_table(context: interfaces.context.ContextInterface, symbol_table: str,
                               config_path: str) -> str:
        symbol_filename = "vc-12.4-x64"
        return intermed.IntermediateSymbolTable.create(context,
                                                       config_path,
                                                       os.path.join(
                                                           "windows", "veracrypt"),
                                                       symbol_filename)

    def _generator(self) -> Iterator[Tuple[int, Tuple[int, str, str]]]:
        kernel = self.context.modules[self.config['kernel']]
        symbol_table_name = self.create_truecrypt_table(self.context, kernel.symbol_table_name,
                                                        self.config_path)
        for driver in driverscan.DriverScan.scan_drivers(self.context, kernel.layer_name, kernel.symbol_table_name):
            try:
                driver_name = driver.get_driver_name()
            except (ValueError, exceptions.InvalidAddressException):
                continue

            if driver_name.endswith("veracrypt"):
                device = driver.DeviceObject.dereference()
                device_extension = device.DeviceExtension.dereference()
                ext = device_extension.cast(
                    symbol_table_name + constants.BANG + 'EXTENSION')
                crypto_info = ext.cryptoInfo.dereference()
                bTrueCryptMode = crypto_info.bTrueCryptMode
                ea = crypto_info.ea
                encrypted_area_start = crypto_info.EncryptedAreaStart
                encrypted_area_length = crypto_info.EncryptedAreaLength
                ks = crypto_info.ks
                ks2 = crypto_info.ks2
                cryptoinfo_bytes_array = crypto_info.bytes
                yield 0, (bytes(ks).hex(), bytes(ks2).hex(),bTrueCryptMode,ea,encrypted_area_start,encrypted_area_length,bytes(cryptoinfo_bytes_array).hex())
                break

    def run(self):
        return renderers.TreeGrid([
            ('ks', str),
            ('ks2', str),
            ('bTrueCryptMode', int),
            ('ea', int),
            ('encryptedAreaStart', int),
            ('encryptedAreaLength', int),
            ('cryptoInfo', str),
        ], self._generator())
