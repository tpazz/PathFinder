import os
import struct
import tempfile
import unittest
from pathlib import Path

from tools.verify_collector_artifacts import (
    COLLECTORS,
    VerificationError,
    inspect_elf,
    verify_stdlib_only,
)


class CollectorPackagingTests(unittest.TestCase):
    def test_both_collectors_remain_stdlib_only(self):
        for details in COLLECTORS.values():
            imports = verify_stdlib_only(details["source"])
            self.assertIn("argparse", imports)

    def test_non_stdlib_import_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "collector.py"
            source.write_text("import requests\n", encoding="utf-8")
            with self.assertRaisesRegex(VerificationError, "requests"):
                verify_stdlib_only(source)

    def test_elf_architecture_and_static_interpreter_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            static_elf = root / "static"
            dynamic_elf = root / "dynamic"
            self._write_elf(static_elf, machine=62, segment_type=1)
            self._write_elf(dynamic_elf, machine=183, segment_type=3)

            self.assertEqual(inspect_elf(static_elf)["elf_machine"], 62)
            self.assertFalse(inspect_elf(static_elf)["has_dynamic_interpreter"])
            self.assertEqual(inspect_elf(dynamic_elf)["elf_machine"], 183)
            self.assertTrue(inspect_elf(dynamic_elf)["has_dynamic_interpreter"])

    @staticmethod
    def _write_elf(path, *, machine, segment_type):
        data = bytearray(64 + 56)
        data[:16] = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
        struct.pack_into("<H", data, 18, machine)
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<H", data, 54, 56)
        struct.pack_into("<H", data, 56, 1)
        struct.pack_into("<I", data, 64, segment_type)
        path.write_bytes(data)
        os.chmod(path, 0o755)


if __name__ == "__main__":
    unittest.main()
