import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import hacking


class ToolkitFunctionTests(unittest.TestCase):
    def run_with_inputs(self, func, inputs):
        stream = io.StringIO()
        with patch('builtins.input', side_effect=inputs), redirect_stdout(stream):
            func()
        return stream.getvalue()

    def test_detect_encoding_identifies_multiple_formats(self):
        self.assertIn('base64', hacking.detect_encoding('ZmxhZ3t0ZXN0fQ=='))
        self.assertIn('hex', hacking.detect_encoding('666c61677b746573747d'))
        self.assertIn('binary', hacking.detect_encoding('01100110 01101100'))
        self.assertIn('url_encoded', hacking.detect_encoding('flag%7Btest%7D'))

    def test_magic_decode_base64_and_rot13(self):
        out = hacking.magic_decode('ZmxhZ3t0b29sa2l0fQ==')
        self.assertIn('Base64', out)
        self.assertEqual(out['Base64'], 'flag{toolkit}')
        self.assertEqual(out['ROT13'], 'MzkuM3g0o29fn2y0sD==')

    def test_run_helper_executes_command(self):
        output = hacking._run("python3 -c 'print(12345)'")
        self.assertIn('12345', output)

    def test_hash_identify_sha256(self):
        out = self.run_with_inputs(
            hacking.hash_identify,
            ['a' * 64],
        )
        self.assertIn('SHA-256', out)

    def test_num_convert_decimal(self):
        out = self.run_with_inputs(hacking.num_convert, ['65'])
        self.assertIn('Decimal:     65', out)
        self.assertIn('0x41', out)
        self.assertIn('Unicode:     A', out)

    def test_str_bytes_string_to_bytes(self):
        out = self.run_with_inputs(hacking.str_bytes, ['1', 'Hi'])
        self.assertIn('4869', out)
        self.assertIn('[72, 105]', out)

    def test_str_bytes_bytes_to_string(self):
        out = self.run_with_inputs(hacking.str_bytes, ['2', '666c6167'])
        self.assertIn('flag', out)

    def test_flag_validate_calls_magic_decoder(self):
        with patch.object(hacking, 'magic_decode') as mock_magic:
            self.run_with_inputs(hacking.flag_validate, ['CTF{hello_world}'])
            mock_magic.assert_called_once_with('hello_world')

    def test_url_encoding_helper(self):
        out = self.run_with_inputs(hacking.url_enc, ['a b'])
        self.assertIn('a%20b', out)

    def test_auto_triage_text_file_runs_magic_decode(self):
        with tempfile.NamedTemporaryFile('w', delete=False) as tmp:
            tmp.write('flag{triage}')
            tmp_path = tmp.name

        try:
            with patch.object(hacking, '_run', return_value='ASCII text'):
                with patch.object(hacking, 'magic_decode') as mock_magic:
                    with redirect_stdout(io.StringIO()):
                        hacking.auto_triage(tmp_path)
                    mock_magic.assert_called_once()
        finally:
            os.unlink(tmp_path)


if __name__ == '__main__':
    unittest.main(verbosity=2)
