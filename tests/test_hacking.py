import io
import os
import socket
import tempfile
import threading
import unittest
from contextlib import contextmanager, redirect_stdout
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import hacking
from tests import example


class BaseToolkitTest(unittest.TestCase):
    def run_with_inputs(self, func, inputs):
        stream = io.StringIO()
        with patch('builtins.input', side_effect=inputs), redirect_stdout(stream):
            func()
        return stream.getvalue()


class _MiniResponse:
    def __init__(self, status_code, content, headers):
        self.status_code = status_code
        self.content = content
        self.text = content.decode('utf-8', 'replace')
        self.headers = headers


class _MiniSession:
    headers = {}

    def update(self, values):
        self.headers.update(values)

    def _request(self, method, url, params=None, data=None, timeout=5):
        if params:
            query = urlencode(params)
            sep = '&' if '?' in url else '?'
            url = f'{url}{sep}{query}'
        body = None
        if data is not None:
            body = urlencode(data).encode('utf-8') if isinstance(data, dict) else str(data).encode('utf-8')
        req = Request(url, data=body, method=method.upper(), headers=self.headers)
        try:
            with urlopen(req, timeout=timeout) as r:
                return _MiniResponse(r.status, r.read(), dict(r.headers))
        except HTTPError as ex:
            return _MiniResponse(ex.code, ex.read(), dict(ex.headers))

    def get(self, url, params=None, timeout=5):
        return self._request('GET', url, params=params, timeout=timeout)

    def post(self, url, data=None, timeout=5):
        return self._request('POST', url, data=data, timeout=timeout)


class _MiniRequests:
    @staticmethod
    def Session():
        return _MiniSession()

    @staticmethod
    def request(method, url, headers=None, data=None, timeout=10, verify=False):
        sess = _MiniSession()
        if headers:
            sess.headers.update(headers)
        return sess._request(method, url, data=data, timeout=timeout)


@contextmanager
def requests_backend():
    if hacking.HAS_REQUESTS:
        yield
        return
    with patch.object(hacking, 'HAS_REQUESTS', True), patch.object(hacking, 'requests', _MiniRequests, create=True):
        yield


class CoreHelpersTests(BaseToolkitTest):
    def test_detect_encoding_multiple_formats(self):
        self.assertIn('base64', hacking.detect_encoding('ZmxhZ3t0ZXN0fQ=='))
        self.assertIn('hex', hacking.detect_encoding('666c61677b746573747d'))
        self.assertIn('binary', hacking.detect_encoding('01100110 01101100'))
        self.assertIn('url_encoded', hacking.detect_encoding('flag%7Btest%7D'))

    def test_magic_decode_base64_rot13(self):
        out = hacking.magic_decode('ZmxhZ3t0b29sa2l0fQ==')
        self.assertIn('Base64', out)
        self.assertEqual(out['Base64'], 'flag{toolkit}')
        self.assertEqual(out['ROT13'], 'MzkuM3g0o29fn2y0sD==')

    def test_run_executes_command(self):
        output = hacking._run("python3 -c 'print(12345)'")
        self.assertIn('12345', output)


class UtilityFunctionTests(BaseToolkitTest):
    def test_hash_identify_sha256(self):
        out = self.run_with_inputs(hacking.hash_identify, ['a' * 64])
        self.assertIn('SHA-256', out)

    def test_num_convert_decimal(self):
        out = self.run_with_inputs(hacking.num_convert, ['65'])
        self.assertIn('Decimal:     65', out)
        self.assertIn('0x41', out)
        self.assertIn('Unicode:     A', out)

    def test_str_bytes_modes(self):
        out1 = self.run_with_inputs(hacking.str_bytes, ['1', 'Hi'])
        self.assertIn('4869', out1)
        out2 = self.run_with_inputs(hacking.str_bytes, ['2', '666c6167'])
        self.assertIn('flag', out2)
        out3 = self.run_with_inputs(hacking.str_bytes, ['3', '0001'])
        self.assertIn('Integer (big-endian): 1', out3)
        out4 = self.run_with_inputs(hacking.str_bytes, ['4', '255'])
        self.assertIn('Hex:   ff', out4)

    def test_flag_validate_calls_magic_decode(self):
        with patch.object(hacking, 'magic_decode') as mock_magic:
            self.run_with_inputs(hacking.flag_validate, ['CTF{hello_world}'])
            mock_magic.assert_called_once_with('hello_world')

    def test_url_encoding_helper(self):
        out = self.run_with_inputs(hacking.url_enc, ['a b'])
        self.assertIn('a%20b', out)

    def test_rot_brute_and_frequency(self):
        out_rot = self.run_with_inputs(hacking.rot_brute, ['uryyb'])
        self.assertIn('ROT13', out_rot)
        out_freq = self.run_with_inputs(hacking.freq_analysis, ['ABBA'])
        self.assertIn('Most frequent', out_freq)

    def test_flag_finder_text_and_file(self):
        out = self.run_with_inputs(hacking.flag_finder, ['CTF{abc_123}'])
        self.assertIn('FLAG CANDIDATE', out)
        with tempfile.NamedTemporaryFile('w', delete=False) as tmp:
            tmp.write('noise picoCTF{from_file} noise')
            tmp_path = tmp.name
        try:
            out2 = self.run_with_inputs(hacking.flag_finder, [tmp_path])
            self.assertIn('picoCTF{from_file}', out2)
        finally:
            os.unlink(tmp_path)


class MenuDispatchTests(BaseToolkitTest):
    def _assert_menu_dispatch(self, menu_func, target_name):
        with patch.object(hacking, 'menu', side_effect=[1, 0]):
            with patch.object(hacking, target_name) as target:
                menu_func()
                target.assert_called_once()

    def test_main_submenus_dispatch(self):
        self._assert_menu_dispatch(hacking.crypto_menu, 'rsa_small_e')
        self._assert_menu_dispatch(hacking.re_menu, 'binary_recon')
        self._assert_menu_dispatch(hacking.web_menu, 'sqli_tester')
        self._assert_menu_dispatch(hacking.forensics_menu, 'file_analysis')
        self._assert_menu_dispatch(hacking.osint_menu, 'domain_recon')
        self._assert_menu_dispatch(hacking.net_menu, 'port_scan')
        self._assert_menu_dispatch(hacking.utils_menu, 'num_convert')


class WebAndNetworkIntegrationTests(BaseToolkitTest):
    @classmethod
    def setUpClass(cls):
        cls.httpd = example.create_server(0)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def test_sqli_tester_against_example_site(self):
        with requests_backend():
            url = f'http://127.0.0.1:{self.port}/login'
            out = self.run_with_inputs(hacking.sqli_tester, [url, 'username', 'post', 'welcome'])
        self.assertIn('SUCCESS', out)
        self.assertIn('TIME-BASED BLIND', out)

    def test_lfi_fuzzer_against_example_site(self):
        with requests_backend():
            url = f'http://127.0.0.1:{self.port}/lfi?file=FUZZ'
            out = self.run_with_inputs(hacking.lfi_fuzzer, [url, 'root:'])
        self.assertIn('HIT', out)

    def test_param_fuzzer_with_small_wordlist(self):
        with tempfile.NamedTemporaryFile('w', delete=False) as tmp:
            tmp.write('1\nadmin\nmissing\n')
            wordlist = tmp.name
        try:
            with requests_backend():
                out = self.run_with_inputs(
                    hacking.param_fuzzer,
                    [f'http://127.0.0.1:{self.port}/item?id=FUZZ', wordlist, 'interesting marker']
                )
            self.assertIn("word='admin'", out)
        finally:
            os.unlink(wordlist)

    def test_http_requester_gets_flag(self):
        with requests_backend():
            out = self.run_with_inputs(hacking.http_requester, [f'http://127.0.0.1:{self.port}/flag', 'GET', ''])
        self.assertIn('Status: 200', out)
        self.assertIn('CTF{web_flag}', out)

    def test_port_scan_and_banner_grab_local_socket(self):
        scan_sock = socket.socket()
        scan_sock.bind(('127.0.0.1', 0))
        scan_sock.listen(1)
        scan_port = scan_sock.getsockname()[1]
        try:
            out_scan = self.run_with_inputs(hacking.port_scan, ['127.0.0.1', f'{scan_port}-{scan_port}'])
            self.assertIn('OPEN', out_scan)
        finally:
            scan_sock.close()

        banner_sock = socket.socket()
        banner_sock.bind(('127.0.0.1', 0))
        banner_sock.listen(1)
        banner_port = banner_sock.getsockname()[1]

        def worker():
            conn, _ = banner_sock.accept()
            try:
                conn.recv(2048)
                conn.sendall(b'HELLO_BANNER\r\n')
            finally:
                conn.close()
                banner_sock.close()

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        out_banner = self.run_with_inputs(hacking.banner_grab, ['127.0.0.1', str(banner_port), ''])
        self.assertIn('Banner', out_banner)


class FilesAndReconTests(BaseToolkitTest):
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

    def test_binary_recon_and_steg_tester_with_mocked_run(self):
        with tempfile.NamedTemporaryFile('wb', delete=False) as tmp:
            tmp.write(b'\x7fELFdummy')
            path = tmp.name
        try:
            mocked = 'file output\nflag{from_cmd}'
            with patch.object(hacking, '_run', return_value=mocked):
                out1 = self.run_with_inputs(hacking.binary_recon, [path])
                out2 = self.run_with_inputs(hacking.steg_tester, [path])
            self.assertIn('flag{from_cmd}', out1)
            self.assertIn('flag{from_cmd}', out2)
        finally:
            os.unlink(path)

    def test_elf_header_and_hex_viewer(self):
        with tempfile.NamedTemporaryFile('wb', delete=False) as tmp:
            tmp.write(
                b'\x7fELF' + bytes([2, 1, 1, 0]) + b'\x00' * 8 +
                (2).to_bytes(2, 'little') + (0x3E).to_bytes(2, 'little') +
                (1).to_bytes(4, 'little') + (0x400000).to_bytes(8, 'little') +
                b'\x00' * 32
            )
            path = tmp.name
        try:
            out_header = self.run_with_inputs(hacking.elf_header, [path])
            self.assertIn('64-bit', out_header)
            out_hex = self.run_with_inputs(hacking.hex_viewer, [path, '0', '16'])
            self.assertIn('00000000', out_hex)
        finally:
            os.unlink(path)

    def test_entropy_calc_and_proto_decode(self):
        with tempfile.NamedTemporaryFile('wb', delete=False) as tmp:
            tmp.write(b'A' * 256)
            path = tmp.name
        try:
            out_entropy = self.run_with_inputs(hacking.entropy_calc, [path, 'n'])
            self.assertIn('Shannon entropy', out_entropy)
        finally:
            os.unlink(path)
        out_proto = self.run_with_inputs(hacking.proto_decode, ['504b0304'])
        self.assertIn('Detected: ZIP archive', out_proto)

    def test_recon_osint_command_wrappers(self):
        with patch.object(hacking, '_run', return_value='mock output'):
            out_domain = self.run_with_inputs(hacking.domain_recon, ['example.com'])
            out_geo = self.run_with_inputs(hacking.geo_from_meta, ['img.jpg'])
        self.assertIn('WHOIS', out_domain)
        self.assertIn('mock output', out_geo)

        out_dorks = self.run_with_inputs(hacking.google_dorks, ['example.com'])
        self.assertIn('site:example.com', out_dorks)

    def test_email_header_parser_and_requestless_helpers(self):
        headers = ['From: sender@example.com', 'Reply-To: attacker@example.com', 'Message-ID: <x@y>', '']
        out_email = self.run_with_inputs(hacking.email_header, headers)
        self.assertIn('From', out_email)

        out_oneliners = self.run_with_inputs(hacking.oneliner_sheet, [])
        self.assertIn('Base64 decode', out_oneliners)

        out_nc = self.run_with_inputs(hacking.nc_helper, [])
        self.assertIn('Essential netcat commands', out_nc)


if __name__ == '__main__':
    unittest.main(verbosity=2)
