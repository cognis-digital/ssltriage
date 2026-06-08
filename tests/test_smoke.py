"""Smoke tests for SSLTRIAGE. No network. Standard library only."""
import datetime as dt
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ssltriage import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    grade_report,
    parse_input,
    triage,
)
from ssltriage.cli import main  # noqa: E402


VULNERABLE = """\
Connecting to legacy.example:443
 * TLS 1.0 Cipher suites:
     TLS_RSA_WITH_RC4_128_SHA
     TLS_RSA_WITH_3DES_EDE_CBC_SHA
 * TLS 1.2 Cipher suites:
     TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
 not after:  Jun 20 23:59:59 2026 GMT
"""

STRONG = """\
Connecting to secure.example:443
 * TLS 1.2 Cipher suites:
     TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 * TLS 1.3 Cipher suites:
     TLS_AES_256_GCM_SHA384
 not after:  Jun 20 23:59:59 2030 GMT
"""

NOW = dt.datetime(2026, 6, 8)


class TestMeta(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "ssltriage")
        self.assertRegex(TOOL_VERSION, r"^\d+\.\d+\.\d+$")


class TestParsing(unittest.TestCase):
    def test_parses_protocols_and_target(self):
        prof = parse_input(VULNERABLE)
        self.assertIn("TLSv1.0", prof["protocols"])
        self.assertIn("TLSv1.2", prof["protocols"])
        self.assertEqual(prof["target"], "legacy.example")

    def test_parses_ciphers(self):
        prof = parse_input(VULNERABLE)
        joined = " ".join(prof["ciphers"])
        self.assertIn("RC4", joined)
        self.assertIn("3DES", joined)

    def test_target_override(self):
        prof = parse_input(VULNERABLE, target="override.example")
        self.assertEqual(prof["target"], "override.example")


class TestTriage(unittest.TestCase):
    def test_vulnerable_grades_poorly(self):
        rep = triage(VULNERABLE, now=NOW)
        self.assertIn(rep.grade, ("D", "E", "F"))
        codes = {f.code for f in rep.findings}
        self.assertIn("PROTO_INSECURE", codes)
        self.assertIn("CIPHER_WEAK", codes)
        self.assertTrue(rep.has_actionable_findings())

    def test_strong_grades_well(self):
        rep = triage(STRONG, now=NOW)
        self.assertIn(rep.grade, ("A", "B"))
        self.assertFalse(rep.has_actionable_findings())

    def test_expired_cert_is_critical(self):
        text = "TLSv1.3\n not after: Jan 01 00:00:00 2020 GMT\n"
        rep = triage(text, now=NOW)
        codes = {f.code for f in rep.findings}
        self.assertIn("CERT_EXPIRED", codes)
        self.assertEqual(rep.grade, "F")

    def test_grade_monotonic(self):
        clean, _ = grade_report([])
        self.assertEqual(clean, 100)

    def test_report_json_roundtrip(self):
        rep = triage(VULNERABLE, now=NOW)
        blob = json.dumps(rep.to_dict())
        data = json.loads(blob)
        self.assertEqual(data["target"], "legacy.example")
        self.assertIn("findings", data)


class TestCLI(unittest.TestCase):
    def _run(self, argv, stdin=""):
        out, err = io.StringIO(), io.StringIO()
        old = (sys.stdin, sys.stdout, sys.stderr)
        sys.stdin, sys.stdout, sys.stderr = io.StringIO(stdin), out, err
        try:
            code = main(argv)
        finally:
            sys.stdin, sys.stdout, sys.stderr = old
        return code, out.getvalue(), err.getvalue()

    def test_version(self):
        with self.assertRaises(SystemExit) as ctx:
            main(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_grade_stdin_json_nonzero_on_findings(self):
        code, out, _ = self._run(["grade", "-", "--format", "json"], stdin=VULNERABLE)
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertIn(data["grade"], ("D", "E", "F"))

    def test_grade_strong_exits_zero(self):
        code, out, _ = self._run(["grade", "-"], stdin=STRONG)
        self.assertEqual(code, 0)
        self.assertIn("Report Card", out)

    def test_no_command_is_error(self):
        code, _, _ = self._run([])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
