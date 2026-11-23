import os
import tempfile
import unittest

from main import export_report_to_html


class TestHTMLReportXSSProtection(unittest.TestCase):
    """Tests for stored XSS hardening and pinned SRI CDN scripts in HTML export (Issue #10)."""

    def test_script_and_html_injection_escaped_in_pre_title_and_inline_json(self):
        malicious_md = (
            "# Report\n"
            "</pre><script>alert('xss-pre')</script>\n"
            "</script><img src=x onerror=alert('xss-script')>\n"
        )
        malicious_title = "</title><script>alert('xss-title')</script>"

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "report.html")
            export_report_to_html(malicious_md, out_path, title=malicious_title)
            with open(out_path, "r", encoding="utf-8") as f:
                html_doc = f.read()

        # Raw executable payloads must never appear unescaped anywhere in the document
        self.assertNotIn("<script>alert('xss-pre')</script>", html_doc)
        self.assertNotIn("<script>alert('xss-title')</script>", html_doc)
        self.assertNotIn("<img src=x onerror=alert('xss-script')>", html_doc)
        self.assertNotIn("</script><img", html_doc)

        # Escaped forms must be present
        self.assertIn("&lt;/title&gt;&lt;script&gt;", html_doc)
        self.assertIn("&lt;/pre&gt;&lt;script&gt;", html_doc)
        self.assertIn("\\u003c/script\\u003e", html_doc)

    def test_cdn_scripts_are_pinned_with_sri_and_dompurify_required(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "report.html")
            export_report_to_html("# Clean Report", out_path)
            with open(out_path, "r", encoding="utf-8") as f:
                html_doc = f.read()

        self.assertIn("marked@12.0.2/marked.min.js", html_doc)
        self.assertIn("dompurify@3.0.9/dist/purify.min.js", html_doc)
        self.assertEqual(html_doc.count('integrity="sha384-'), 2)
        self.assertEqual(html_doc.count('crossorigin="anonymous"'), 2)
        self.assertIn("typeof marked !== 'undefined' && typeof DOMPurify !== 'undefined'", html_doc)


if __name__ == "__main__":
    unittest.main()
