import tempfile
import unittest
from pathlib import Path

from file_analyzer import analyze, format_size, is_probably_text


class FileAnalyzerTests(unittest.TestCase):
    def test_format_size(self):
        self.assertEqual(format_size(0), "0 B")
        self.assertEqual(format_size(1024), "1.00 KiB")

    def test_text_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.txt"
            path.write_text("hello world\n", encoding="utf-8")
            self.assertTrue(is_probably_text(path))

    def test_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.txt"
            path.write_text("hello", encoding="utf-8")
            info = analyze(path)
            self.assertEqual(info["name"], "sample.txt")
            self.assertEqual(info["size"], 5)
            self.assertEqual(info["type"], "text")
            self.assertEqual(len(info["sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
