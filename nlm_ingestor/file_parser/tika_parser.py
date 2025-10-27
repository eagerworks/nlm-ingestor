import logging
import os

from bs4 import BeautifulSoup
from nlm_utils.utils.utils import ensure_bool
from tika import parser

from nlm_ingestor.file_parser.file_parser import FileParser
from nlm_ingestor.ingestor_utils.pdf_sanitizer import sanitize_pdf_for_tika


class TikaFileParser(FileParser):
    def __init__(self):
        pass

    def parse_to_html(self, filepath, do_ocr=False):
        # CVE-2025-54988 Mitigation: Remove XFA forms from PDFs to prevent XXE attacks
        # This compensating control eliminates the vulnerable code path before
        # the PDF reaches the vulnerable Tika server (tika-parser-pdf-module 2.9.3)
        sanitized_filepath, sanitization_result = sanitize_pdf_for_tika(filepath)

        if sanitization_result and sanitization_result.xfa_removed:
            print(f"CVE-2025-54988 MITIGATION: XFA forms removed from PDF before Tika processing: {filepath}")

        # Use the sanitized filepath for Tika processing
        filepath = sanitized_filepath

        # Turn off OCR by default
        timeout = 3000
        headers = {
            "X-Tika-OCRskipOcr": "true",
            "X-Tika-PDFOcrStrategy": "auto",
            "X-Tika-PDFExtractFontNames": "true",
        }
        if do_ocr:
            headers = {
                "X-Tika-OCRskipOcr": "false",
                "X-Tika-OCRoutputType": "hocr",
                "X-Tika-Timeout-Millis": str(100 * timeout),
                "X-Tika-PDFOcrStrategy": "ocr_only",
                "X-Tika-OCRtimeoutSeconds": str(timeout),
            }

        if ensure_bool(os.environ.get("TIKA_OCR", False)):
            headers = None
        return parser.from_file(
            filepath,
            xmlContent=True,
            requestOptions={"headers": headers, "timeout": timeout},
        )

    def parse_to_clean_html(self, filepath):
        if not find_tika_header(filepath):
            with open(filepath) as file:
                file_data = BeautifulSoup(
                    file.read(),
                    features="html.parser",
                ).prettify()
            return parser.from_buffer(file_data, xmlContent=True)
        else:
            with open(filepath) as file:
                file_data = file.read()
            return {"metadata": "", "content": file_data, "status": ""}


def find_tika_header(fp):
    try:
        with open(fp) as file:
            file_data = file.read()
            soup = BeautifulSoup(file_data, "html.parser")
            # print(str(soup.find_all('head')[0]))
            head = soup.find_all("head")
            return "org.apache.tika.parser" in str(head[0])
    except Exception as e:
        logging.error(e)
        return False
