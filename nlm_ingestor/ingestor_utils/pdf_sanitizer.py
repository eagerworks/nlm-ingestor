"""
PDF Sanitization Utility - CVE-2025-54988 Mitigation

This module provides functions to sanitize PDF files by removing XFA (XML Forms Architecture) forms that could contain XXE (XML External Entity) injection payloads.

CVE-2025-54988 affects Apache Tika's tika-parser-pdf-module versions 1.13 through 3.2.1,
allowing XXE attacks via crafted XFA files inside PDFs. This module provides a compensating
control by removing XFA content before PDFs are processed by the vulnerable Tika server.

Vulnerability: CVE-2025-54988 (CVSS 9.8 Critical)
Attack Vector: Crafted XFA forms in PDF with XXE payloads
Mitigation: Surgical removal of /XFA entries from PDF AcroForm dictionary

Date: 2025-10-27
"""

import os
import pikepdf
import shutil
import tempfile
from typing import Optional, Tuple


class XFARemovalResult:
    """Result object for XFA removal operations with audit trail data."""

    def __init__(
        self,
        success: bool,
        file_path: str,
        had_xfa: bool,
        xfa_removed: bool,
        error_message: Optional[str] = None,
        original_size: Optional[int] = None,
        sanitized_size: Optional[int] = None,
    ):
        self.success = success
        self.file_path = file_path
        self.had_xfa = had_xfa
        self.xfa_removed = xfa_removed
        self.error_message = error_message
        self.original_size = original_size
        self.sanitized_size = sanitized_size

    def to_dict(self):
        """Convert to dictionary for logging and audit trails."""
        return {
            "success": self.success,
            "file_path": self.file_path,
            "had_xfa": self.had_xfa,
            "xfa_removed": self.xfa_removed,
            "error_message": self.error_message,
            "original_size_bytes": self.original_size,
            "sanitized_size_bytes": self.sanitized_size,
            "size_reduction_bytes": (
                self.original_size - self.sanitized_size
                if self.original_size and self.sanitized_size
                else None
            ),
        }

    def __str__(self):
        if not self.success:
            return f"XFA Removal Failed: {self.error_message}"
        if self.xfa_removed:
            return f"XFA Removed: {self.file_path} (had XFA, now sanitized)"
        if self.had_xfa:
            return f"XFA Already Removed: {self.file_path}"
        return f"No XFA Found: {self.file_path} (clean PDF)"


def check_pikepdf_available() -> bool:
    """Check if pikepdf library is available."""
    return pikepdf is not None


def remove_xfa_from_pdf(pdf_path: str) -> XFARemovalResult:
    """
    Remove XFA forms from a PDF file in-place to mitigate CVE-2025-54988.

    Args:
        pdf_path: Path to the PDF file to sanitize (modified in-place)

    Returns:
        XFARemovalResult with success status, whether XFA was found/removed, and file sizes
    """
    if not check_pikepdf_available():
        return XFARemovalResult(
            success=False,
            file_path=pdf_path,
            had_xfa=False,
            xfa_removed=False,
            error_message="pikepdf library not available - cannot sanitize PDF",
        )

    if not os.path.exists(pdf_path):
        return XFARemovalResult(
            success=False,
            file_path=pdf_path,
            had_xfa=False,
            xfa_removed=False,
            error_message=f"File not found: {pdf_path}",
        )

    original_size = os.path.getsize(pdf_path)

    try:
        with pikepdf.open(pdf_path) as pdf:
            had_xfa = False
            xfa_removed = False

            # Check if the PDF has an AcroForm dictionary
            if "/AcroForm" in pdf.Root:
                acroform = pdf.Root.AcroForm

                # Check if AcroForm has XFA entry
                if "/XFA" in acroform:
                    had_xfa = True

                    # Log the XFA removal for security audit
                    print(f"CVE-2025-54988 MITIGATION: Removing XFA forms from PDF: {pdf_path}")

                    # Remove the XFA entry
                    del acroform.XFA
                    xfa_removed = True

                    # If AcroForm is now empty except for /XFA, remove it entirely
                    if len(acroform) == 0:
                        del pdf.Root.AcroForm

            # Save in-place using temporary file for atomic operation
            temp_fd, temp_path = tempfile.mkstemp(suffix=".pdf", prefix="sanitized_")
            os.close(temp_fd)

            try:
                pdf.save(temp_path, compress_streams=True)
                shutil.move(temp_path, pdf_path)
            finally:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)

            sanitized_size = os.path.getsize(pdf_path)

            result = XFARemovalResult(
                success=True,
                file_path=pdf_path,
                had_xfa=had_xfa,
                xfa_removed=xfa_removed,
                original_size=original_size,
                sanitized_size=sanitized_size,
            )

            # Log the result for audit trail
            if xfa_removed:
                print(f"CVE-2025-54988 MITIGATION COMPLETE: XFA forms removed from {pdf_path}")
            else:
                print(f"PDF sanitization check passed: {pdf_path} (no XFA found)")

            return result

    except pikepdf.PasswordError:
        error_msg = "PDF is password-protected - cannot sanitize"
        print(f"ERROR: {error_msg}: {pdf_path}")
        return XFARemovalResult(
            success=False,
            file_path=pdf_path,
            had_xfa=False,
            xfa_removed=False,
            error_message=error_msg,
            original_size=original_size,
        )

    except pikepdf.PdfError as e:
        error_msg = f"Not a valid PDF or corrupted: {str(e)}"
        print(f"INFO: {error_msg}: {pdf_path} - skipping XFA check")
        # Return None to indicate file is not a PDF, not an error
        return XFARemovalResult(
            success=True,  # Not an error, just not a PDF
            file_path=pdf_path,
            had_xfa=False,
            xfa_removed=False,
            error_message=None,
            original_size=original_size,
        )

    except Exception as e:
        error_msg = f"Unexpected error during PDF sanitization: {str(e)}"
        print(f"ERROR: {error_msg}: {pdf_path}")
        return XFARemovalResult(
            success=False,
            file_path=pdf_path,
            had_xfa=False,
            xfa_removed=False,
            error_message=error_msg,
            original_size=original_size,
        )


def sanitize_pdf_for_tika(pdf_path: str) -> Tuple[str, Optional[XFARemovalResult]]:
    """
    Sanitize a PDF file before sending to Tika server.

    Args:
        pdf_path: Path to the PDF file to sanitize

    Returns:
        Tuple of (sanitized_path, result):
        - sanitized_path: Path to the sanitized PDF (same as input)
        - result: XFARemovalResult object, or None if not a PDF
    """

    # We do not check the file extension, because temp files here do not have extensions
    # We also do not check file mime type, to avoid adding additional dependencies
    # Just try to process it; remove_xfa_from_pdf will handle non-PDFs gracefully
    print(f"=== CHECKING PDF FOR XFA === {pdf_path}")
    result = remove_xfa_from_pdf(pdf_path)

    print(
        f"=== SANITIZATION RESULT === success={result.success}, had_xfa={result.had_xfa}, xfa_removed={result.xfa_removed}"
    )

    if not result.success:
        print(f"ERROR: CVE-2025-54988: Failed to sanitize PDF, processing with risk: {result.error_message}")

    return pdf_path, result
