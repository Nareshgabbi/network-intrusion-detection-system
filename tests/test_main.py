"""Tests for graceful NIDS shutdown."""

import contextlib
import io
import unittest
from unittest.mock import patch

import main


class MainShutdownTests(unittest.TestCase):
    @patch("main.AlertManager")
    @patch("main.start_capture", side_effect=KeyboardInterrupt)
    def test_keyboard_interrupt_prints_summary_and_exits_cleanly(
        self, mock_start_capture, mock_alert_manager
    ):
        output = io.StringIO()
        manager = mock_alert_manager.return_value

        with contextlib.redirect_stdout(output):
            main.main()

        text = output.getvalue()
        self.assertIn("Stopping NIDS...", text)
        self.assertIn("NIDS stopped successfully.", text)
        manager.print_summary.assert_called_once_with()
        mock_start_capture.assert_called_once_with(alert_manager=manager)


if __name__ == "__main__":
    unittest.main()
