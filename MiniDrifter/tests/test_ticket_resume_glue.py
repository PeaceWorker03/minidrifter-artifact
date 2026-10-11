# -*- coding: utf-8 -*-
"""Tests for ticket normalizer and field_to_blocked_hops index."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from minidrifter.verification.field_to_blocked_hops import (
    chains_blocked_by_fields,
    clear_field_blocks,
    record_blocked_hop,
)
from minidrifter.verification.ticket_normalizer import (
    normalize_ticket,
    ticket_from_next_action,
    write_operator_request_md,
)


class TicketNormalizerTests(unittest.TestCase):
    def test_normalize_ticket_resume_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            ticket = ticket_from_next_action('provide_capture_file', pack_dir=pack, path='/api/order/detail')
            norm = normalize_ticket(ticket, pack_dir=pack)
            self.assertIn('workbench resume', norm['resume_command'])
            self.assertIn('/api/order/detail', norm.get('blocked_api', '') or norm['evidence'].get('api', ''))

    def test_write_operator_request_md(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            ticket = ticket_from_next_action('refresh_baseline_capture', pack_dir=pack)
            from minidrifter.verification.ticket_normalizer import emit_ticket
            emit_ticket(pack, ticket)
            md = (pack / 'operator_request.md').read_text(encoding='utf-8')
            self.assertIn('操作请求', md)
            self.assertIn('resume_command', md.lower() or 'workbench resume' in md)


class FieldBlockedHopsTests(unittest.TestCase):
    def test_record_and_clear(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp)
            record_blocked_hop(
                pack, 'orderId',
                chain_id='chain_12',
                blocked_path='/order/detail',
                blocked_stage='M0_BUILD',
                resume_from_hop=2,
                ticket_id='T-001',
            )
            self.assertIn('chain_12', chains_blocked_by_fields(pack, ['orderId']))
            revived = clear_field_blocks(pack, ['orderId'])
            self.assertEqual(revived, ['chain_12'])
            self.assertEqual(chains_blocked_by_fields(pack, ['orderId']), [])


if __name__ == '__main__':
    unittest.main()
