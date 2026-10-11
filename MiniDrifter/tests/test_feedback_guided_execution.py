# -*- coding: utf-8 -*-
"""Node-level and workflow-level feedback must actually change the request."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from minidrifter.runtime_trace.chain_executor import ChainExecutor
from minidrifter.runtime_trace.feedback_alts import (
    apply_node_alt,
    synthesize_node_alts,
    synthesize_workflow_alts,
)


def _write_pack(tmp: Path, *, bcg=None, ccrs=None) -> Path:
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / 'rpgraph.json').write_text(
        json.dumps(bcg or {'nodes': [], 'edges': []}), encoding='utf-8'
    )
    (tmp / 'rcr_pack.json').write_text(
        json.dumps({'ccrs': ccrs or []}), encoding='utf-8'
    )
    return tmp


def _http_by_method(url, data=None, headers=None, method=None, timeout=15):
    m = (method or ('POST' if data else 'GET')).upper()
    if m == 'GET':
        return 405, 'Method Not Allowed', 1.0
    return 200, json.dumps({'data': {'ok': True}, 'IsSuccess': True}), 1.0


EHAI_DEVICE = '/Wechat/Special/Mini/Device/List'
EHAI_BIND = '/Wechat/WeChat/Account/BindInfo/V2'


class NodeAltSynthesisTests(unittest.TestCase):
    def test_device_list_gets_method_and_alias(self):
        step = {
            'path': EHAI_DEVICE,
            'method': 'GET',
            'inputs': {'userId': '1'},
            'drift_fields': ['userId'],
        }
        ccrs = [{
            'endpoint': {'path': EHAI_DEVICE},
            'method': {'value': 'GET'},
            'request_semantics': {'credentials': ['ByUserId', 'userId', 'Token']},
            'binding_credentials': ['ByUserId'],
        }]
        har = {'request': {'method': 'GET', 'query': {'UserId': '1', 'ByUserId': '1'}}}
        alts = synthesize_node_alts(step, har_entry=har, ccrs=ccrs, has_crypto=True)
        kinds = {a['kind'] for a in alts}
        ids = [a['id'] for a in alts]
        # method_switch 已迁至 Workflow；Node 只做物化
        self.assertNotIn('method_switch', kinds)
        self.assertTrue(any(a['kind'] == 'field_alias' and a.get('rename', {}).get('userId') == 'ByUserId' for a in alts) or
                        any('ByUserId' in i for i in ids) or
                        any(a['kind'] == 'field_alias' for a in alts))
        self.assertIn('alt:transport:plaintext', ids)
        self.assertIn('fill_missing_ids', kinds)

    def test_apply_method_switch(self):
        step, resolved = apply_node_alt(
            {'path': EHAI_BIND, 'method': 'GET'},
            {'userId': '9'},
            {'kind': 'method_switch', 'method': 'POST'},
        )
        self.assertEqual(step['method'], 'POST')
        self.assertEqual(resolved['userId'], '9')


class WorkflowAltSynthesisTests(unittest.TestCase):
    def test_bindinfo_ccr_post_variant(self):
        step = {'node_id': 'har:bind', 'path': EHAI_BIND, 'method': 'GET', 'inputs': {'userId': '1'}}
        ccrs = [
            {'operation_id': 'op_get', 'endpoint': {'path': EHAI_BIND}, 'method': {'value': 'GET'}},
            {'operation_id': 'op_post', 'endpoint': {'path': EHAI_BIND}, 'method': {'value': 'POST'}},
        ]
        alts = synthesize_workflow_alts(step, {'nodes': {}}, ccrs=ccrs)
        self.assertTrue(alts)
        self.assertEqual(alts[0]['step']['method'], 'POST')
        self.assertEqual(alts[0]['kind'], 'same_path_variant')

    def test_device_list_sibling_from_bcg(self):
        step = {'node_id': 'har:mini', 'path': EHAI_DEVICE, 'method': 'GET'}
        bcg = {
            'nodes': [
                {'node_id': 'a', 'path': EHAI_DEVICE, 'method': 'GET', 'credential': 'ByUserId'},
                {'node_id': 'b', 'path': '/Wechat/User/OnLine/Device/List', 'method': 'GET', 'credential': 'ByUserId'},
            ]
        }
        alts = synthesize_workflow_alts(step, {'nodes': {}}, bcg=bcg)
        paths = [a['step']['path'] for a in alts]
        self.assertIn('/Wechat/User/OnLine/Device/List', paths)


class ExecutorFeedbackTests(unittest.TestCase):
    def test_node_feedback_retries_post_after_get_405(self):
        tmp = Path(tempfile.mkdtemp())
        _write_pack(tmp)
        ex = ChainExecutor(tmp, feedback_mode='no_workflow')
        chain = {
            'chain_id': 'gold:ehai:device-list',
            'poc_steps': [{
                'step': 1,
                'node_id': 'har:device',
                'path': EHAI_DEVICE,
                'method': 'GET',
                'inputs': {'userId': '2519481970'},
                'drift_fields': ['userId'],
            }],
            'nodes': {},
        }
        with patch('minidrifter.runtime_trace.chain_executor._http', side_effect=_http_by_method):
            result = ex.execute_chain(chain, base_url='https://appmini.1hai.cn', mode='execute')
        self.assertEqual(result['final_status'], 'completed')
        last = result['steps'][-1]
        self.assertEqual(last['status'], 'success')
        self.assertGreaterEqual(last.get('materialization_attempts') or 0, 2)
        self.assertEqual(last.get('method'), 'POST')
        stats = ex.feedback.get_stats()
        self.assertGreater(stats.get('materialization_feedback_nodes') or 0, 0)

    def test_workflow_feedback_switches_bindinfo_post(self):
        tmp = Path(tempfile.mkdtemp())
        ccrs = [
            {'operation_id': 'op_get', 'endpoint': {'path': EHAI_BIND}, 'method': {'value': 'GET'}},
            {'operation_id': 'op_post', 'endpoint': {'path': EHAI_BIND}, 'method': {'value': 'POST'}},
        ]
        _write_pack(tmp, ccrs=ccrs)
        ex = ChainExecutor(tmp, feedback_mode='no_node')
        chain = {
            'chain_id': 'gold:ehai:bindinfo',
            'poc_steps': [{
                'step': 1,
                'node_id': 'har:bind',
                'path': EHAI_BIND,
                'method': 'GET',
                'inputs': {'userId': '1'},
            }],
            'nodes': {},
        }
        with patch('minidrifter.runtime_trace.chain_executor._http', side_effect=_http_by_method):
            result = ex.execute_chain(chain, base_url='https://appmini.1hai.cn', mode='execute')
        self.assertEqual(result['final_status'], 'completed')
        self.assertTrue(any(s.get('alternative_tried') for s in result['steps']))
        self.assertTrue(any(s.get('method') == 'POST' and s.get('status') == 'success' for s in result['steps']))
        self.assertGreater(ex.feedback.get_stats().get('blocked_branches') or 0, 0)

    def test_workflow_does_not_replace_target_with_producer(self):
        step = {
            'node_id': 'RCR:phone',
            'path': '/Wechat/WeChat/phoneNumber/unionid',
            'method': 'POST',
            'inputs': {'unionId': 'x'},
            'drift_fields': ['unionId'],
        }
        chain = {
            'nodes': {
                'har:bind': {
                    'path': '/Wechat/WeChat/Account/BindInfo/V2',
                    'method': 'GET',
                    'produces': ['UnionId', 'unionId'],
                },
                'RCR:phone': {
                    'path': '/Wechat/WeChat/phoneNumber/unionid',
                    'method': 'POST',
                    'consumes': ['unionId'],
                },
            }
        }
        alts = synthesize_workflow_alts(step, chain, ccrs=[])
        # same-slot replacement must not swap target to BindInfo
        replace_paths = [
            a['step']['path'] for a in alts
            if a.get('kind') not in ('insert_producer_prefix',) and a.get('step')
        ]
        self.assertNotIn('/Wechat/WeChat/Account/BindInfo/V2', replace_paths)
        # but insert_producer_prefix may prepend BindInfo
        prefixes = [
            (a.get('prefix_step') or {}).get('path')
            for a in alts if a.get('kind') == 'insert_producer_prefix'
        ]
        self.assertIn('/Wechat/WeChat/Account/BindInfo/V2', prefixes)

    def test_promote_exit_and_path_prefix(self):
        failed = {
            'node_id': 'har:addr',
            'path': '/member-general/AddressController/addressList',
            'method': 'GET',
            'inputs': {'uid': '1'},
            'drift_fields': ['uid'],
        }
        chain = {
            'exit_node': 'RCR:order',
            'nodes': {
                'har:addr': {'path': failed['path'], 'method': 'GET'},
                'RCR:order': {
                    'path': '/member-important/dgfOrderController/dgfOrderQuery',
                    'method': 'GET',
                    'produces': ['orderId'],
                },
            },
        }
        alts = synthesize_workflow_alts(failed, chain, ccrs=[])
        kinds = {a['kind'] for a in alts}
        self.assertIn('promote_exit', kinds)
        pe = next(a for a in alts if a['kind'] == 'promote_exit')
        self.assertIn('dgfOrderQuery', pe['step']['path'])

        put = {
            'node_id': 'bcg:put',
            'path': '/my/mySecondHandHouse/putOffSale',
            'method': 'PUT',
            'drift_fields': ['id'],
        }
        alts2 = synthesize_workflow_alts(put, {'nodes': {}}, ccrs=[])
        self.assertTrue(any(a.get('kind') == 'path_prefix' for a in alts2))
        self.assertTrue(any('/hcapi/wx' in (a.get('step') or {}).get('path', '') for a in alts2))


class NodeFillAltTests(unittest.TestCase):
    def test_fill_missing_ids_and_encrypted_query(self):
        step = {
            'path': '/Wechat/Invoice/Title/Detail',
            'method': 'GET',
            'drift_fields': ['titleId'],
            'inputs': {},
        }
        alts = synthesize_node_alts(step, has_crypto=True, session_values={'BindId': '9'})
        kinds = {a['kind'] for a in alts}
        self.assertIn('fill_missing_ids', kinds)
        self.assertIn('fill_session', kinds)
        self.assertTrue(any(a.get('placement') == 'encrypted_query' for a in alts))
        _, filled = apply_node_alt(step, {}, {'kind': 'fill_missing_ids'})
        self.assertEqual(filled.get('titleId'), '1')
        self.assertNotIn('BindId', filled)
        _, mapped = apply_node_alt(
            {'path': '/Wechat/Invoice/Title/Detail', 'drift_fields': ['titleid', 'token']},
            {},
            {'kind': 'fill_missing_ids'},
        )
        self.assertEqual(mapped.get('titleId'), '1')
        self.assertNotIn('token', mapped)
        _, sess = apply_node_alt(
            step, {}, {'kind': 'fill_session', 'values': {'BindId': '9', 'titleId': '3'}}
        )
        self.assertEqual(sess.get('titleId'), '3')
        self.assertNotIn('BindId', sess)

    def test_one_shot_does_not_retry(self):
        tmp = Path(tempfile.mkdtemp())
        _write_pack(tmp)
        ex = ChainExecutor(tmp, feedback_mode='one_shot')
        chain = {
            'chain_id': 'one-shot',
            'poc_steps': [{
                'step': 1, 'node_id': 'n1', 'path': EHAI_DEVICE, 'method': 'GET',
                'inputs': {'userId': '1'},
            }],
            'nodes': {},
        }
        with patch('minidrifter.runtime_trace.chain_executor._http', side_effect=_http_by_method):
            result = ex.execute_chain(chain, base_url='https://appmini.1hai.cn', mode='execute')
        self.assertNotEqual(result['final_status'], 'completed')
        self.assertEqual(result['steps'][0].get('materialization_attempts'), 1)
        self.assertFalse(any(s.get('alternative_tried') for s in result['steps']))


class RepairAndConfirmTests(unittest.TestCase):
    def test_288_is_repairable_and_retries(self):
        tmp = Path(tempfile.mkdtemp())
        _write_pack(tmp)
        ex = ChainExecutor(tmp, feedback_mode='no_workflow')
        chain = {
            'chain_id': 'http-288',
            'poc_steps': [{
                'step': 1, 'node_id': 'har:device', 'path': EHAI_DEVICE, 'method': 'GET',
                'inputs': {'userId': '1'}, 'drift_fields': ['userId'],
            }],
            'nodes': {},
        }

        def http_288_then_ok(url, data=None, headers=None, method=None, timeout=15):
            m = (method or ('POST' if data else 'GET')).upper()
            if m == 'GET':
                return 288, 'custom', 1.0
            return 200, json.dumps({'data': {'ok': True}, 'IsSuccess': True}), 1.0

        with patch('minidrifter.runtime_trace.chain_executor._http', side_effect=http_288_then_ok):
            result = ex.execute_chain(chain, base_url='https://appmini.1hai.cn', mode='execute')
        self.assertEqual(result['final_status'], 'completed')
        self.assertGreaterEqual(result['steps'][-1].get('materialization_attempts') or 0, 2)

    def test_business_false_is_failure_and_repairable(self):
        tmp = Path(tempfile.mkdtemp())
        _write_pack(tmp)
        ex = ChainExecutor(tmp, feedback_mode='no_workflow')
        chain = {
            'chain_id': 'biz-fail',
            'poc_steps': [{
                'step': 1, 'node_id': 'n1', 'path': EHAI_DEVICE, 'method': 'GET',
                'inputs': {'userId': '1'},
            }],
            'nodes': {},
        }
        n = {'i': 0}

        def http_biz(url, data=None, headers=None, method=None, timeout=15):
            n['i'] += 1
            if n['i'] == 1:
                return 200, json.dumps({'IsSuccess': False, 'Message': '请更新最新版本'}), 1.0
            return 200, json.dumps({'IsSuccess': True, 'data': {'ok': True}}), 1.0

        with patch('minidrifter.runtime_trace.chain_executor._http', side_effect=http_biz):
            result = ex.execute_chain(chain, base_url='https://appmini.1hai.cn', mode='execute')
        self.assertEqual(result['final_status'], 'completed')
        self.assertGreater(n['i'], 1)

    def test_confirm_realize_uses_drift_target(self):
        from minidrifter.runtime_trace.chain_executor import DriftState, ExecutionState
        tmp = Path(tempfile.mkdtemp())
        _write_pack(tmp)
        ex = ChainExecutor(tmp, feedback_mode='one_shot')
        omega = DriftState()
        omega.set_drift('target', '2')
        pred = ex._evaluate_confirm_crbd(
            {'drift_point': 'login', 'drift_target': 'target'},
            {
                'final_status': 'completed',
                'steps': [{'node_id': 'target', 'status': 'success', 'crbd_probe': {'crbd_detected': True}}],
            },
            ExecutionState(),
            omega,
        )
        self.assertTrue(pred['Realize'])
        self.assertTrue(pred['Confirmed'])

    def test_issuccess_true_ignores_non_numeric_errorcode(self):
        tmp = Path(tempfile.mkdtemp())
        _write_pack(tmp)
        ex = ChainExecutor(tmp, feedback_mode='one_shot')
        self.assertFalse(ex._business_failed(json.dumps({
            'IsSuccess': True, 'ErrorCode': 'None', 'Message': 'ok',
        })))
        self.assertTrue(ex._business_failed(json.dumps({
            'IsSuccess': False, 'ErrorCode': 0, 'Message': '请更新最新版本',
        })))


class PathFieldTests(unittest.TestCase):
    def test_bytitle_and_title_detail(self):
        from minidrifter.runtime_trace.chain_composer import infer_binding_fields_from_path
        title = {x.lower() for x in infer_binding_fields_from_path('/Wechat/Invoice/List/ByTitle')}
        self.assertIn('title', title)
        detail = {x.lower() for x in infer_binding_fields_from_path('/wechat/Invoice/Title/Detail')}
        self.assertIn('titleid', detail)
        unbind = {x.lower() for x in infer_binding_fields_from_path('/wechat/WeChat/UnBind')}
        self.assertIn('bindid', unbind)
        member = {x.lower() for x in infer_binding_fields_from_path(
            '/action/carrctapi/account/personalData/get/v2'
        )}
        self.assertIn('memberid', member)
        house = {x.lower() for x in infer_binding_fields_from_path(
            '/hcapi/wx/my/mySecondHandHouse/detail/{houseId}'
        )}
        self.assertIn('houseid', house)
        nick = {x.lower() for x in infer_binding_fields_from_path('/hcapi/wx/member/updateMemberInfo')}
        self.assertIn('memberid', nick)
        face = {x.lower() for x in infer_binding_fields_from_path('/hcapi/wx/auth/face/verifiedStatus')}
        self.assertIn('userid', face)


class NodeFeedbackEffectTests(unittest.TestCase):
    def test_four_effects_on_one_path(self):
        tmp = Path(tempfile.mkdtemp())
        ccrs = [{
            'endpoint': {'path': '/order/submit'},
            'binding_credentials': ['userId'],
        }]
        _write_pack(tmp, ccrs=ccrs)
        calls = []

        def http(url, data=None, headers=None, method=None, timeout=15):
            body = data if isinstance(data, dict) else {}
            calls.append((url, dict(body)))
            if '/checkout/init' in url:
                if body.get('userId') != '801563':
                    return 400, json.dumps({'IsSuccess': False, 'Message': '参数格式错误'}), 1.0
                if body.get('nonce') == '10':
                    return 400, json.dumps({'IsSuccess': False, 'Message': 'timestamp过期'}), 1.0
                return 200, json.dumps({'IsSuccess': True, 'checkoutToken': 'tok-new'}), 1.0
            if body.get('userId') != 'AUTH':
                return 400, json.dumps({'IsSuccess': False, 'Message': '身份不一致'}), 1.0
            if body.get('checkoutToken') == 'tok-new' and body.get('houseId') == 'H-KEEP':
                return 200, json.dumps({'IsSuccess': True, 'orderId': 'O-1'}), 1.0
            return 400, json.dumps({'IsSuccess': False}), 1.0

        chain = {
            'chain_id': 'node-feedback-effects',
            'poc_steps': [
                {
                    'step': 1, 'node_id': 'checkout', 'path': '/checkout/init', 'method': 'POST',
                    'inputs': {
                        'userId': '801553', 'houseId': 'H-KEEP', 'amount': '100', 'nonce': '10',
                    },
                    'drift_fields': ['userId'],
                    'outputs': {'checkoutToken': {'node_id': 'checkout'}},
                },
                {
                    'step': 2, 'node_id': 'order', 'path': '/order/submit', 'method': 'POST',
                    'inputs': {
                        'checkoutToken': {'from': 'checkout'},
                        'userId': '801553',
                        'houseId': 'H-KEEP',
                    },
                },
            ],
            'nodes': {},
        }
        ex = ChainExecutor(tmp, feedback_mode='no_workflow')
        ex._session_identity_values = lambda: {'userId': 'AUTH', 'houseId': 'H-OTHER'}
        with patch('minidrifter.runtime_trace.chain_executor._http', side_effect=http):
            result = ex.execute_chain(chain, base_url='https://127.0.0.1', mode='execute')

        self.assertEqual(result['final_status'], 'completed')
        checkout_bodies = [b for u, b in calls if '/checkout/init' in u]
        self.assertEqual(checkout_bodies[0]['userId'], '801553')
        self.assertIn('801554', [b['userId'] for b in checkout_bodies])
        self.assertEqual(checkout_bodies[-1]['userId'], '801563')
        self.assertTrue(all(b['houseId'] == 'H-KEEP' and b['amount'] == '100' for b in checkout_bodies))
        self.assertNotEqual(checkout_bodies[-1]['nonce'], '10')
        order = result['steps'][-1]
        self.assertEqual(order['status'], 'success')
        self.assertEqual(order['inputs']['checkoutToken'], 'tok-new')
        self.assertEqual(order['inputs']['userId'], 'AUTH')
        self.assertEqual(order['inputs']['houseId'], 'H-KEEP')
        self.assertEqual(result['variables']['userId'], '801563')


if __name__ == '__main__':
    unittest.main()
