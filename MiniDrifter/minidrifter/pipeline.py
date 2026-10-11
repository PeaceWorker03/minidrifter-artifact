# -*- coding: utf-8 -*-
from __future__ import annotations
from pathlib import Path
from typing import Any, Dict
from minidrifter.analyzers.credential import CredentialFlowAnalyzer
from minidrifter.analyzers.reachability import ReachabilityClassifier
from minidrifter.builders.api_cards import APICardBuilder
from minidrifter.builders.replay_contracts import ReplayContractBuilder
from minidrifter.core.profile import ProjectProfileDetector
from minidrifter.core.utils import extract_input, write_json, write_text
from minidrifter.extractors.api_calls import APICallSiteExtractor
from minidrifter.extractors.crypto_transform import CryptoTransformAnalyzer
from minidrifter.extractors.module_alias import ModuleAliasResolver
from minidrifter.extractors.page_surface import PageSurfaceExtractor
from minidrifter.extractors.request_wrapper import RequestWrapperAnalyzer
from minidrifter.extractors.url_registry import URLRegistryExtractor
from minidrifter.extractors.wrapper_url_resolver import apply_wrapper_url_resolution
from minidrifter.extractors.wxml_events import WxmlEventExtractor
from minidrifter.reporting.summary import build_summary_json, build_summary_md
from minidrifter.optimizers.postprocess import StaticResultOptimizer, write_optimizer_outputs
from minidrifter.freezers.api_card import APICardFreezer


class MiniDrifterPipeline:
    def __init__(self, input_path: str | Path, output_dir: str | Path, platform: str = 'wechat'):
        self.input_path = input_path
        self.output_dir = Path(output_dir).resolve()
        self.platform = platform
        self._temp = None
        self.root: Path | None = None

    def run(self) -> Dict[str, Any]:
        root, td = extract_input(self.input_path)
        self.root = root
        self._temp = td
        profile = ProjectProfileDetector(root).run()
        page_surface = PageSurfaceExtractor(root).run()
        events = WxmlEventExtractor(root).run()
        aliases = ModuleAliasResolver(root).run()
        url_registry = URLRegistryExtractor(root).run()
        wrappers = RequestWrapperAnalyzer(root, self.platform).run()
        crypto_cards = CryptoTransformAnalyzer(root).run()
        api_call_res = APICallSiteExtractor(root, url_registry, aliases, wrappers, self.platform).run()
        api_call_res = apply_wrapper_url_resolution(api_call_res, url_registry, wrappers)
        api_calls = api_call_res['api_call_sites']
        dynamic = api_call_res['dynamic_api_candidates']
        reach = ReachabilityClassifier(url_registry, api_calls, events).run()
        url_registry = reach['url_registry']
        credentials = CredentialFlowAnalyzer(api_calls, url_registry).run()
        api_cards = APICardBuilder(url_registry, api_calls, dynamic, events, wrappers, crypto_cards).run()
        replay_contracts = ReplayContractBuilder(api_cards['all_api_cards'], crypto_cards, wrappers).run()
        result = {
            'project_profile': profile,
            'page_surface': page_surface,
            'events': events,
            'module_aliases': aliases,
            'url_registry': url_registry,
            'request_wrappers': wrappers,
            'crypto_cards': crypto_cards,
            'api_call_sites': api_calls,
            'dynamic_api_candidates': dynamic,
            'reachability': reach,
            'credential_candidates': credentials,
            'api_cards': api_cards,
            'replay_contracts': replay_contracts,
        }
        optimizer_outputs = StaticResultOptimizer(result).run()
        result['optimizer_outputs'] = optimizer_outputs
        self.write_outputs(result)
        return result

    def write_outputs(self, result: Dict[str, Any]) -> None:
        out = self.output_dir
        out.mkdir(parents=True, exist_ok=True)
        files = {
            'project_profile.json': result['project_profile'],
            'page_surface.json': result['page_surface'],
            'events.json': result['events'],
            'module_aliases.json': result['module_aliases'],
            'url_registry.json': result['url_registry'],
            'request_wrappers.json': result['request_wrappers'],
            'crypto_cards.json': result['crypto_cards'],
            'api_call_sites.json': result['api_call_sites'],
            'dynamic_api_candidates.json': result['dynamic_api_candidates'],
            'credential_candidates.json': result['credential_candidates'],
            'reached_api_cards.json': result['api_cards']['reached_api_cards'],
            'registered_only_api_cards.json': result['api_cards']['registered_only_api_cards'],
            'dynamic_api_cards.json': result['api_cards']['dynamic_api_cards'],
            'all_api_cards.json': result['api_cards']['all_api_cards'],
            'raw_replay_contracts.json': result['replay_contracts'],
            'summary.json': build_summary_json(result),
        }
        for name, data in files.items():
            write_json(out / name, data)
        if result.get('optimizer_outputs'):
            write_optimizer_outputs(out, result['optimizer_outputs'])
            APICardFreezer(
                ranked=result['optimizer_outputs'].get('ranked_api_candidates') or [],
                replay_contracts=result['optimizer_outputs'].get('replay_contracts') or [],
                registered_only=result['api_cards'].get('registered_only_api_cards') or [],
                dedup_report=result['optimizer_outputs'].get('dedup_report') or {},
                request_wrappers=result.get('request_wrappers') or [],
                project_profile=result.get('project_profile') or {},
                registered_only_policy=(result['optimizer_outputs'].get('dedup_report') or {}).get('registered_only_policy') or {},
                app_label=self.output_dir.name,
            ).write(out)
        write_text(out / 'summary.md', build_summary_md(result))
        post_step_errors: list[dict] = []

        def _record_post_error(step: str, exc: Exception) -> None:
            post_step_errors.append({
                'step': step,
                'error_type': type(exc).__name__,
                'message': str(exc)[:500],
            })

        try:
            from minidrifter.adapters.pack_resolver import write_adapter_resolution
            write_adapter_resolution(out)
        except Exception as exc:
            _record_post_error('write_adapter_resolution', exc)

        if self.root:
            try:
                from minidrifter.runtime.crypto.static_emit import emit_crypto_static_profile
                emit_crypto_static_profile(out, source_dir=self.root)
            except Exception as exc:
                _record_post_error('emit_crypto_static_profile', exc)

        try:
            from minidrifter.classification.api_plane_classifier import write_api_plane_index
            from minidrifter.orchestration.project_dashboard import write_project_dashboard

            write_api_plane_index(out)
            write_project_dashboard(out, project_name=self.output_dir.name)
        except Exception as exc:
            _record_post_error('api_plane_or_dashboard', exc)

        # Request facts + RCR (static contract recovery) — best-effort after cards exist.
        try:
            from minidrifter.request_facts.export import write_request_facts
            from minidrifter.rcr.export import write_rcr_pack
            write_request_facts(out, result=result)
            write_rcr_pack(out)
        except Exception as exc:
            _record_post_error('request_facts_or_ccr', exc)

        # RPGraph / Cross-API Business Credential Dependency Graph + workflows + drift plans (approach §2).
        try:
            from minidrifter.rpgraph.export import write_rpgraph_pack
            write_rpgraph_pack(out)
        except Exception as exc:
            _record_post_error('RPGraph', exc)

        # E1 RR-Drift Candidate Field/Relation export (C_i^bind + evidence relations).
        try:
            from minidrifter.rrdrift_candidate.recover import write_crbd_candidates
            write_crbd_candidates(out, appid=self.output_dir.name, app_src=self.root)
        except Exception as exc:
            _record_post_error('crbd_candidates', exc)

        # CRBD_validation/trace kit for legitimate capture intake (§3 prelude).
        try:
            from minidrifter.runtime_trace.prepare_kit import prepare_trace_kit
            project_root = self.root or out.parent
            prepare_trace_kit(project_root, pack_dir=out)
        except Exception as exc:
            _record_post_error('prepare_trace_kit', exc)

        try:
            from minidrifter.quality.runner import write_static_quality_report
            from minidrifter.quality.models import StaticIssue, QualityReport
            doc = write_static_quality_report(
                out,
                phase='post_analyze',
                resolutions_applied=[
                    'dual_pool_host_resolution',
                    'third_party_url_role',
                    'adapter_profile_autowrite',
                    'request_facts_ccr',
                ],
            )
            if post_step_errors:
                # Append visibility for previously silent failures.
                for err in post_step_errors:
                    (doc.setdefault('issues', [])).append({
                        'code': 'POST_ANALYZE_STEP_FAILED',
                        'class': 'EXECUTION_ADAPTER',
                        'severity': 'warning',
                        'message': f"post-analyze step failed: {err['step']}: {err['error_type']}: {err['message']}",
                        'artifact': err['step'],
                        'evidence': err,
                        'hint': 'Check traceback; analyze pack may still be usable',
                    })
                doc['issue_count'] = len(doc.get('issues') or [])
                doc['post_analyze_errors'] = post_step_errors
                write_json(out / 'static_quality_report.json', doc)
        except Exception as exc:
            write_json(out / 'post_analyze_errors.json', {
                'errors': post_step_errors + [{
                    'step': 'write_static_quality_report',
                    'error_type': type(exc).__name__,
                    'message': str(exc)[:500],
                }],
            })
