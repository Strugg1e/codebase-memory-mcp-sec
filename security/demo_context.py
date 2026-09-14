"""Exercise location handoff and views through the real MCP, using labelled fixtures.

This is a protocol/size regression, NOT a live CBM graph or model evaluation.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
from demo_flow import Client, require, sha

SOURCE = '''class Example {
  private String decorate(String value) {
    String copied = value;
    if (copied == null) return "fixed";
    return "prefix-" + copied;
  }
  void handle(String tenant, boolean flag) {
    String scope = decorate(tenant);
    if (flag) scope = unknownProvider();
    store(scope);
  }
}'''


def run(binary: Path, include_results: bool = False) -> dict:
    raw_source = SOURCE.encode()
    raw = json.dumps({'schema':'cbm.security-snapshot.v1','files':[
        {'path':'Example.java','source':SOURCE,'sha256':sha(raw_source)}]},
        ensure_ascii=False,separators=(',',':')).encode()
    snapshot = sha(raw)
    # These are fixture navigation fields. A live host must verify the CBM
    # generation against its pinned source manifest before passing its range.
    line = SOURCE[:SOURCE.index('store(scope)')].count('\n')+1
    navigation = {'file_path':'Example.java','start_line':line,'end_line':line}
    with tempfile.TemporaryDirectory(prefix='cbm-sec-context-') as work, tempfile.TemporaryFile() as errors:
        bundle=Path(work)/'snapshot.json'; bundle.write_bytes(raw); bundle.chmod(0o600)
        process=subprocess.Popen([str(binary),'--snapshot',str(bundle),'--expect-snapshot',snapshot],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=errors)
        try:
            client=Client(process)
            client.rpc('initialize',{'protocolVersion':'2025-11-25','capabilities':{},
                       'clientInfo':{'name':'cbm-sec-context-fixture','version':'1'}})
            client.send({'jsonrpc':'2.0','method':'notifications/initialized'})
            info=client.tool('get_snapshot_info',{})
            candidates=client.tool('resolve_code_location',{'snapshot_id':snapshot,
                'path':navigation['file_path'],'sha256':sha(raw_source),
                'start_line':navigation['start_line'],'end_line':navigation['end_line']})
            require(candidates['status']=='unique_candidate','Ambiguous fixture call location')
            require(not candidates['external_graph_verified'],'Graph provenance must not be inferred')
            anchor=candidates['candidates'][0]['operation_anchor']
            args={'snapshot_id':snapshot,**anchor}
            results={}
            for view in ('full','summary','values'):
                request={**args,'view':view}
                if view=='values': request['argument_index']=0
                results[view]=client.tool('inspect_operation_context',request)
            recovered=client.tool('inspect_operation_context',results['summary']['full_request']['arguments'])
            require(recovered==results['full'],'Compact view failed full-context round trip')
            for result in results.values():
                require(result['authorization_verdict']=='not_evaluated','Unexpected verdict')
                relation=result['arguments'][0]['local_value_flow']
                require(relation['derived_parameter_indices']==[0],'Derived source was lost')
                require('call_return_not_modeled' in relation['unknown_reasons'],'Unknown branch was lost')
            sizes={k:len(json.dumps(v,ensure_ascii=False,separators=(',',':')).encode()) for k,v in results.items()}
            stats=client.tool('get_snapshot_info',{})
            process.stdin.close(); process.wait(timeout=15)
            errors.seek(0)
            require(process.returncode==0,'MCP failed: '+errors.read(8192).decode('utf-8','replace'))
            result={'schema':'cbm.context-demo.v1','test_fixture':True,'live_cbm_used':False,
                'model_calls':0,'target_execution':False,'source_navigation':navigation,
                'product_capabilities':info['product_capabilities'],'view_bytes':sizes,
                'measurement_scope':'canonical_structured_content_utf8_bytes_not_tokens_or_total_workflow_cost',
                'full_round_trip_equal':True,'known_and_unknown_dependencies_preserved':True,
                'operation_counters':stats['operation_context']}
            if include_results: result['results']=results
            return result
        finally:
            if process.poll() is None:
                process.kill(); process.wait(timeout=5)
            if not process.stdin.closed:
                try: process.stdin.close()
                except BrokenPipeError: pass
            process.stdout.close()


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mcp',required=True,type=Path)
    p.add_argument('--include-results',action='store_true')
    args=p.parse_args()
    try:
        require(os.name=='posix','POSIX pipes are required')
        binary=args.mcp.resolve(strict=True)
        require(binary.is_file() and os.access(binary,os.X_OK),'MCP binary is not executable')
        print(json.dumps(run(binary,args.include_results),ensure_ascii=False,indent=2)); return 0
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:
        print('context_demo_failed: '+str(error),file=__import__('sys').stderr); return 2

if __name__=='__main__': raise SystemExit(main())
