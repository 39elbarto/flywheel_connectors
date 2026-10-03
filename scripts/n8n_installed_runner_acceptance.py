#!/usr/bin/env python3
"""One reviewed installed synthetic fixture; no fallback, cleanup or replay.

The operator must review this source and its pinned preparation before --run.
Tokens remain in memory; the existing approval helper alone handles its seed.
Execution items are read only for the newly created synthetic workflow.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

ROOT = Path('/srv/dev-ssd/fcp/nqm81-34')
PREP = ROOT / '20261003-installed-runner-preparation.json'
PREP_SHA = '8940d03e7000991736079a332a511a88c6f1a59ed763ee7856420e0b1357e047'
BIN = '/usr/local/lib/fwc-n8n/current/bin/fwc-n8n'
PARENT = '/srv/dev-ssd/fcp/targets/nqm81-cbor-helper-rc20/release/nqm81-cbor-helper'
PARENT_SHA = 'ae8be6b280f05bad439f00153fbb46ce13753a426444cbb424c2f41c33cfdf22'
HELPER = Path(__file__).with_name('n8n_approval_once.sh')
HELPER_SHA = '124374a22da7d2bebef6dbe3f7a69634be7ba046b43170e1dd0aee53a4de6616'
ISSUER = Path('/usr/local/sbin/fcp-n8n-approval-issue')
ISSUER_SHA = '48b8167603ffb98d10f9d8f53d981ec3e5031862bb3fc801901ce7866a340c4b'
REQUEST_ROOT = '/var/lib/fwc-n8n/approval-requests'
SAFE_CODES = frozenset(('unknown_outcome', 'official_mcp_plan_failed',
                       'invalid_operation_input', 'approval_required', 'invoke_failed',
                       'local_provider_failed', 'invalid_correlation_id'))
SAFE_CODES |= frozenset(('unsupported_platform', 'invalid_envelope', 'credential_empty',
    'credential_oversized', 'credential_invalid_utf8', 'credential_invalid_header',
    'envelope_encode_failed', 'envelope_too_large', 'bundle_invalid', 'credential_channel_failed',
    'request_cgroup_failed', 'supervisor_gate_failed', 'process_spawn_failed', 'stdin_unavailable',
    'stdout_unavailable', 'stderr_unavailable', 'credential_write_failed', 'stdin_write_failed',
    'output_read_failed', 'output_too_large', 'process_wait_failed', 'timeout', 'child_failed',
    'host_connector_not_found', 'host_invalid_input', 'host_preflight_denied',
    'host_connector_unavailable', 'host_connector_frame_limit', 'host_internal',
    'host_n8n_input_failed', 'host_n8n_config_failed', 'host_n8n_plan_failed',
    'host_n8n_credential_failed', 'host_n8n_policy_failed', 'host_n8n_runtime_state_failed',
    'host_n8n_manifest_failed', 'host_n8n_capability_failed', 'host_n8n_invoke_failed',
    'teardown_failed', 'process_group_present', 'io_worker_failed', 'output_empty',
    'output_invalid', 'output_trailing', 'official_mcp_catalog_blocked',
    'official_mcp_response_invalid', 'stale_precondition', 'readback_mismatch',
    'deadline_exceeded', 'invalid_deadline', 'bundle_unavailable', 'credential_broker_rejected',
    'credential_broker_unavailable', 'credential_broker_io_failed', 'credential_broker_protocol_failed',
    'credential_broker_response_invalid', 'credential_backend_failed', 'credential_invalid',
    'provider_unavailable', 'provider_unauthorized', 'provider_forbidden', 'provider_not_found',
    'provider_conflict', 'provider_rate_limited'))
SAFE_DIAGNOSTICS = frozenset(('execute_receipt_persist_failed', 'invoke_unknown',
    'validation_failed', 'provider_unauthorized', 'provider_forbidden', 'provider_not_found',
    'provider_conflict', 'provider_rate_limited', 'provider_unavailable',
    'external.mcp.discovery_jsonrpc_error', 'external.mcp.discovery_tool_result_error',
    'external.mcp.execute_call_jsonrpc_error', 'external.mcp.execute_call_tool_result_error',
    'owned.egress_stage.host_authorization_binding', 'owned.egress_stage.credential_lease',
    'owned.egress_stage.policy_preflight', 'owned.egress_stage.dns_resolution',
    'owned.egress_stage.tls_policy_validation', 'owned.egress_stage.outbound_transport',
    'owned.egress_stage.response_body_read', 'lifecycle_response_shape',
    'lifecycle_provider_field_mismatch', 'lifecycle_readback_precondition_mismatch',
    'lifecycle_provider_rejected', 'lifecycle_provider_status_rejected',
    'lifecycle_provider_error_field', 'lifecycle_provider_result_is_error',
    'lifecycle_provider_result_success_false', 'lifecycle_provider_result_error_field',
    'response_protocol', 'response_auth', 'response_rate_limited', 'response_capability',
    'response_zone', 'response_connector', 'response_resource', 'response_external_4xx',
    'response_external_5xx', 'response_external_other', 'response_external_unknown',
    'response_upstream_timeout', 'response_dependency_unavailable', 'response_internal',
    'child.protocol', 'child.auth', 'child.capability', 'child.zone', 'child.connector',
    'child.resource', 'child.external', 'child.internal', 'child.unknown'))
SAFE_ABORTS = frozenset(('clock_invalid', 'expiry_not_integer', 'expiry_not_13_digits',
    'expiry_stale', 'expiry_over_60s', 'invalid_request_file', 'issuer_unavailable',
    'secret_reader_unavailable', 'public_key_unavailable', 'request_unreadable',
    'request_busy', 'clock_failed', 'invalid_request_json', 'request_digest_failed',
    'safe_plan_mismatch', 'request_changed', 'issuer_failed', 'secret_reader_failed',
    'seed_decode_failed'))


def safe_uuid(value):
    try:
        return str(uuid.UUID(value)) if isinstance(value, str) else None
    except ValueError:
        return None


def diagnostic_projection(response):
    response = response if isinstance(response, dict) else {}
    code, detail = response.get('code'), response.get('diagnostic')
    rpc = response.get('rpcCode')
    return {'code': code if isinstance(code, str) and code in SAFE_CODES else 'other',
            'diagnostic': detail if isinstance(detail, str) and detail in SAFE_DIAGNOSTICS else 'other',
            'rpcPhase': response.get('rpcPhase') if response.get('rpcPhase') in
            ('discovery', 'execute_call') else None,
            'rpcCode': rpc if type(rpc) is int and -2147483648 <= rpc <= 2147483647 else None,
            'observedUUID': safe_uuid(response.get('correlationId', response.get('id')))}


def issuer_projection(stderr):
    codes = []
    for line in stderr.split(b'\n'):
        try:
            item = json.loads(line)
        except (ValueError, UnicodeError):
            continue
        if isinstance(item, dict) and item.get('schema') == 'fwc.n8n.approval-once.v1':
            code = item.get('abort_code')
            codes.append(code if isinstance(code, str) and code in SAFE_ABORTS else 'other')
    return codes


def stderr_projection(stderr):
    labels = []
    pattern = re.compile(rb'(?:FCP-N8N-HOST-ERROR-DETAIL/v1 (?:policy\.(?:approval|capability|deployment|network|lease|binding|decision|other)|host\.other)|FCP-N8N-INVOKE-DIAGNOSTIC/v1 (?:dispatch_(?:4xx|5xx|other)|response_(?:protocol|auth|rate_limited|capability|zone|connector|resource|external_(?:4xx|5xx|other|unknown)|upstream_timeout|dependency_unavailable|internal)))')
    for line in stderr.split(b'\n'):
        if pattern.fullmatch(line):
            labels.append(line.decode('ascii'))
    return labels[:32]


def encode(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()


def require(condition, label):
    if not condition:
        raise RuntimeError(label)


def pinned(path, digest):
    data = Path(path).read_bytes()
    require(hashlib.sha256(data).hexdigest() == digest, 'source_pin_mismatch')
    return data


def save(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(encode(value) + b'\n')
        out.flush()
        os.fsync(out.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def safe_fixture(graph, python):
    nodes = graph['nodes']
    require(len(nodes) == (3 if python else 2), 'fixture_node_count')
    require([n['type'] for n in nodes] ==
            ['n8n-nodes-base.manualTrigger'] + ['n8n-nodes-base.code'] * (len(nodes) - 1),
            'fixture_node_types')
    require(all(not n.get('credentials') and not n.get('disabled') for n in nodes),
            'fixture_credentials_or_disabled')
    require(graph['settings']['availableInMCP'] is False, 'fixture_initial_mcp')
    require(nodes[1]['parameters']['language'] == 'javaScript', 'fixture_js')
    if python:
        require(nodes[2]['parameters']['language'] == 'pythonNative', 'fixture_python')


def checked_plan(plan, workflow, server):
    require(not plan['exceptions'] and not plan['changed'] and
            len(plan['planned']) + len(plan['skipped']) == 1, 'mcp_plan_scope')
    item = (plan['planned'] + plan['skipped'])[0]
    require(item['id'] == workflow and item['desired'] is True and
            type(item['availableInMCP']) is bool, 'mcp_plan_binding')
    available = item['availableInMCP']
    require((not available and len(plan['planned']) == 1 and item['reason'] == 'requires_change') or
            (available and len(plan['skipped']) == 1 and item['reason'] == 'already_desired'),
            'mcp_plan_reason')
    require(re.fullmatch('blake3-256:[a-f0-9]{64}', plan['readbackDigest']), 'mcp_plan_digest')
    receipt = plan['receipt']
    require(receipt['schema'] == 'fwc.n8n.mcp-access-receipt.v1' and
            receipt['operation'] == 'n8n.mcp_access.reconcile' and receipt['serverId'] == server and
            receipt['scope'] == 'workflow_ids' and receipt['desired'] is True and
            receipt['dryRun'] is True and receipt['status'] == 'planned' and
            receipt['readbackDigest'] == plan['readbackDigest'] and len(receipt['items']) == 1 and
            receipt['items'][0]['desired'] is True and
            receipt['items'][0]['availableInMCP'] is available, 'mcp_plan_receipt')
    return available


def execute_provider_binding(server, value):
    # Exact serialization of the existing fcp-host producer:
    # build_n8n_official_mcp_run_once_plan + mcp_tools_call_payload_digest.
    # Its retained native host-builder golden digest is checked below.
    arguments = {'workflowId': value['id'], 'executionMode': value['mode']}
    for key in ('triggerNodeName', 'inputs'):
        if key in value:
            arguments[key] = value[key]
    payload = {'name': 'execute_workflow', 'arguments': arguments}
    digest = hashlib.sha256(b'FCP/MCP-Bridge/approval-payload/v1\0' + encode(payload)).hexdigest()
    return ('execute_workflow', f'fwc-mcp-bridge://{server}/tools/execute%5Fworkflow',
            'sha256:' + digest)


def lifecycle_provider_binding(server, value):
    # Existing host11827..11855 producer; no guard/state fields in MCP payload.
    require(value.get('action') in ('publish', 'unpublish'), 'lifecycle_action')
    arguments = {'workflowId': value['id']}
    if value['action'] == 'publish':
        require(isinstance(value.get('versionId'), str) and bool(value['versionId']),
                'publish_version_required')
        arguments['versionId'] = value['versionId']
    else:
        require('versionId' not in value, 'unpublish_version_forbidden')
    tool = value['action'] + '_workflow'
    payload = {'name': tool, 'arguments': arguments}
    digest = hashlib.sha256(b'FCP/MCP-Bridge/approval-payload/v1\0' + encode(payload)).hexdigest()
    segment = ''.join(chr(b) if (48 <= b <= 57 or 65 <= b <= 90 or 97 <= b <= 122)
                      else f'%{b:02X}' for b in tool.encode())
    return tool, f'fwc-mcp-bridge://{server}/tools/{segment}', 'sha256:' + digest


def approval_request(server, operation, value, workflow, expires):
    names = {'n8n.workflows.create_draft': 'create_draft',
             'n8n.mcp_access.reconcile': 'mcp_access_reconcile',
             'n8n.workflows.execute': 'execute'}
    if operation == 'n8n.workflows.lifecycle':
        require(value.get('action') in ('publish', 'unpublish'), 'lifecycle_action')
        names[operation] = value['action']
    require(operation in names, 'approval_operation')
    require(server in ('eec', 'hetzner'), 'approval_server')
    if operation == 'n8n.workflows.execute':
        require(value['guard']['inputClass'] == ('bounded_json' if 'inputs' in value else 'none'),
                'execute_input_class')
    direct = operation in ('n8n.workflows.create_draft', 'n8n.mcp_access.reconcile')
    target_workflow = '' if direct else workflow
    segment = ''.join(chr(b) if (48 <= b <= 57 or 65 <= b <= 90 or 97 <= b <= 122)
                      else f'%{b:02X}' for b in workflow.encode())
    uri = f'fwc-n8n://{server}' if direct else f'fwc-n8n://{server}/workflows/{segment}'
    pinned(PARENT, PARENT_SHA)
    argv = [PARENT, server, uri, operation, encode(value).decode()]
    p = subprocess.run(argv, capture_output=True, timeout=5)
    binding = p.stdout.decode().strip()
    require(p.returncode == 0 and re.fullmatch('[a-f0-9]{64}', binding), 'parent_binding')
    tool, resource, payload = (('', '', '') if direct else
                              lifecycle_provider_binding(server, value)
                              if operation == 'n8n.workflows.lifecycle' else
                              execute_provider_binding(server, value))
    return {'schema': 'fwc.n8n.owner-approval-request.v1', 'server': server,
            'workflow_id': target_workflow, 'operation': names[operation], 'input': value,
            'official_mcp_tool': tool, 'official_mcp_resource_uri': resource,
            'official_mcp_payload_digest': payload, 'parent_binding_sha256': binding,
            'expires_at_ms': expires}


def check_execution(value, workflow, version):
    require(value['workflowId'] == workflow and value['workflowVersionId'] == version,
            'execution_binding')
    require(value['mode'] == 'manual' and value['status'] == 'success' and
            value['finished'] is True, 'execution_not_terminal_success')


def wait_execution(once, execution, workflow, version, clock=time.monotonic, sleep=time.sleep):
    deadline = clock() + 60
    for index in range(20):
        remaining = deadline - clock()
        require(remaining > 0, 'execution_wait_timeout')
        value = once.call('n8n.executions.get', {'id': execution, 'workflow_id': workflow},
                          budget_ms=min(5000, max(1, int(remaining * 1000))))
        require(clock() <= deadline, 'execution_wait_timeout')
        require(value.get('id') == execution and value.get('workflowId') == workflow and
                value.get('workflowVersionId') == version and value.get('mode') == 'manual',
                'execution_binding')
        require(value.get('status') not in ('error', 'canceled', 'crashed'), 'execution_failed')
        if value.get('status') == 'success':
            check_execution(value, workflow, version)
            return value
        require(value.get('status') in ('new', 'running', 'waiting') and
                value.get('finished') is False, 'execution_unknown_state')
        remaining = deadline - clock()
        if index < 19 and remaining > 0:
            sleep(min(1, remaining))
    raise RuntimeError('execution_wait_count_exhausted')


def flat_execute_result(response, value):
    fields = {'status', 'operation', 'provider', 'workflowId', 'mode', 'versionId',
              'executionId', 'initialStatus', 'executionStatus', 'retry', 'readback'}
    require(isinstance(response, dict) and set(response) == fields,
            'execute_flat_shape')
    require(response['operation'] == 'n8n.workflows.execute' and
            response['provider'] == 'official_mcp' and response['workflowId'] == value['id'] and
            response['versionId'] == value['versionId'] and response['mode'] == value['mode'] and
            response['mode'] == 'manual' and response['initialStatus'] == 'accepted' and
            response['retry'] == 'never_automatic' and
            response['readback'] == 'independent_execution_get', 'execute_flat_binding')
    require(response['status'] in ('verified', 'unknown', 'failed') and
            response['executionStatus'] in (None, 'new', 'running', 'waiting', 'success',
                                           'error', 'canceled', 'crashed'), 'execute_flat_status')
    require(isinstance(response['executionId'], str) and
            re.fullmatch('[0-9]+', response['executionId']), 'execution_id_missing')
    return response


def flat_lifecycle_result(response, value):
    require(isinstance(response, dict) and set(response) ==
            {'status', 'operation', 'action', 'provider', 'retry', 'readback', 'before', 'after'},
            'lifecycle_flat_shape')
    require(response['status'] == 'verified' and
            response['operation'] == 'n8n.workflows.lifecycle' and
            response['action'] == value['action'] and value['action'] in ('publish', 'unpublish') and
            response['provider'] == 'official_mcp' and response['retry'] == 'never_automatic' and
            response['readback'] == 'independent_get', 'lifecycle_flat_binding')
    before, after = response['before'], response['after']
    state_fields = {'id', 'versionId', 'activeVersionId', 'active', 'isArchived',
                    'stateDigest', 'draft', 'published'}
    for state in (before, after):
        require(isinstance(state, dict) and state_fields <= set(state) and
                set(state) <= state_fields | {'name', 'folderId', 'projectId', 'updatedAt'},
                'lifecycle_state_shape')
        require(all(state.get(k) is None or isinstance(state[k], str)
                    for k in ('name', 'folderId', 'projectId', 'updatedAt')),
                'lifecycle_metadata_shape')
        require(state['id'] == value['id'] and isinstance(state['versionId'], str) and
                bool(state['versionId']) and type(state['active']) is bool and
                type(state['isArchived']) is bool and isinstance(state['stateDigest'], str) and
                re.fullmatch(r'blake3-256:[a-f0-9]{64}', state['stateDigest']) and
                (state['activeVersionId'] is None or
                 isinstance(state['activeVersionId'], str) and bool(state['activeVersionId'])),
                'lifecycle_state_binding')
        for name in ('draft', 'published'):
            graph = state[name]
            if name == 'published' and graph is None:
                continue
            require(isinstance(graph, dict) and set(graph) == {'versionId', 'graphDigest'} and
                    isinstance(graph['versionId'], str) and bool(graph['versionId']) and
                    isinstance(graph['graphDigest'], str) and
                    re.fullmatch(r'blake3-256:[a-f0-9]{64}', graph['graphDigest']),
                    'lifecycle_graph_shape')
    precondition = value['guard']['precondition']
    require(all(before[key] == precondition[key] for key in
                ('versionId', 'activeVersionId', 'active', 'isArchived', 'stateDigest')) and
            after['versionId'] == before['versionId'] and after['draft'] == before['draft'],
            'lifecycle_precondition_or_draft_changed')
    if value['action'] == 'publish':
        require(after['active'] is True and after['isArchived'] is False and
                after['activeVersionId'] == value['versionId'] and
                after['published'] is not None and
                after['published']['versionId'] == value['versionId'], 'lifecycle_publish_readback')
    else:
        require(after['active'] is False and after['activeVersionId'] is None and
                after['published'] is None and after['isArchived'] == before['isArchived'],
                'lifecycle_unpublish_readback')
    # Receipt retains only validated state controls, never names or other metadata.
    return dict(response, before={k: before[k] for k in state_fields},
                after={k: after[k] for k in state_fields})


def installed_state(server):
    host = 'eec-contabo' if server == 'eec' else 'hetzner-main'
    app = ('617e247c3268c30ddb96bdd0581814a7fb6f588e6f94796d18a5f7ea061bc16b'
           if server == 'eec' else
           'f7ab855a2c59212effdd614a074233039852d90a9b4a4f92b7021e5448c639f5')
    image = ('sha256:e73e3048c6ce10ae72617a5bab2bb837f4fe7258f094da043ccc85495bd37014'
             if server == 'eec' else
             'sha256:ebc538b77c489a512c6392fa5b0fa53c109a71078369b3cdaa8619b115f16e45')
    code = '''import subprocess,json
app,image,external=ARGS
p=subprocess.run(['docker','inspect',app],capture_output=True,timeout=10);assert p.returncode==0
x=json.loads(p.stdout)[0];assert x['Id']==app and x['Image']==image and x['State']['Running'] and x['RestartCount']==0
e=dict(v.split('=',1) for v in x['Config']['Env'])
out={'app_id':app,'image':image,'running':True,'restarts':0,'external':external}
if external:
 assert e.get('N8N_RUNNERS_MODE')=='external' and e.get('N8N_RUNNERS_ENABLED')=='true' and e.get('N8N_NATIVE_PYTHON_RUNNER')=='true'
 runner='4e7ea2a720a4fe961f28f03566f5a7c1492eb6c44d986554816b04c07df96815'
 p=subprocess.run(['docker','inspect',runner],capture_output=True,timeout=10);assert p.returncode==0
 r=json.loads(p.stdout)[0];assert r['Id']==runner and r['Image']=='sha256:4681689b452b379420c3054a7ddefc8e0bea65c5c8bc6353813665d03d8979b1' and r['State']['Running'] and r['RestartCount']==0
 out['runner_id']=runner
print(json.dumps(out))
'''
    code = 'ARGS=' + repr((app, image, server == 'hetzner')) + '\n' + code
    p = subprocess.run(['ssh', host, 'python3 -'], input=code.encode(),
                       capture_output=True, timeout=30)
    require(p.returncode == 0, 'installed_identity_or_configuration')
    return json.loads(p.stdout)


def node_outputs(server, workflow, execution):
    require(re.fullmatch('[A-Za-z0-9_-]+', workflow) and
            re.fullmatch('[0-9]+', execution), 'output_read_identity')
    # The query is limited to the new fixture and execution. Credentials stay
    # inside the existing server/PG contour. Raw rows never cross SSH stdout.
    remote = r'''import json,subprocess,re,sys
server,workflow,execution=ARGS
app,pg,expected_image=(
 ('617e247c3268c30ddb96bdd0581814a7fb6f588e6f94796d18a5f7ea061bc16b','b62887d41daf5baefc812c2b3eba44a3601bb81369921cdf3af2e83f9d16640e','sha256:e73e3048c6ce10ae72617a5bab2bb837f4fe7258f094da043ccc85495bd37014') if server=='eec' else
 ('f7ab855a2c59212effdd614a074233039852d90a9b4a4f92b7021e5448c639f5','d5058bc3945de4a50259c7cf6fe545240d317292c2b2b1564a4f6a3bc9dc609c','sha256:ebc538b77c489a512c6392fa5b0fa53c109a71078369b3cdaa8619b115f16e45'))
p=subprocess.run(['docker','inspect',app],capture_output=True,timeout=10);assert p.returncode==0
state=json.loads(p.stdout)[0];assert state['Id']==app and state['Image']==expected_image and state['State']['Running']
env=dict(z.split('=',1) for z in state['Config']['Env']);schema=env.get('DB_POSTGRESDB_SCHEMA','public');prefix=env.get('DB_TABLE_PREFIX','')
assert re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',schema) and re.fullmatch('[A-Za-z0-9_]*',prefix)
if server=='hetzner':assert env.get('N8N_RUNNERS_MODE')=='external' and env.get('N8N_RUNNERS_ENABLED')=='true' and env.get('N8N_NATIVE_PYTHON_RUNNER')=='true'
sql=''' + '"""' + r'''BEGIN READ ONLY; SET LOCAL statement_timeout=5000;
SELECT d.data FROM :"schema".:"data_table" d JOIN :"schema".:"entity_table" e ON e.id=d."executionId"
WHERE e.id=:'execution_id' AND e."workflowId"=:'workflow_id' AND octet_length(d.data)<=1048576; COMMIT;
''' + '"""' + r'''
argv=['docker','exec','-i',pg,'sh','-c','exec psql -X -qAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" "$@"','sh','-v','schema='+schema,'-v','data_table='+prefix+'execution_data','-v','entity_table='+prefix+'execution_entity','-v','execution_id='+execution,'-v','workflow_id='+workflow]
p=subprocess.run(argv,input=sql.encode(),capture_output=True,timeout=10);assert p.returncode==0 and 0<len(p.stdout)<=1048577
node=r''' + '"""' + r'''const a=require('assert');let b='';process.stdin.setEncoding('utf8');process.stdin.on('data',c=>{b+=c;if(b.length>1048577)throw Error('bounded');});process.stdin.on('end',()=>{const f=require(require.resolve('flatted',{paths:['/usr/local/lib/node_modules/n8n']}));const d=f.parse(b.trim());const r=d.resultData.runData;let expected={'Compute JS answer 42':42};if(process.argv[1]==='hetzner')expected['Compute Python answer 43']=43;for(const [name,n] of Object.entries(expected)){a.equal(r[name].length,1);a.equal(r[name][0].data.main.length,1);a.equal(r[name][0].data.main[0].length,1);a.deepEqual(r[name][0].data.main[0][0].json,{fixture:'installed-runner-20261003',answer:n});}console.log(JSON.stringify({exact_synthetic_outputs:true,node_count:Object.keys(expected).length,provider_calls:false}));});
''' + '"""' + r'''
p=subprocess.run(['docker','exec','-i',app,'node','-e',node,server],input=p.stdout,capture_output=True,timeout=10);assert p.returncode==0
print(p.stdout.decode(),end='')
'''
    remote = 'ARGS=' + repr((server, workflow, execution)) + '\n' + remote
    host = 'eec-contabo' if server == 'eec' else 'hetzner-main'
    p = subprocess.run(['ssh', host, 'python3 -'], input=remote.encode(),
                       capture_output=True, timeout=45)
    require(p.returncode == 0, 'synthetic_node_readback')
    result = json.loads(p.stdout)
    require(result['exact_synthetic_outputs'] is True, 'synthetic_node_output_mismatch')
    return result


class Once:
    def __init__(self, server, folder):
        self.server, self.folder = server, folder
        self.counter = 0
        self.workflow = None
        self.phase = 'preflight'
        self.execution = None

    def call(self, operation, value, token=None, budget_ms=30000):
        self.counter += 1
        request = {'server_id': self.server, 'input': value,
                   'deadline_ms': budget_ms, 'correlation_id': str(uuid.uuid4())}
        if token is not None:
            request['approval_token'] = token
        receipt = {'phase': self.phase, 'operation': operation,
                   'requestedUUID': request['correlation_id'],
                   'argv': [BIN, 'run-once', operation], 'budget_ms': budget_ms,
                   'raw_bodies_retained': False}
        try:
            p = subprocess.run([BIN, 'run-once', operation], input=encode(request),
                               capture_output=True, timeout=budget_ms / 1000 + 1)
        except subprocess.TimeoutExpired:
            save(self.folder / f'{self.counter:02d}-call.json',
                 dict(receipt, outcome='UNKNOWN_timeout', exit=None))
            raise RuntimeError('invoke_timeout_unknown') from None
        try:
            response = json.loads(p.stdout)
        except (ValueError, UnicodeError):
            response = None
        save(self.folder / f'{self.counter:02d}-call.json',
             dict(receipt, exit=p.returncode,
              outcome='received' if isinstance(response, dict) else 'UNKNOWN_malformed',
              diagnostic=diagnostic_projection(response),
              stderr_labels=stderr_projection(p.stderr),
              response_sha256=hashlib.sha256(p.stdout).hexdigest(),
              stderr_bytes=len(p.stderr)))
        require(isinstance(response, dict), 'response_malformed_unknown')
        if operation == 'n8n.workflows.execute':
            result = flat_execute_result(response, value)
            self.execution = result['executionId']
            save(self.folder / f'{self.counter:02d}-execute-handle.json', result)
            require(p.returncode == 0, 'invoke_failed_or_unknown')
            return result
        if operation == 'n8n.workflows.lifecycle':
            require(p.returncode == 0, 'invoke_failed_or_unknown')
            result = flat_lifecycle_result(response, value)
            save(self.folder / f'{self.counter:02d}-lifecycle-readback.json', result)
            return result
        require(p.returncode == 0, 'invoke_failed_or_unknown')
        require(response.get('type') == 'response' and response.get('status') == 'ok',
                'response_failed_or_unknown')
        result = response['result']
        require(isinstance(result, dict), 'result_not_object')
        return result

    def write(self, phase, operation, value, workflow):
        self.phase = phase
        # Durable claim prevents an accidental second invocation, including
        # when issuance or delivery failed. A new run is not a retry authority.
        save(self.folder / f'claim-{phase}.json',
             {'operation': operation, 'workflow': workflow,
              'input_sha256': hashlib.sha256(encode(value)).hexdigest(),
              'claim': 'invoke_may_start_once'})
        request = approval_request(self.server, operation, value, workflow,
                                   int(time.time() * 1000) + 45000)
        basename = 'installed-runner-' + str(uuid.uuid4()) + '.json'
        # Only root-owned O_EXCL requests; no mutable privileged script path.
        placement = '''import os,sys,stat
root='/var/lib/fwc-n8n/approval-requests'
s=os.lstat(root);assert stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700
assert os.path.realpath(root)==root
b=sys.stdin.buffer.read(65537);assert 0<len(b)<=65536
p=root+'/'+sys.argv[1];fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
'''
        p = subprocess.run(['sudo', '-n', '/usr/bin/python3', '-c', placement, basename],
                           input=encode(request), capture_output=True, timeout=5)
        require(p.returncode == 0, 'approval_request_placement')
        helper = pinned(HELPER, HELPER_SHA)
        pinned(ISSUER, ISSUER_SHA)
        # Existing helper's FD3 is an anonymous stdout pipe; seed bytes never
        # enter this controller, a variable, an environment or a file.
        try:
            p = subprocess.run(['sudo', '-n', '/usr/bin/env', '-i',
                            'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'HOME=/home/ubuntu',
                            'LC_ALL=C', '/usr/bin/bash', '-c',
                            'exec 3>&1; exec 1>/dev/null; exec /usr/bin/bash -s -- --request-file "$1"',
                            'sh', basename], input=helper, capture_output=True, timeout=35)
        except subprocess.TimeoutExpired:
            save(self.folder / f'issuer-{phase}.json',
                 {'phase': phase, 'operation': operation, 'outcome': 'UNKNOWN_timeout',
                  'request_basename': basename, 'token_retained': False})
            raise RuntimeError('approval_timeout_unknown') from None
        save(self.folder / f'issuer-{phase}.json',
             {'phase': phase, 'operation': operation, 'exit': p.returncode,
              'issuerabort_code': issuer_projection(p.stderr), 'stderr_bytes': len(p.stderr),
              'request_basename': basename, 'TTL_ms': 45000, 'token_retained': False})
        require(p.returncode == 0 and 0 < len(p.stdout) <= 131072, 'approval_issuance')
        try:
            token = json.loads(p.stdout)
        except (ValueError, UnicodeError):
            save(self.folder / f'issuer-{phase}-malformed.json',
                 {'phase': phase, 'operation': operation, 'outcome': 'UNKNOWN_malformed'})
            raise RuntimeError('approval_malformed_unknown') from None
        return self.call(operation, value, token)


def run(server):
    packet = json.loads(pinned(PREP, PREP_SHA))
    selected = next(g for g in packet['graphs'] if g['server'] == server)
    safe_fixture(selected['graph'], server == 'hetzner')
    folder = ROOT / ('installed-runner-live-20261003-' + server)
    folder.mkdir(mode=0o700)
    once = Once(server, folder)
    try:
        state = installed_state(server)
        save(folder / 'installed-state.json', state)
        # Public current verification is prerequisite to any approval or write.
        p = subprocess.run([BIN, 'verify-current'], capture_output=True, timeout=10)
        require(p.returncode == 0, 'installed_bundle_unverified')
        created = once.write('create', 'n8n.workflows.create_draft', selected['create_input'], '')
        require(created.get('status') == 'verified', 'create_not_verified')
        workflow = created['id']
        require(re.fullmatch('[A-Za-z0-9_-]+', workflow), 'created_id')
        once.workflow = workflow
        baseline = once.call('n8n.workflows.get', {'id': workflow})
        require(baseline['versionId'] == created['versionId'] and
                baseline['draft']['graphDigest'] == created['graphDigest'] and
                baseline['active'] is False and baseline['activeVersionId'] is None and
                baseline['isArchived'] is False, 'created_graph_readback')
        save(folder / 'created-baseline.json', baseline)
        reconcile = {'scope': 'workflow_ids', 'workflowIds': [workflow],
                     'desired': True, 'dryRun': True}
        plan = once.call('n8n.mcp_access.reconcile', reconcile)
        save(folder / 'mcp-plan.json', plan)
        available = checked_plan(plan, workflow, server)
        if not available:
            apply = dict(reconcile, dryRun=False, guard={
                'approvalRef': 'installed-runner-mcp-' + str(uuid.uuid4()),
                'dryRunDigest': plan['readbackDigest'], 'idempotencyKey': str(uuid.uuid4())})
            applied = once.write('mcp', 'n8n.mcp_access.reconcile', apply, workflow)
            require(applied['receipt']['status'] == 'applied', 'mcp_apply_unknown')
        readback = once.call('n8n.mcp_access.reconcile', reconcile)
        require(checked_plan(readback, workflow, server), 'mcp_readback_false')
        fresh = once.call('n8n.workflows.get', {'id': workflow})
        require(fresh['versionId'] == baseline['versionId'] and
                fresh['draft']['graphDigest'] == baseline['draft']['graphDigest'] and
                fresh['active'] is False and fresh['isArchived'] is False and
                fresh['activeVersionId'] is None, 'preexecution_graph_changed')
        value = {'id': workflow, 'mode': 'manual', 'versionId': fresh['versionId'],
                 'triggerNodeName': 'Run synthetic runner check', 'guard': {
                     'approvalRef': 'installed-runner-execute-' + str(uuid.uuid4()),
                     'idempotencyKey': str(uuid.uuid4()), 'precondition': {
                         'versionId': fresh['versionId'], 'activeVersionId': None,
                         'active': False, 'isArchived': False, 'stateDigest': fresh['stateDigest']},
                     'inputClass': 'none',
                     'sideEffectSummary': 'Synthetic arithmetic only; no credentials, recipients, webhook, schedules or external actions'}}
        executed = once.write('execute', 'n8n.workflows.execute', value, workflow)
        execution = executed.get('executionId')
        require(isinstance(execution, str) and re.fullmatch('[0-9]+', execution), 'execution_id_missing')
        once.execution = execution
        save(folder / 'execute-known-id.json',
             {'executionId': execution, 'expected_workflowId': workflow,
              'expected_versionId': fresh['versionId'], 'expected_mode': 'manual',
              'status': executed.get('status') if executed.get('status') in
              ('verified', 'unknown', 'failed') else 'other'})
        require(executed.get('workflowId') == workflow and
                executed.get('versionId') == fresh['versionId'] and
                executed.get('mode') == 'manual', 'execution_invoke_binding')
        require(executed.get('status') in ('verified', 'unknown') and
                executed.get('executionStatus') not in ('error', 'canceled', 'crashed'),
                'execution_invoke_failed')
        if executed['status'] == 'verified':
            require(executed.get('executionStatus') == 'success', 'verified_execute_not_success')
            once.phase = 'verified_execution_readback'
            observed = once.call('n8n.executions.get',
                                 {'id': execution, 'workflow_id': workflow})
            require(observed.get('id') == execution, 'execution_readback_id')
            check_execution(observed, workflow, fresh['versionId'])
        else:
            require(executed.get('executionStatus') in (None, 'new', 'running', 'waiting'),
                    'unknown_execute_not_nonterminal')
            once.phase = 'execution_wait'
            observed = wait_execution(once, execution, workflow, fresh['versionId'],
                                      clock=time.monotonic, sleep=time.sleep)
        outputs = node_outputs(server, workflow, execution)
        final = once.call('n8n.workflows.get', {'id': workflow})
        require(final['versionId'] == fresh['versionId'] and final['active'] is False and
                final['draft']['graphDigest'] == fresh['draft']['graphDigest'], 'final_workflow_changed')
        save(folder / 'public-proof.json',
             {'status': 'installed_synthetic_execution_verified',
              'server': server, 'workflow': workflow, 'versionId': baseline['versionId'],
              'fixture_retained': True, 'execution_attempts': 1, 'executionId': execution,
              'execution_readback': observed, 'node_outputs': outputs, 'installed_state': state,
              'business_or_provider_calls': False, 'plan_sha256': hashlib.sha256(encode(plan)).hexdigest()})
    except Exception as error:
        # Only a single exact workflow readback after an uncertain mutation;
        # never invoke again, cancel, delete or claim it did not happen.
        if once.workflow:
            try:
                state = once.call('n8n.workflows.get', {'id': once.workflow})
                save(folder / 'stop-state-observation.json', state)
            except Exception as observation_error:
                save(folder / 'stop-state-observation-failed.json',
                     {'status': 'UNKNOWN', 'exception_class': type(observation_error).__name__,
                      'raw_error_body_retained': False})
        save(folder / 'public-proof.json',
             {'status': 'STOP', 'exception_class': type(error).__name__,
              'known_workflow': once.workflow, 'automatic_retry': False,
              'phase': once.phase, 'known_execution': once.execution,
              'raw_error_body_retained': False})
        raise RuntimeError('installed_runner_stopped') from None
    print(json.dumps({'proof': str(folder / 'public-proof.json'), 'execution_attempts': 1}))


def publication_graph(server):
    require(server in ('eec', 'hetzner'), 'publication_server')
    webhook = {'eec': '8c186456-980d-4937-a352-34aa7700ab45',
               'hetzner': '35c75bf4-eacc-4d70-846b-2767b72e644e'}[server]
    return {'nodes': [{'id': 'harmless-webhook', 'name': 'Disconnected publication trigger',
             'type': 'n8n-nodes-base.webhook', 'typeVersion': 2,
             'position': [0, 0], 'webhookId': webhook, 'parameters': {
                 'httpMethod': 'POST', 'path': 'fcp-rc43-publish-' + server + '-' + webhook,
                 'authentication': 'none', 'responseMode': 'onReceived', 'options': {}}}],
            'connections': {}, 'settings': {'executionOrder': 'v1', 'availableInMCP': False}}


def publication_eligibility(graph, server):
    # Exact reviewed literal graph; deny extra nodes/connections/credentials,
    # schedules, URLs, commands, Code, receivers or any changed parameter.
    require(graph == publication_graph(server), 'publication_graph_not_exact')
    return {'types': ['n8n-nodes-base.webhook'], 'method': 'POST',
            'disconnected': True, 'credentials_or_external_actions': False,
            'schedule_or_execute_or_direct_webhook_call': False,
            'graph_sha256': hashlib.sha256(encode(graph)).hexdigest(),
            'activation_trigger_type': 'webhook', 'provider_publishability': 'UNVERIFIED'}


def publish_check(server):
    """One approved new disconnected Webhook draft, publish/unpublish pair.

    No execute, direct webhook call, mutation retry or cleanup.
    Requires admitted RC43 to be actually signed and current first.
    """
    graph = publication_graph(server)
    eligibility = publication_eligibility(graph, server)
    folder = ROOT / ('controlled-webhook-publish-unpublish-rc43-once-' + server)
    folder.mkdir(mode=0o700)
    once = Once(server, folder)
    workflow = version = baseline = None
    fields = ('id', 'versionId', 'activeVersionId', 'active', 'isArchived',
              'stateDigest', 'draft', 'published')
    try:
        state = installed_state(server)
        save(folder / 'installed-state.json', state)
        p = subprocess.run([BIN, 'verify-current'], capture_output=True, timeout=10)
        require(p.returncode == 0, 'installed_bundle_unverified')
        current = json.loads(p.stdout)
        require(current['status'] == 'verified' and
                current['proof']['validation_mode'] == 'signed_current' and
                current['proof']['owner_key_id'] == '8e7a0ab7f8435586' and
                current['proof']['release_id'] == 'release-20261003-37936e82d-publish-reasons-rc43' and
                re.fullmatch('[a-f0-9]{64}', current['proof']['provision_receipt_blake3']),
                'publish_requires_signed_current_rc43')
        save(folder / 'current-verification.json', {'status': 'verified', 'proof': {
            k: current['proof'][k] for k in ('validation_mode', 'owner_key_id',
                                            'release_id', 'provision_receipt_blake3')}})
        save(folder / 'eligibility.json', eligibility)
        create = {'name': 'FWC harmless disconnected publication RC43 ' + server,
                  'graph': graph, 'guard': {
                      'approvalRef': 'synthetic-publication-create-' + str(uuid.uuid4()),
                      'idempotencyKey': str(uuid.uuid4()), 'precondition': {}}}
        created = once.write('create', 'n8n.workflows.create_draft', create, '')
        candidate = created.get('id')
        if isinstance(candidate, str) and re.fullmatch('[A-Za-z0-9_-]{1,256}', candidate):
            workflow = once.workflow = candidate
        require(created.get('status') == 'verified' and workflow is not None and
                isinstance(created.get('versionId'), str) and
                re.fullmatch('[A-Za-z0-9_-]{1,256}', created['versionId']) and
                isinstance(created.get('graphDigest'), str) and
                re.fullmatch(r'blake3-256:[a-f0-9]{64}', created['graphDigest']),
                'publication_create_not_verified')
        version = created['versionId']
        save(folder / 'created-handle.json', {'id': workflow, 'versionId': version,
                                             'graphDigest': created['graphDigest']})
        once.phase = 'publish_prestate'
        fresh = once.call('n8n.workflows.get', {'id': workflow})
        require(fresh['id'] == workflow and fresh['versionId'] == version and
                fresh['draft'] == {'versionId': version, 'graphDigest': created['graphDigest']} and
                fresh['active'] is False and
                fresh['activeVersionId'] is None and fresh['published'] is None and
                fresh['isArchived'] is False and isinstance(fresh.get('stateDigest'), str) and
                re.fullmatch(r'blake3-256:[a-f0-9]{64}', fresh['stateDigest']),
                'publish_fixture_changed')
        save(folder / 'prestate.json', {k: fresh[k] for k in fields})
        baseline = fresh
        reconcile = {'scope': 'workflow_ids', 'workflowIds': [workflow],
                     'desired': True, 'dryRun': True}
        once.phase = 'publication_mcp_dryrun'
        plan = once.call('n8n.mcp_access.reconcile', reconcile)
        save(folder / 'mcp-plan.json', plan)
        if not checked_plan(plan, workflow, server):
            apply = dict(reconcile, dryRun=False, guard={
                'approvalRef': 'synthetic-publication-mcp-' + str(uuid.uuid4()),
                'dryRunDigest': plan['readbackDigest'], 'idempotencyKey': str(uuid.uuid4())})
            applied = once.write('mcp', 'n8n.mcp_access.reconcile', apply, workflow)
            require(applied['receipt']['status'] == 'applied', 'publication_mcp_apply_unknown')
        once.phase = 'publication_mcp_readback'
        readback = once.call('n8n.mcp_access.reconcile', reconcile)
        require(checked_plan(readback, workflow, server), 'publication_mcp_unavailable')
        fresh = once.call('n8n.workflows.get', {'id': workflow})
        require(fresh['id'] == workflow and fresh['versionId'] == version and
                fresh['draft'] == baseline['draft'] and fresh['active'] is False and
                fresh['isArchived'] is False and fresh['activeVersionId'] is None and
                fresh['published'] is None and isinstance(fresh.get('stateDigest'), str) and
                re.fullmatch(r'blake3-256:[a-f0-9]{64}', fresh['stateDigest']),
                'publication_after_mcp_changed')
        save(folder / 'post-mcp-prestate.json', {k: fresh[k] for k in fields})
        for action in ('publish', 'unpublish'):
            value = {'id': workflow, 'action': action, 'guard': {
                'approvalRef': 'synthetic-lifecycle-' + action + '-' + str(uuid.uuid4()),
                'idempotencyKey': str(uuid.uuid4()),
                'precondition': {k: fresh[k] for k in
                    ('versionId', 'activeVersionId', 'active', 'isArchived', 'stateDigest')}}}
            if action == 'publish':
                value['versionId'] = version
            # Existing issuer and native parent producer handle exact per-write approval.
            result = once.write(action, 'n8n.workflows.lifecycle', value, workflow)
            result = flat_lifecycle_result(result, value)
            once.phase = action + '_independent_get'
            observed = once.call('n8n.workflows.get', {'id': workflow})
            require(all(observed.get(k) == result['after'][k] for k in fields),
                    'lifecycle_independent_readback_mismatch')
            require(observed['id'] == workflow and observed['versionId'] == version and
                    observed['draft'] == baseline['draft'], 'lifecycle_fixture_binding')
            save(folder / (action + '-independent-get.json'), {k: observed[k] for k in fields})
            fresh = observed
        save(folder / 'public-proof.json', {
            'status': 'controlled_publish_unpublish_verified', 'server': server,
            'workflow': workflow, 'versionId': version, 'graph_sha256': eligibility['graph_sha256'],
            'publish_attempts': 1, 'unpublish_attempts': 1,
            'create_attempts': 1, 'execute_calls': 0, 'direct_webhook_calls': 0,
            'business_or_external_actions': False,
            'final_state': {k: fresh[k] for k in fields}, 'fixture_retained': True})
    except Exception as error:
        try:
            require(workflow is not None, 'publication_no_known_workflow')
            observed = once.call('n8n.workflows.get', {'id': workflow})
            # A drifted/malformed read must not persist arbitrary provider fields.
            save(folder / 'stop-state-observation.json', {
                'workflow_binding_equal': observed.get('id') == workflow,
                'version_binding_equal': observed.get('versionId') == version,
                'draft_binding_equal': baseline is not None and
                    observed.get('draft') == baseline['draft'],
                'active': observed.get('active') if type(observed.get('active')) is bool else None,
                'isArchived': observed.get('isArchived') if
                    type(observed.get('isArchived')) is bool else None,
                'active_version_equal': observed.get('activeVersionId') == version,
                'active_version_absent': observed.get('activeVersionId') is None,
                'published_absent': observed.get('published') is None,
                'raw_bodies_retained': False})
        except Exception as observation_error:
            save(folder / 'stop-state-observation-failed.json', {
                'status': 'UNKNOWN', 'exception_class': type(observation_error).__name__,
                'raw_error_body_retained': False})
        save(folder / 'public-proof.json', {
            'status': 'STOP', 'phase': once.phase, 'workflow': workflow, 'versionId': version,
            'exception_class': type(error).__name__, 'automatic_retry': False,
            'raw_error_body_retained': False})
        raise RuntimeError('controlled_publish_stopped') from None
    print(json.dumps({'proof': str(folder / 'public-proof.json'), 'new_execution_calls': 0}))


def publish_self_test():
    """Serialized complete publish path with native parent, no signer/provider.

    Retains fixtures. Mock only subprocess boundaries, not Once.write/call.
    """
    from unittest.mock import patch
    sandbox = ROOT / ('publish-offline-retained-' + str(uuid.uuid4()))
    sandbox.mkdir(mode=0o700)
    native_run = subprocess.run
    canary = 'HOSTILE_PARAMETER_MUST_NOT_BE_RETAINED_53c77'
    scenarios = ('success', 'prestate_drift', 'publish_unknown', 'publish_timeout',
                 'publish_malformed', 'publish_readback_drift', 'unpublish_failed',
                 'issuer_abort', 'wrong_current', 'hostile_prestate_and_stop',
                 'create_unknown', 'create_timeout', 'create_malformed',
                 'mcp_unknown', 'mcp_after_get_drift', 'mcp_already_available')
    total_parent = 0
    for server in ('hetzner', 'eec'):
        base = {'id': 'synthetic_webhook_' + server, 'versionId': 'synthetic-version',
                'activeVersionId': None, 'active': False, 'isArchived': False,
                'stateDigest': 'blake3-256:' + '0' * 64,
                'draft': {'versionId': 'synthetic-version',
                          'graphDigest': 'blake3-256:' + '4' * 64}, 'published': None}
        published = dict(base, active=True, activeVersionId=base['versionId'],
                         published=base['draft'], stateDigest='blake3-256:' + '1' * 64)
        final = dict(base, stateDigest='blake3-256:' + '2' * 64)
        for scenario in scenarios:
            case = sandbox / (server + '-' + scenario)
            case.mkdir(mode=0o700)
            saved = case / ('controlled-webhook-publish-unpublish-rc43-once-' + server)
            actions, requests, parent_calls = [], [], []
            state = [base]
            available = [scenario == 'mcp_already_available']
            def boundary(argv, **kwargs):
                if argv[0] == PARENT:
                    parent_calls.append(argv)
                    return native_run(argv, **kwargs)
                if argv == [BIN, 'verify-current']:
                    current = {'status': 'verified', 'proof': {
                        'validation_mode': 'signed_current', 'owner_key_id': '8e7a0ab7f8435586',
                        'provision_receipt_blake3': 'a' * 64,
                        'release_id': 'wrong' if scenario == 'wrong_current' else
                        'release-20261003-37936e82d-publish-reasons-rc43'}}
                    return subprocess.CompletedProcess(argv, 0, encode(current), b'')
                if argv[:3] == ['sudo', '-n', '/usr/bin/python3']:
                    request = json.loads(kwargs['input'])
                    if request['operation'] == 'create_draft':
                        require(request['workflow_id'] == '' and
                                request['input']['graph'] == publication_graph(server) and
                                request['input']['graph']['settings']['availableInMCP'] is False and
                                request['input']['guard']['precondition'] == {} and
                                (request['official_mcp_tool'], request['official_mcp_resource_uri'],
                                 request['official_mcp_payload_digest']) == ('', '', ''),
                                'test_create_approval_binding')
                    elif request['operation'] == 'mcp_access_reconcile':
                        require(request['workflow_id'] == '' and
                                request['input']['workflowIds'] == [base['id']] and
                                request['input']['desired'] is True and
                                request['input']['dryRun'] is False and
                                (request['official_mcp_tool'], request['official_mcp_resource_uri'],
                                 request['official_mcp_payload_digest']) == ('', '', ''),
                                'test_mcp_approval_scope')
                    else:
                        require(request['operation'] in ('publish', 'unpublish') and
                                request['workflow_id'] == base['id'], 'test_issuer_request_binding')
                        tool, resource, digest = lifecycle_provider_binding(server, request['input'])
                        require((request['official_mcp_tool'], request['official_mcp_resource_uri'],
                                 request['official_mcp_payload_digest']) == (tool, resource, digest),
                                'test_native_payload_binding')
                    requests.append(request)
                    return subprocess.CompletedProcess(argv, 0, b'', b'')
                if argv[:3] == ['sudo', '-n', '/usr/bin/env']:
                    if scenario == 'issuer_abort':
                        error = {'schema': 'fwc.n8n.approval-once.v1', 'abort_code': canary}
                        return subprocess.CompletedProcess(argv, 1, b'', encode(error))
                    # Synthetic token only, no issuer invocation or signature claim.
                    return subprocess.CompletedProcess(argv, 0, b'{"synthetic_offline":true}', b'')
                require(argv[:2] == [BIN, 'run-once'], 'test_unexpected_subprocess')
                envelope = json.loads(kwargs['input'])
                operation, value = argv[2], envelope['input']
                actions.append((operation, value))
                if operation == 'n8n.mcp_access.reconcile':
                    require(value['workflowIds'] == [base['id']] and
                            value['scope'] == 'workflow_ids' and value['desired'] is True,
                            'test_mcp_only_new_fixture')
                    if value['dryRun'] is False:
                        require(envelope.get('approval_token') == {'synthetic_offline': True},
                                'test_mcp_approval_missing')
                        if scenario == 'mcp_unknown':
                            return subprocess.CompletedProcess(argv, 1, encode({
                                'code': 'unknown_outcome', 'diagnostic': canary}), b'')
                        available[0] = True
                        result = {'receipt': {'status': 'applied'}}
                    else:
                        item = {'id': base['id'], 'desired': True,
                                'availableInMCP': available[0],
                                'reason': 'already_desired' if available[0] else 'requires_change'}
                        result = {'exceptions': [], 'changed': [],
                                  'planned': [] if available[0] else [item],
                                  'skipped': [item] if available[0] else [],
                                  'readbackDigest': 'blake3-256:' + '5' * 64,
                                  'receipt': {'schema': 'fwc.n8n.mcp-access-receipt.v1',
                                  'operation': operation, 'serverId': server, 'scope': 'workflow_ids',
                                  'desired': True, 'dryRun': True, 'status': 'planned',
                                  'readbackDigest': 'blake3-256:' + '5' * 64,
                                  'items': [{'desired': True, 'availableInMCP': available[0]}]}}
                    return subprocess.CompletedProcess(argv, 0, encode({
                        'type': 'response', 'status': 'ok', 'result': result}), b'')
                if operation == 'n8n.workflows.create_draft':
                    require(value['graph'] == publication_graph(server) and
                            envelope.get('approval_token') == {'synthetic_offline': True},
                            'test_create_scope')
                    if scenario == 'create_timeout':
                        raise subprocess.TimeoutExpired(argv, 30, output=canary.encode())
                    if scenario == 'create_malformed':
                        return subprocess.CompletedProcess(argv, 0, canary.encode(), b'')
                    result = {'status': 'unknown' if scenario == 'create_unknown' else 'verified',
                              'id': base['id'], 'versionId': base['versionId'],
                              'graphDigest': base['draft']['graphDigest']}
                    return subprocess.CompletedProcess(argv, 0, encode({
                        'type': 'response', 'status': 'ok', 'result': result}), b'')
                if operation == 'n8n.workflows.get':
                    require(value == {'id': base['id']}, 'test_get_scope')
                    observed = state[0]
                    if scenario == 'prestate_drift' and len(actions) == 2:
                        observed = dict(base, versionId='drift')
                    if scenario == 'hostile_prestate_and_stop':
                        observed = dict(base, stateDigest=canary, published={'raw': canary})
                    if scenario == 'mcp_after_get_drift' and available[0] and len(actions) > 2:
                        observed = dict(base, versionId='mcp-drift')
                    if scenario == 'publish_readback_drift' and any(
                            op == 'n8n.workflows.lifecycle' for op, v in actions):
                        observed = dict(published, stateDigest='blake3-256:' + '3' * 64)
                    return subprocess.CompletedProcess(argv, 0, encode({
                        'type': 'response', 'status': 'ok', 'result': observed}), b'')
                require(operation == 'n8n.workflows.lifecycle' and
                        envelope.get('approval_token') == {'synthetic_offline': True},
                        'test_unapproved_or_extra_mutation')
                action = value['action']
                if action == 'publish' and scenario == 'publish_timeout':
                    raise subprocess.TimeoutExpired(argv, 30, output=canary.encode())
                if action == 'publish' and scenario == 'publish_malformed':
                    return subprocess.CompletedProcess(argv, 0, canary.encode(), canary.encode())
                before, after = state[0], published if action == 'publish' else final
                result = {'status': 'verified', 'operation': operation, 'action': action,
                          'provider': 'official_mcp', 'retry': 'never_automatic',
                          'readback': 'independent_get', 'before': before, 'after': after}
                if (action == 'publish' and scenario == 'publish_unknown') or (
                        action == 'unpublish' and scenario == 'unpublish_failed'):
                    return subprocess.CompletedProcess(argv, 1, encode({
                        'status': 'unknown', 'code': 'unknown_outcome', 'diagnostic': canary}), b'')
                state[0] = after
                return subprocess.CompletedProcess(argv, 0, encode(result), b'')
            with patch.dict(globals(), ROOT=case, installed_state=lambda s: {'synthetic': True}), \
                    patch('subprocess.run', side_effect=boundary):
                try:
                    publish_check(server)
                except RuntimeError:
                    require(scenario not in ('success', 'mcp_already_available'),
                            'test_publish_success_failed')
                else:
                    require(scenario in ('success', 'mcp_already_available'),
                            'test_publish_negative_not_denied')
            mutations = [v['action'] for op, v in actions if op == 'n8n.workflows.lifecycle']
            require(mutations == (['publish', 'unpublish'] if scenario in
                    ('success', 'unpublish_failed', 'mcp_already_available') else ['publish'] if scenario in
                    ('publish_unknown', 'publish_timeout', 'publish_malformed',
                     'publish_readback_drift') else []), 'test_mutation_retry_or_scope')
            require(all(op in ('n8n.workflows.get', 'n8n.workflows.lifecycle',
                              'n8n.workflows.create_draft', 'n8n.mcp_access.reconcile')
                        for op, value in actions), 'test_execute_create_forbidden')
            require(sum(op == 'n8n.workflows.create_draft' for op, value in actions) ==
                    (0 if scenario in ('wrong_current', 'issuer_abort') else 1),
                    'test_create_replayed')
            lifecycle_requests = [r for r in requests if r['operation'] in ('publish', 'unpublish')]
            if len(lifecycle_requests) == 2:
                require(len({r['input']['guard']['idempotencyKey'] for r in requests}) == len(requests) and
                        lifecycle_requests[1]['input']['guard']['precondition']['active'] is True,
                        'test_distinct_fresh_unpublish_approval')
            for path in saved.rglob('*.json'):
                require(canary.encode() not in path.read_bytes(), 'test_publish_canary_leak')
            total_parent += len(parent_calls)
    for server in ('eec', 'hetzner'):
        graph = publication_graph(server)
        for changed in (dict(graph, connections={'unexpected': {}}),
                        dict(graph, settings=dict(graph['settings'], availableInMCP=True)),
                        dict(graph, nodes=graph['nodes'] + graph['nodes']),
                        dict(graph, nodes=[dict(graph['nodes'][0], credentials={'canary': canary})]),
                        dict(graph, nodes=[dict(graph['nodes'][0], parameters={
                            'url': canary, 'httpMethod': 'POST'})])):
            try:
                publication_eligibility(changed, server)
            except RuntimeError:
                pass
            else:
                raise RuntimeError('test_unsafe_graph_not_denied')
    print(json.dumps({'publish_self_test': True, 'serialized_full_paths': 32,
                      'unsafe_graph_denials': 10,
                      'native_parent_calls': total_parent, 'live_or_signer_calls': 0,
                      'retained': str(sandbox)}))


def reconcile(server):
    # Read-only observation of the two already executed fixtures. Never call
    # run/write/create/execute from this mode, including after a refusal.
    bindings = {
        'hetzner': ('vgqzXFab4Ai8X4De', '21daa1e2-6d14-4b2f-8a17-d9fd1426fe58',
                    '207f4971-8820-408a-b159-359ea9fd3621',
                    'a784b9ba56274a71e5db8b21774671dc2dc76f0a28838c4362a9f808b8d02761',
                    '2026-10-03T01:04:05+00:00', '2026-10-03T01:04:37+00:00'),
        'eec': ('eep3dyOe0hUpmsQU', '20d86cfd-423d-4b91-aacc-9c1f9a015c35',
                'a25d025f-6f2b-47cc-862f-183383aec38c',
                'f92ce053e3d7a2393dfa0ae0883a74d75ef8086a3c532995cf3ff5b1a4f77be3',
                '2026-10-03T01:04:57+00:00', '2026-10-03T01:05:18+00:00')}
    workflow, version, correlation, prior_sha, start, finish = bindings[server]
    original = ROOT / ('installed-runner-live-20261003-' + server)
    prior = json.loads(pinned(original / 'public-proof.json', prior_sha))
    require(prior['status'] == 'STOP' and prior['known_workflow'] == workflow,
            'reconciliation_prior_binding')
    call = json.loads((original / '07-call.json').read_bytes())
    require(call['requestedUUID'] == correlation and call['operation'] == 'n8n.workflows.execute'
            and call['exit'] == 0, 'reconciliation_original_call')
    wrapper_path = Path('/run/user') / str(os.getuid()) / 'fwc-n8n/receipts' / (
        'wrapper-' + correlation + '.receipt.json')
    wrapper_sha = ('fd37fd9b3f18a124cbd1032f1748a6c8f08878e133db0e4f619b71de1c2d7c05'
                   if server == 'hetzner' else
                   'f4cf4ccb5aacfd42eaa5ac1818b743669475acabf9ea3aa0d4d989d068cd0b92')
    wrapper = json.loads(pinned(wrapper_path, wrapper_sha))
    require(wrapper['schema'] == 'fwc.n8n.execute-wrapper-receipt.v1' and
            wrapper['operation'] == 'n8n.workflows.execute' and
            wrapper['phase'] == 'wrapper_dispatch_returned' and wrapper['status'] == 'verified'
            and wrapper['requestCorrelationId'] == correlation, 'reconciliation_wrapper_binding')
    folder = original / 'readonly-reconciliation-flat1'
    folder.mkdir(mode=0o700)
    once = Once(server, folder)
    once.workflow, once.phase = workflow, 'readonly_reconciliation'
    try:
        state = installed_state(server)
        listing = once.call('n8n.executions.list', {'limit': 100})
        require(isinstance(listing.get('data'), list) and len(listing['data']) <= 100,
                'reconciliation_list_bound')
        candidates = [row for row in listing['data'] if row.get('workflowId') == workflow]
        require(len(candidates) == 1, 'reconciliation_not_unique')
        execution = candidates[0].get('id')
        require(isinstance(execution, str) and re.fullmatch('[0-9]+', execution),
                'reconciliation_id')
        once.execution = execution
        save(folder / 'selected-execution-id.json',
             {'executionId': execution, 'workflowId': workflow, 'versionId': version,
              'requestedUUID': correlation, 'prior_proof_sha256': prior_sha})
        observed = once.call('n8n.executions.get', {'id': execution, 'workflow_id': workflow})
        require(observed.get('id') == execution, 'reconciliation_get_id')
        check_execution(observed, workflow, version)
        timestamp = datetime.datetime.fromisoformat(observed['startedAt'].replace('Z', '+00:00'))
        require(datetime.datetime.fromisoformat(start) <= timestamp <=
                datetime.datetime.fromisoformat(finish), 'reconciliation_execution_time')
        metadata = once.call('n8n.workflows.get', {'id': workflow})
        baseline = json.loads((original / 'created-baseline.json').read_bytes())
        require(metadata['versionId'] == version and metadata['active'] is False and
                metadata['activeVersionId'] is None and metadata['isArchived'] is False and
                metadata['draft']['graphDigest'] == baseline['draft']['graphDigest'],
                'reconciliation_workflow_version_graph')
        outputs = node_outputs(server, workflow, execution)
        save(folder / 'public-proof.json',
             {'status': 'existing_installed_synthetic_execution_verified', 'server': server,
              'workflow': workflow, 'versionId': version, 'executionId': execution,
              'execution_readback': observed, 'node_outputs': outputs, 'installed_state': state,
              'original_requestedUUID': correlation, 'original_wrapper_status': 'verified',
              'original_STOP_preserved': True, 'new_execute_calls': 0,
              'new_workflow_mutations': 0, 'provider_or_business_calls': False})
    except Exception as error:
        save(folder / 'public-proof.json',
             {'status': 'STOP', 'exception_class': type(error).__name__,
              'workflow': workflow, 'known_execution': once.execution,
              'phase': once.phase, 'new_execute_calls': 0, 'raw_error_body_retained': False})
        raise RuntimeError('readonly_reconciliation_stopped') from None
    print(json.dumps({'proof': str(folder / 'public-proof.json'), 'new_execute_calls': 0,
                      'workflow': workflow, 'executionId': execution}))


def self_test():
    from unittest.mock import patch
    canary = 'PRIVATE-CANARY-token'
    hostile = {'code': canary, 'diagnostic': canary, 'rpcPhase': canary,
               'rpcCode': canary, 'correlationId': canary}
    require(canary not in encode(diagnostic_projection(hostile)).decode(), 'diagnostic_canary')
    require(diagnostic_projection({'code': 'unknown_outcome', 'diagnostic':
            'external.mcp.execute_call_jsonrpc_error', 'rpcPhase': 'execute_call',
            'rpcCode': -32000})['rpcCode'] == -32000, 'diagnostic_closed_labels')
    require(issuer_projection(encode({'schema': 'fwc.n8n.approval-once.v1',
            'abort_code': canary})) == ['other'], 'issuer_canary')
    require(stderr_projection(canary.encode() + b'\nFCP-N8N-HOST-ERROR-DETAIL/v1 policy.binding\n') ==
            ['FCP-N8N-HOST-ERROR-DETAIL/v1 policy.binding'], 'stderr_canary')
    root = ROOT / ('runner-local-tests-' + str(uuid.uuid4()))
    root.mkdir(mode=0o700)
    # Literal flat receipt shape emitted by fwc-n8n.rs lifecycle source2745;
    # actual Once.call serialization path, never a generic-envelope stand-in.
    state = {'id': 'fixture', 'versionId': 'v1', 'activeVersionId': None,
             'active': False, 'isArchived': False, 'stateDigest': 'blake3-256:' + 'a' * 64,
             'draft': {'versionId': 'v1', 'graphDigest': 'blake3-256:' + 'b' * 64},
             'published': None}
    published = dict(state, active=True, activeVersionId='v1',
                     published=state['draft'], stateDigest='blake3-256:' + 'c' * 64)
    for action, before, after in [('publish', state, published),
                                  ('unpublish', published, state)]:
        lifecycle_input = {'id': 'fixture', 'action': action, 'guard': {'precondition':
                           {k: before[k] for k in ('versionId', 'activeVersionId', 'active',
                                                  'isArchived', 'stateDigest')}}}
        if action == 'publish':
            lifecycle_input['versionId'] = 'v1'
        native_lifecycle = {'status': 'verified', 'operation': 'n8n.workflows.lifecycle',
                            'action': action, 'provider': 'official_mcp',
                            'retry': 'never_automatic', 'readback': 'independent_get',
                            'before': before, 'after': after}
        folder = root / ('flat-lifecycle-' + action)
        folder.mkdir(mode=0o700)
        with patch('subprocess.run', return_value=subprocess.CompletedProcess(
                [], 0, encode(dict(native_lifecycle,
                    before=dict(before, name='TOKEN_CANARY_DO_NOT_SAVE', folderId=None,
                                projectId=None, updatedAt='2026-10-03T01:04:10.218Z'),
                    after=dict(after, name='TOKEN_CANARY_DO_NOT_SAVE', folderId=None,
                               projectId=None, updatedAt='2026-10-03T01:04:10.218Z'))), b'')):
            require(Once('hetzner', folder).call('n8n.workflows.lifecycle', lifecycle_input) ==
                    native_lifecycle, 'actual_flat_lifecycle_call')
        require((folder / '01-lifecycle-readback.json').exists(), 'lifecycle_readback_not_saved')
        require(b'TOKEN_CANARY_DO_NOT_SAVE' not in
                (folder / '01-lifecycle-readback.json').read_bytes(), 'lifecycle_metadata_leaked')
        for field, bad in [('operation', 'n8n.workflows.execute'), ('provider', 'other'),
                           ('action', 'archive'), ('retry', 'automatic'), ('status', 'unknown'),
                           ('readback', 'advisory'), ('hostile', 'TOKEN_CANARY_DO_NOT_SAVE')]:
            try:
                flat_lifecycle_result(dict(native_lifecycle, **{field: bad}), lifecycle_input)
            except RuntimeError:
                pass
            else:
                raise RuntimeError('flat_lifecycle_negative_not_denied')
        for changed_after in (dict(after, id='other'), dict(after, versionId='other'),
                              dict(after, draft=dict(after['draft'], graphDigest='bad'))):
            try:
                flat_lifecycle_result(dict(native_lifecycle, after=changed_after), lifecycle_input)
            except RuntimeError:
                pass
            else:
                raise RuntimeError('flat_lifecycle_state_negative_not_denied')
    native_flat = {'status': 'verified', 'operation': 'n8n.workflows.execute',
                   'provider': 'official_mcp', 'workflowId': 'fixture', 'mode': 'manual',
                   'versionId': 'v1', 'executionId': '1', 'initialStatus': 'accepted',
                   'executionStatus': 'success', 'retry': 'never_automatic',
                   'readback': 'independent_execution_get'}
    folder = root / 'actual-flat-call'
    folder.mkdir(mode=0o700)
    once = Once('hetzner', folder)
    with patch('subprocess.run', return_value=subprocess.CompletedProcess(
            [], 0, encode(native_flat), b'')):
        require(once.call('n8n.workflows.execute', {'id': 'fixture', 'mode': 'manual',
                'versionId': 'v1'}) == native_flat and once.execution == '1', 'actual_flat_call')
    require((folder / '01-execute-handle.json').exists(), 'flat_handle_not_retained')
    for field, bad_value in [('workflowId', 'other'), ('versionId', 'other'),
                             ('mode', 'webhook'), ('provider', 'other'),
                             ('operation', 'n8n.workflows.get'), ('executionId', None)]:
        try:
            flat_execute_result(dict(native_flat, **{field: bad_value}),
                                {'id': 'fixture', 'mode': 'manual', 'versionId': 'v1'})
        except RuntimeError:
            pass
        else:
            raise RuntimeError('flat_negative_not_denied')
    require(flat_execute_result(dict(native_flat, status='unknown', executionStatus='running'),
            {'id': 'fixture', 'mode': 'manual', 'versionId': 'v1'})['executionId'] == '1',
            'flat_unknown_handle_lost')
    # Actual reconciliation method, using exact retained non-secret prior pins;
    # list/get/output transport is synthetic and never invokes a provider.
    for scenario in ('success', 'multiple', 'wrong_version'):
        sandbox = root / ('reconcile-' + scenario)
        original = sandbox / 'installed-runner-live-20261003-hetzner'
        original.mkdir(mode=0o700, parents=True)
        real = ROOT / 'installed-runner-live-20261003-hetzner'
        for name in ('public-proof.json', '07-call.json', 'created-baseline.json'):
            (original / name).write_bytes((real / name).read_bytes())
        calls = []
        recovered = {'id': '123', 'workflowId': 'vgqzXFab4Ai8X4De', 'mode': 'manual',
                     'workflowVersionId': '21daa1e2-6d14-4b2f-8a17-d9fd1426fe58',
                     'status': 'success', 'finished': True, 'startedAt': '2026-10-03T01:04:20Z'}
        def recovery_call(once, operation, value, token=None, budget_ms=30000):
            calls.append(operation)
            if operation == 'n8n.executions.list':
                require(value == {'limit': 100}, 'unsupported_list_filter')
                return {'data': [recovered] * (2 if scenario == 'multiple' else 1)}
            if operation == 'n8n.executions.get':
                require(value == {'id': '123', 'workflow_id': recovered['workflowId']},
                        'recovery_get_binding')
                return dict(recovered, workflowVersionId='wrong') if scenario == 'wrong_version' else recovered
            require(operation == 'n8n.workflows.get', 'recovery_mutation_forbidden')
            return json.loads((real / 'created-baseline.json').read_bytes())
        with patch.dict(globals(), ROOT=sandbox,
                installed_state=lambda server: {'synthetic': True},
                node_outputs=lambda *args: {'exact_synthetic_outputs': True}), \
                patch.object(Once, 'call', recovery_call), \
                patch.object(Once, 'write', side_effect=AssertionError('recovery_must_not_write')):
            try:
                reconcile('hetzner')
            except RuntimeError:
                require(scenario != 'success', 'recovery_success_failed')
            else:
                require(scenario == 'success', 'recovery_negative_not_denied')
        require(all(op in ('n8n.executions.list', 'n8n.executions.get', 'n8n.workflows.get')
                for op in calls), 'recovery_not_readonly')
    for label, effect in (
            ('timeout', subprocess.TimeoutExpired('synthetic', 1, output=canary.encode())),
            ('malformed', subprocess.CompletedProcess([], 1, canary.encode(), canary.encode())),
            ('error', subprocess.CompletedProcess([], 1, encode(hostile), canary.encode()))):
        folder = root / label
        folder.mkdir(mode=0o700)
        once = Once('hetzner', folder)
        with patch('subprocess.run', side_effect=effect if isinstance(effect, Exception) else None,
                   return_value=effect):
            try:
                once.call('n8n.executions.get', {'id': '1', 'workflow_id': 'fixture'})
            except RuntimeError:
                pass
            else:
                raise RuntimeError('diagnostic_error_not_denied')
        receipt = (folder / '01-call.json').read_bytes()
        require(canary.encode() not in receipt, 'persisted_diagnostic_canary')
    class Reads:
        def __init__(self, values):
            self.values, self.calls = values, []
        def call(self, operation, value, budget_ms):
            self.calls.append((operation, value, budget_ms))
            return self.values[min(len(self.calls)-1, len(self.values)-1)]
    base = {'id': '1', 'workflowId': 'fixture', 'workflowVersionId': 'v1',
            'mode': 'manual', 'status': 'running', 'finished': False}
    success = dict(base, status='success', finished=True)
    ticks = [0.0]
    def clock():
        return ticks[0]
    def sleep(seconds):
        ticks[0] += seconds
    reads = Reads([base, success])
    require(wait_execution(reads, '1', 'fixture', 'v1', clock, sleep) == success,
            'nonterminal_followup')
    require(len(reads.calls) == 2 and all(c[0] == 'n8n.executions.get' and
            c[1] == {'id': '1', 'workflow_id': 'fixture'} and c[2] <= 5000
            for c in reads.calls), 'readonly_wait_scope')
    for value in (dict(base, id='2'), dict(base, workflowId='other'),
                  dict(base, workflowVersionId='other'), dict(base, mode='webhook'),
                  dict(base, status='error'), base):
        ticks[0] = 0
        reads = Reads([value])
        try:
            wait_execution(reads, '1', 'fixture', 'v1', clock, sleep)
        except RuntimeError:
            require(len(reads.calls) <= 20, 'wait_count_bound')
        else:
            raise RuntimeError('wait_negative_not_denied')
    packet = json.loads(pinned(PREP, PREP_SHA))
    golden = {'id': 'kXVmpnLGECl1aHLy', 'mode': 'manual',
              'triggerNodeName': 'FWC Acceptance Webhook', 'inputs': {'webhookData': {
                  'method': 'POST', 'query': {}, 'body': {'fcpAcceptance': 'nqm81.25-eec-manual-noop'}}}}
    require(execute_provider_binding('eec', golden)[2] ==
            'sha256:1504202e414defdaf892754772136916f950038837af32f5715b1045d48184fd',
            'native_host_producer_golden')
    request_cases = []
    for g in packet['graphs']:
        server = g['server']
        values = [('n8n.workflows.create_draft', g['create_input'], '', 'create_draft'),
                  ('n8n.mcp_access.reconcile', {'scope': 'workflow_ids',
                   'workflowIds': ['fixture_1'], 'desired': True, 'dryRun': False,
                   'guard': {'approvalRef': 'test', 'idempotencyKey':
                   '4be6bbd7-c953-498c-a5ab-415d8c140038',
                   'dryRunDigest': 'blake3-256:'+'0'*64}}, 'fixture_1', 'mcp_access_reconcile'),
                  ('n8n.workflows.execute', {'id': 'fixture_1', 'mode': 'manual',
                   'versionId': 'test-version', 'triggerNodeName': 'Run synthetic runner check',
                   'guard': {'approvalRef': 'test', 'idempotencyKey':
                   '4be6bbd7-c953-498c-a5ab-415d8c140038',
                   'inputClass': 'none',
                   'sideEffectSummary': 'Synthetic arithmetic only', 'precondition': {
                   'versionId': 'test-version', 'activeVersionId': None, 'active': False,
                   'isArchived': False, 'stateDigest': 'blake3-256:'+'0'*64}}},
                   'fixture_1', 'execute')]
        for action in ('publish', 'unpublish'):
            value = {'id': 'fixture_1', 'action': action, 'guard': {
                     'approvalRef': 'test', 'idempotencyKey':
                     '4be6bbd7-c953-498c-a5ab-415d8c140038', 'precondition': {
                     'versionId': 'test-version', 'activeVersionId':
                     None if action == 'publish' else 'test-version',
                     'active': action == 'unpublish', 'isArchived': False,
                     'stateDigest': 'blake3-256:' + '0' * 64}}}
            if action == 'publish':
                value['versionId'] = 'test-version'
            values.append(('n8n.workflows.lifecycle', value, 'fixture_1', action))
        for operation, value, workflow, short in values:
            # Actual pinned native parent producer, no mock/signer/seed.
            request = approval_request(server, operation, value, workflow,
                                       int(time.time() * 1000) + 45000)
            serialized = json.loads(encode(request))
            require(serialized['operation'] == short and serialized['input'] == value and
                    serialized['workflow_id'] == (workflow if short in
                     ('execute', 'publish', 'unpublish') else ''),
                    'issuer_serialized_enum_scope')
            uri = f'fwc-n8n://{server}' + ('/workflows/fixture%5F1' if short in
                                        ('execute', 'publish', 'unpublish') else '')
            expected = subprocess.run([PARENT, server, uri, operation, encode(value).decode()],
                                      capture_output=True, timeout=5)
            require(expected.returncode == 0 and expected.stdout.decode().strip() ==
                    request['parent_binding_sha256'], 'actual_parent_uri_and_full_operation')
            if short in ('publish', 'unpublish'):
                arguments = {'workflowId': 'fixture_1'}
                if short == 'publish':
                    arguments['versionId'] = 'test-version'
                expected_payload = {'name': short + '_workflow', 'arguments': arguments}
                expected_digest = 'sha256:' + hashlib.sha256(
                    b'FCP/MCP-Bridge/approval-payload/v1\0' + encode(expected_payload)).hexdigest()
                require(request['official_mcp_tool'] == short + '_workflow' and
                        request['official_mcp_resource_uri'] ==
                        f'fwc-mcp-bridge://{server}/tools/{short}%5Fworkflow' and
                        request['official_mcp_payload_digest'] == expected_digest,
                        'lifecycle_producer_consumer_binding')
                changed = json.loads(encode(value))
                changed['guard']['approvalRef'] = 'other'
                require(lifecycle_provider_binding(server, changed)[2] == expected_digest,
                        'lifecycle_guard_leaked_into_payload')
                if short == 'publish':
                    changed['versionId'] = 'other'
                    require(lifecycle_provider_binding(server, changed)[2] != expected_digest,
                            'publish_version_not_bound')
                else:
                    changed['versionId'] = 'forbidden'
                    try:
                        lifecycle_provider_binding(server, changed)
                    except RuntimeError:
                        pass
                    else:
                        raise RuntimeError('unpublish_version_not_denied')
            if short == 'execute':
                invalid = json.loads(encode(value))
                invalid['guard']['inputClass'] = 'synthetic_no_external_actions'
                with patch('subprocess.run') as not_called:
                    try:
                        approval_request(server, operation, invalid, workflow,
                                         int(time.time() * 1000) + 45000)
                    except RuntimeError as error:
                        require(str(error) == 'execute_input_class', 'input_class_negative_label')
                    else:
                        raise RuntimeError('old_input_class_not_denied')
                    require(not not_called.called, 'invalid_class_called_producer_or_signer')
                require(request['official_mcp_resource_uri'] ==
                        f'fwc-mcp-bridge://{server}/tools/execute%5Fworkflow' and
                        request['official_mcp_tool'] == 'execute_workflow', 'execute_binding_uri')
                changed = dict(value, versionId='other-version', guard={'other': True})
                require(execute_provider_binding(server, value) == execute_provider_binding(server, changed),
                        'high_level_fields_not_provider_payload')
                changed = dict(value, triggerNodeName='other-trigger')
                require(execute_provider_binding(server, value) != execute_provider_binding(server, changed),
                        'provider_payload_change_not_bound')
            elif short in ('create_draft', 'mcp_access_reconcile'):
                require(all(request[k] == '' for k in ('official_mcp_tool',
                        'official_mcp_resource_uri', 'official_mcp_payload_digest')), 'rest_has_mcp_binding')
            request_cases.append(request)
    save(root / 'serialized-approval-requests.json', request_cases)
    def plan_fixture(available):
        item = {'id': 'fixture', 'desired': True, 'availableInMCP': available,
                'reason': 'already_desired' if available else 'requires_change'}
        return {'exceptions': [], 'changed': [], 'planned': [] if available else [item],
                'skipped': [item] if available else [], 'readbackDigest': 'blake3-256:'+'0'*64,
                'receipt': {'schema': 'fwc.n8n.mcp-access-receipt.v1',
                'operation': 'n8n.mcp_access.reconcile', 'serverId': 'hetzner',
                'scope': 'workflow_ids', 'desired': True, 'dryRun': True, 'status': 'planned',
                'readbackDigest': 'blake3-256:'+'0'*64,
                'items': [{'desired': True, 'availableInMCP': available}]}}
    require(checked_plan(plan_fixture(False), 'fixture', 'hetzner') is False and
            checked_plan(plan_fixture(True), 'fixture', 'hetzner') is True, 'both_actual_dryrun_shapes')
    for field in ('exceptions', 'changed', 'planned', 'skipped'):
        bad = plan_fixture(True)
        bad[field].append({'id': 'extra', 'desired': True, 'availableInMCP': True})
        try:
            checked_plan(bad, 'fixture', 'hetzner')
        except RuntimeError:
            pass
        else:
            raise RuntimeError('mcp_extra_scope_not_denied')
    for g in packet['graphs']:
        safe_fixture(g['graph'], g['server'] == 'hetzner')
        changed = json.loads(json.dumps(g['graph']))
        changed['nodes'][1]['credentials'] = {'forbidden': 'canary'}
        try:
            safe_fixture(changed, g['server'] == 'hetzner')
        except RuntimeError:
            continue
        raise RuntimeError('credential_canary_not_denied')
    actual_call = Once.call
    full_scenarios = ('verified_success', 'verified_wrong_id', 'verified_wrong_binding',
                      'verified_nonterminal_read', 'verified_nonterminal_receipt',
                      'unknown_running', 'failed_final_observation')
    for scenario in full_scenarios:
        failed_observation = scenario == 'failed_final_observation'
        expected_failure = scenario not in ('verified_success', 'unknown_running')
        folder_root = root / ('full-' + scenario)
        folder_root.mkdir(mode=0o700)
        actions = []
        workflow_reads = [0]
        execution_reads = [0]
        reconcile_reads = [0]
        metadata = {'versionId': 'v1', 'draft': {'graphDigest': 'graph'},
                    'active': False, 'activeVersionId': None, 'isArchived': False,
                    'stateDigest': 'state'}
        def write_stub(once, phase, operation, value, workflow):
            actions.append(operation)
            once.phase = phase
            if phase == 'create':
                return {'status': 'verified', 'id': 'fixture', 'versionId': 'v1',
                        'graphDigest': 'graph'}
            if phase == 'mcp':
                require(value['scope'] == 'workflow_ids' and value['workflowIds'] == ['fixture'] and
                        value['dryRun'] is False, 'full_mcp_apply_scope')
                return {'receipt': {'status': 'applied'}}
            require(phase == 'execute', 'unexpected_synthetic_write')
            flat = dict(native_flat, status='unknown' if scenario == 'unknown_running' else 'verified',
                        executionStatus='running' if scenario in
                        ('unknown_running', 'verified_nonterminal_receipt') else 'success')
            with patch('subprocess.run', return_value=subprocess.CompletedProcess(
                    [], 0, encode(flat), b'')):
                return actual_call(once, operation, value)
        def call_stub(once, operation, value, token=None, budget_ms=30000):
            actions.append(operation)
            if operation == 'n8n.workflows.get':
                workflow_reads[0] += 1
                if failed_observation and workflow_reads[0] >= 3:
                    raise RuntimeError('synthetic_final_observation_failure')
                return metadata
            if operation == 'n8n.mcp_access.reconcile':
                reconcile_reads[0] += 1
                return plan_fixture(reconcile_reads[0] != 1)
            require(operation == 'n8n.executions.get' and
                    value == {'id': '1', 'workflow_id': 'fixture'},
                    'unexpected_synthetic_read')
            execution_reads[0] += 1
            if scenario == 'verified_wrong_id':
                return dict(success, id='2')
            if scenario == 'verified_wrong_binding':
                return dict(success, workflowId='other')
            if scenario == 'verified_nonterminal_read':
                return base
            return base if scenario == 'unknown_running' and execution_reads[0] == 1 else success
        with patch.dict(globals(), ROOT=folder_root), patch.object(Once, 'write', write_stub), \
                patch.object(Once, 'call', call_stub), patch.dict(globals(),
                installed_state=lambda server: {'synthetic': True},
                node_outputs=lambda *args: {'exact_synthetic_outputs': True}), \
                patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0, b'', b'')), \
                patch('time.sleep') as sleep_calls:
            try:
                run('hetzner')
            except RuntimeError:
                require(expected_failure, 'full_success_failed')
            else:
                require(not expected_failure, 'full_failure_not_denied')
            require(actions.count('n8n.workflows.execute') == 1, 'execute_repeated')
            if scenario == 'unknown_running':
                require(execution_reads[0] == 2 and sleep_calls.call_count == 1,
                        'unknown_nonterminal_wait_contract')
            else:
                require(execution_reads[0] == (0 if scenario == 'verified_nonterminal_receipt' else 1)
                        and sleep_calls.call_count == 0, 'verified_readback_polled_or_slept')
        require(actions.count('n8n.workflows.create_draft') == 1 and
                actions.count('n8n.mcp_access.reconcile') == 3 and
                actions.count('n8n.workflows.execute') == 1,
                'mutation_replay_or_execution_read_scope')
        folder = folder_root / 'installed-runner-live-20261003-hetzner'
        require((folder / 'execute-known-id.json').exists(), 'known_id_not_persisted')
        if failed_observation:
            require(json.loads((folder / 'stop-state-observation-failed.json').read_bytes())
                    ['status'] == 'UNKNOWN', 'failed_observation_missing_receipt')
    print(json.dumps({'self_test': True, 'live_calls': 0, 'positive_graphs': 2,
                      'credential_denials': 2, 'diagnostic_cases': 3,
                      'wait_positive': 1, 'wait_denials': 6, 'full_paths': len(full_scenarios),
                      'verified_no_poll_scenarios': 6,
                      'real_parent_serialized_requests': len(request_cases), 'native_host_golden': True,
                      'dryrun_shapes': 2, 'dryrun_extra_denials': 4,
                      'old_input_class_denials_before_subprocess': 2,
                      'real_call_serialized_flat_receipt': 1, 'flat_binding_denials': 6,
                      'readonly_recovery_full_paths': 3,
                      'retained_fixtures': str(root)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--run', choices=['eec', 'hetzner'])
    parser.add_argument('--reconcile', choices=['eec', 'hetzner'])
    parser.add_argument('--publish-check', choices=['eec', 'hetzner'])
    parser.add_argument('--publish-self-test', action='store_true')
    args = parser.parse_args()
    if sum(bool(v) for v in (args.self_test, args.run, args.reconcile,
                            args.publish_check, args.publish_self_test)) != 1:
        parser.error('exactly one mode required')
    if args.publish_self_test:
        publish_self_test()
    elif args.self_test and not args.run and not args.reconcile and not args.publish_check:
        self_test()
    elif args.run and not args.self_test and not args.reconcile and not args.publish_check:
        run(args.run)
    elif args.reconcile and not args.self_test and not args.run and not args.publish_check:
        reconcile(args.reconcile)
    elif args.publish_check and not args.self_test and not args.run and not args.reconcile:
        publish_check(args.publish_check)
    else:
        parser.error('exactly one mode required')
