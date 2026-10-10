'use strict';

// Controlled offline component regression: real patched native classes, fake
// repository plus the pinned public catalog in a SELECT-only RAM adapter.
// The owned Rust test supplies network denial and an empty replacement env.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const assert = require('assert').strict;
const PATCH = '391a6acf86de476e45a7a65ad286719dca569abe7d216c2a50eaae7efc1fd832';
const root = process.argv[2];
let stage = 'metadata';
let checks = 0;
if (process.argv.length !== 3 || !/^\/srv\/dev-ssd\/fcp\/nqm81-35\/derived-n8n-mcp-2\.91-[0-9a-f]{32}\/node_modules\/n8n-mcp$/.test(root || '')
    || fs.realpathSync(root) !== root || process.env.N8N_MCP_TELEMETRY_DISABLED !== 'true') {
    process.stdout.write('{"status":"fixture_input_refused"}\n');
    process.exitCode = 1;
} else {
    run().catch(() => {
        // No assertion/raw native message/canary/paths on failure.
        process.stdout.write(JSON.stringify({ status: 'native_fixture_failed', stage, checks }) + '\n');
        process.exitCode = 1;
    });
}

async function run() {
    const metadata = JSON.parse(fs.readFileSync(path.join(root, 'package.json')));
    assert.equal(metadata.name, 'n8n-mcp');
    assert.equal(metadata.version, '2.91.0');
    assert.equal(metadata.fwcDerivedValidation.patchSha256, PATCH);
    for (const [relative, expected] of Object.entries(metadata.fwcDerivedValidation.files)) {
        assert.equal(crypto.createHash('sha256').update(fs.readFileSync(path.join(root, relative))).digest('hex'), expected);
    }
    const { WorkflowValidator } = require(path.join(root, 'dist/services/workflow-validator.js'));
    const { EnhancedConfigValidator } = require(path.join(root, 'dist/services/enhanced-config-validator.js'));
    const { N8NDocumentationMCPServer } = require(path.join(root, 'dist/mcp/server.js'));
    const common = [
        { name: 'version', type: 'options', default: 1, options: [1, 2, 3].map(value => ({ name: String(value), value })) },
        { name: 'resource', type: 'options', default: 'row', options: [{ name: 'Row', value: 'row' }] },
        { name: 'operation', type: 'options', default: 'get', options: ['get', 'delete', 'update'].map(value => ({ name: value, value })) },
    ];
    // Official2.41.5 registry: NocoDB node3->V1, node4->V2. API parameter
    // version is a DIFFERENT selector; fixtures cover its visibility rules.
    const v3 = [...common,
        { name: 'projectId', type: 'string', required: true, default: '' },
        { name: 'table', type: 'options', required: true, default: '', options: [{ name: 'Table', value: 't' }] },
        { name: 'id', type: 'string', required: true, default: '', displayOptions: { show: { version: [1, 2], operation: ['delete', 'get', 'update'] } } },
        { name: 'id', type: 'string', required: true, default: '', displayOptions: { show: { version: [3], operation: ['delete', 'get'] } } },
    ];
    const v4 = [...common,
        { name: 'projectId', type: 'resourceLocator', required: true, default: { mode: 'id', value: '' } },
        { name: 'table', type: 'resourceLocator', required: true, default: { mode: 'id', value: '' } },
    ];
    const calls = [];
    const repository = {
        getNode(type) { return ['nodes-base.nocoDb', 'n8n-nodes-base.nocoDb'].includes(type)
            ? { nodeType: type, version: '4', isVersioned: true, properties: v4, displayName: 'NocoDB' } : null; },
        getNodeVersion(type, version) { calls.push([type, version]); return version === 3 || version === 4
            ? { version: String(version), propertiesSchema: version === 3 ? v3 : v4 } : null; },
        hasVersionMetadata() { return true; },
        getAllNodes() { return []; },
        getNodeResources() { return ['WRONG_CURRENT_RESOURCE']; },
        getNodeOperations() { return ['WRONG_CURRENT_OPERATION']; },
        getDefaultOperationForResource() { return 'WRONG_CURRENT_OPERATION'; },
    };
    EnhancedConfigValidator.initializeSimilarityServices(repository);
    const parameters = version => ({ projectId: 'p', table: 't', resource: 'row', operation: 'update', version });
    const node = (typeVersion, params, index = 0) => ({ id: `synthetic-${index}`, name: `SYNTHETIC_CANARY_${index}`,
        type: 'n8n-nodes-base.nocoDb', typeVersion, parameters: params, position: [index * 10, 0] });
    async function assess(nodes, selectedRepository = repository) {
        const graph = { nodes, connections: {} };
        const validator = new WorkflowValidator(selectedRepository, EnhancedConfigValidator);
        const result = { errors: [], warnings: [], suggestions: [],
            fwcValidation: { schemas: nodes.map((n, index) => ({ index, typeVersion: n.typeVersion,
                status: 'not_collected', schemaVersion: null, schemaSha256: null, propertyCount: null })) } };
        await validator.validateAllNodes(graph, result, 'runtime');
        return result;
    }
    stage = 'synthetic';
    const accepted = await assess([node(3, { ...parameters(3), '@version': 999 })]);
    assert.equal(accepted.errors.length, 0); ++checks;
    assert.equal(accepted.fwcValidation.schemas[0].schemaVersion, 3); ++checks;
    for (const api of [1, 2]) {
        const required = await assess([node(3, parameters(api))]);
        const finding = required.errors.find(e => e.fwcDiagnostic?.code === 'required_trim_empty');
        assert.ok(finding); assert.equal(finding.fwcDiagnostic.defaultApplied, true);
        assert.equal(finding.fwcDiagnostic.apiVersion, api); assert.equal(finding.fwcDiagnostic.typeVersion, 3); ++checks;
    }
    const hidden = await assess([node(3, parameters(3))]);
    assert.ok(!hidden.errors.some(e => e.fwcDiagnostic?.code === 'required_trim_empty')); ++checks;
    const mismatch = await assess([node(4, parameters(3))]);
    assert.ok(mismatch.errors.some(e => e.fwcDiagnostic?.code === 'special_type_mismatch')); ++checks;
    const literal = await assess([node(4, { ...parameters(3), projectId: { mode: 'id', value: 'p' }, table: { mode: 'id', value: 't' } })]);
    assert.ok(!literal.errors.some(e => e.fwcDiagnostic?.code === 'special_type_mismatch')); ++checks;
    const badOption = await assess([node(3, { ...parameters(3), operation: 'WRONG_CURRENT_OPERATION' })]);
    assert.ok(badOption.errors.length > 0); ++checks;
    const missing = await assess([node(3.5, parameters(3))]);
    assert.equal(missing.fwcValidation.schemas[0].status, 'unsupported_version');
    assert.equal(missing.errors[0].fwcDiagnostic.code, 'schema_version_unavailable'); ++checks;
    const repeated = await assess([node(4, parameters(3), 0), node(4, parameters(3), 1)]);
    assert.deepEqual([...new Set(repeated.errors.filter(e => e.fwcDiagnostic?.code === 'special_type_mismatch')
        .map(e => e.fwcDiagnostic.nodeIndex))].sort(), [0, 1]); ++checks;
    assert.ok(calls.every(([, version]) => [3, 4, 3.5].includes(version))); ++checks;
    // Actual native server copying, without its production constructor/DB/API.
    const response = await N8NDocumentationMCPServer.prototype.validateWorkflow.call(
        { repository, async ensureInitialized() {} },
        { nodes: [node(4, parameters(3))], connections: {} },
        { validateNodes: true, validateConnections: false, validateExpressions: false, profile: 'runtime' },
    );
    assert.ok(response.errors.some(e => e.fwcDiagnostic?.code === 'special_type_mismatch'));
    assert.equal(response.fwcValidation.errorCount, response.errors.length);
    assert.equal(response.fwcValidation.warningCount, response.warnings.length); ++checks;
    stage = 'public_catalog';
    const dbPath = path.join(root, 'data/nodes.db');
    assert.equal(crypto.createHash('sha256').update(fs.readFileSync(dbPath)).digest('hex'),
        '4173f036ce32b12f22a24e5f58b419a8cf7e6b544378b592a3470d8ed07245b3'); ++checks;
    const { createSQLJSAdapter } = require(path.join(root, 'dist/database/database-adapter.js'));
    const { NodeRepository } = require(path.join(root, 'dist/database/node-repository.js'));
    const adapter = await createSQLJSAdapter(dbPath);
    // Never call adapter.exec/run/close (close persists the SQL.js DB).
    // Repository reads receive only SELECT statements; all writes are absent.
    const readonly = { prepare(sql) {
        assert.ok(/^\s*SELECT\b/i.test(sql));
        const statement = adapter.prepare(sql);
        return { get: (...args) => statement.get(...args), all: (...args) => statement.all(...args) };
    } };
    const actualRepository = new NodeRepository(readonly);
    EnhancedConfigValidator.initializeSimilarityServices(actualRepository);
    for (const version of [1, 2, 3]) {
        const actual = await assess([node(version, { ...parameters(3), '@version': 999 })], actualRepository);
        assert.equal(actual.fwcValidation.schemas[0].schemaVersion, version);
        assert.equal(actual.fwcValidation.schemas[0].status, 'validated');
        assert.ok(!actual.errors.some(e => ['special_type_mismatch', 'required_trim_empty'].includes(e.fwcDiagnostic?.code))); ++checks;
    }
    for (const api of [1, 2]) {
        const actual = await assess([node(3, parameters(api))], actualRepository);
        const origin = actual.errors.find(e => e.fwcDiagnostic?.code === 'required_trim_empty')?.fwcDiagnostic;
        assert.ok(origin); assert.equal(origin.apiVersion, api); assert.equal(origin.defaultApplied, true);
        assert.equal(origin.originalOrdinal, 14); ++checks;
    }
    const actualMismatch = await assess([node(4, parameters(3))], actualRepository);
    const mismatchOrigin = actualMismatch.errors.find(e => e.fwcDiagnostic?.code === 'special_type_mismatch')?.fwcDiagnostic;
    assert.ok(mismatchOrigin); assert.equal(mismatchOrigin.expectedType, 'object');
    assert.equal(mismatchOrigin.actualType, 'string'); assert.equal(mismatchOrigin.structureKind, 'resourceLocator'); ++checks;
    const absent = await assess([node(3.5, parameters(3))], actualRepository);
    assert.equal(absent.fwcValidation.schemas[0].status, 'unsupported_version'); ++checks;
    stage = 'graph_warning_origins';
    const trigger = { id: 'trigger', name: 'SYNTHETIC_TRIGGER', type: 'n8n-nodes-base.manualTrigger', typeVersion: 1, parameters: {}, position: [0, 0] };
    const detached = { ...node(3, parameters(3)), continueOnFail: true };
    const disabled = { ...node(3, parameters(3), 1), disabled: true };
    const warningResponse = await N8NDocumentationMCPServer.prototype.validateWorkflow.call(
        { repository: actualRepository, async ensureInitialized() {} },
        { nodes: [trigger, detached, disabled], connections: { SYNTHETIC_TRIGGER: { main: [[{ node: disabled.name, type: 'main', index: 0 }]] } } },
        { validateNodes: true, validateConnections: true, validateExpressions: false, profile: 'runtime' });
    for (const code of ['connection_disabled_target', 'node_unreachable', 'node_legacy_continue_on_fail']) {
        assert.ok(warningResponse.warnings.some(w => w.fwcWarning?.code === code)); ++checks;
    }
    assert.equal(warningResponse.fwcValidation.warningCount, warningResponse.warnings.length); ++checks;
    adapter.db.close(); // RAM-only native SQL.js close; not adapter.close/saveToFile.
    // Consumed in RAM by the owned Rust component test, never an evidence log.
    // The Rust test applies the ACTUAL public projector and checks redaction.
    // Keep the fixture alive like the long-lived MCP provider until its owned
    // parent terminates it. Default TERM handling remains unchanged; the parent
    // retains the fixed receive deadline and bounded teardown/IO joins.
    process.stdin.resume();
    process.stdout.write(JSON.stringify({ status: 'native_fixture_pass', checks, providerCalls: 0,
        synthetic: true, productionAdmission: false, patchSha256: PATCH,
        nativeResponse: response }) + '\n');
}
