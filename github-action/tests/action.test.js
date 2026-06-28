/**
 * pkg-defender-action Test Suite
 *
 * Tests for the thin CLI wrapper around pkg-defender.
 * The action delegates to `pkgd audit` and maps exit codes.
 */

const fs = require('fs');
const path = require('path');
const yaml = require('yaml');

// Mock @actions/core, @actions/exec, @actions/glob before any require
jest.mock('@actions/core');
jest.mock('@actions/exec');
jest.mock('@actions/glob');

const core = require('@actions/core');
const exec = require('@actions/exec');
const glob = require('@actions/glob');

// ============================================================================
// Test Suite: Action Structure Tests (action.yml contract)
// ============================================================================

describe('Action Structure Tests', () => {
  let actionYml;
  const actionDir = path.join(__dirname, '..');

  beforeAll(() => {
    const actionPath = path.join(actionDir, 'action.yml');
    const content = fs.readFileSync(actionPath, 'utf8');
    actionYml = yaml.parse(content);
  });

  test('action.yml exists and is valid YAML', () => {
    expect(actionYml).toBeDefined();
    expect(actionYml.name).toBeDefined();
  });

  test('has required metadata fields', () => {
    expect(actionYml.name).toBe('Package Defender Security Audit');
    expect(actionYml.description).toBeDefined();
    expect(actionYml.author).toBe('divisionseven');
    expect(actionYml.branding).toBeDefined();
    expect(actionYml.branding.icon).toBe('shield');
    expect(actionYml.branding.color).toBe('green');
  });

  describe('Input Definitions', () => {
    test('fail-on input is defined', () => {
      expect(actionYml.inputs['fail-on']).toBeDefined();
      expect(actionYml.inputs['fail-on'].description.toLowerCase()).toContain(
        'severity'
      );
      expect(actionYml.inputs['fail-on'].required).toBe(false);
      expect(actionYml.inputs['fail-on'].default).toBe('high');
    });

    test('ecosystems input is defined', () => {
      expect(actionYml.inputs.ecosystems).toBeDefined();
      expect(actionYml.inputs.ecosystems.description).toContain('ecosystems');
      expect(actionYml.inputs.ecosystems.required).toBe(false);
      expect(actionYml.inputs.ecosystems.default).toBe(
        'npm,pypi,cargo,rubygems'
      );
    });

    test('db-snapshot input is defined', () => {
      expect(actionYml.inputs['db-snapshot']).toBeDefined();
      expect(actionYml.inputs['db-snapshot'].description).toContain(
        'database'
      );
      expect(actionYml.inputs['db-snapshot'].required).toBe(false);
      expect(actionYml.inputs['db-snapshot'].default).toBe('latest');
    });

    test('token input is defined', () => {
      expect(actionYml.inputs.token).toBeDefined();
      expect(actionYml.inputs.token.description).toContain('GitHub token');
      expect(actionYml.inputs.token.required).toBe(false);
    });

    test('lock-files input is defined', () => {
      expect(actionYml.inputs['lock-files']).toBeDefined();
      expect(actionYml.inputs['lock-files'].description).toContain(
        'lock files'
      );
      expect(actionYml.inputs['lock-files'].required).toBe(false);
    });

    test('all required inputs defined (5 inputs)', () => {
      const inputKeys = Object.keys(actionYml.inputs);
      expect(inputKeys).toContain('fail-on');
      expect(inputKeys).toContain('ecosystems');
      expect(inputKeys).toContain('db-snapshot');
      expect(inputKeys).toContain('token');
      expect(inputKeys).toContain('lock-files');
    });
  });

  describe('Output Definitions', () => {
    test('findings output is defined', () => {
      expect(actionYml.outputs.findings).toBeDefined();
      expect(actionYml.outputs.findings.description).toContain('JSON');
      expect(actionYml.outputs.findings.value).toContain('findings');
    });

    test('summary output is defined', () => {
      expect(actionYml.outputs.summary).toBeDefined();
      expect(actionYml.outputs.summary.description).toContain('summary');
      expect(actionYml.outputs.summary.value).toContain('summary');
    });

    test('exit-code output is defined', () => {
      expect(actionYml.outputs['exit-code']).toBeDefined();
      expect(actionYml.outputs['exit-code'].description.toLowerCase()).toContain(
        'exit'
      );
      expect(actionYml.outputs['exit-code'].value).toContain('exit-code');
    });

    test('all required outputs defined (3 outputs)', () => {
      const outputKeys = Object.keys(actionYml.outputs);
      expect(outputKeys).toContain('findings');
      expect(outputKeys).toContain('summary');
      expect(outputKeys).toContain('exit-code');
    });
  });

  test('runs configuration is valid', () => {
    expect(actionYml.runs).toBeDefined();
    expect(actionYml.runs.using).toBe('node20');
    expect(actionYml.runs.main).toBe('dist/index.js');
  });
});

// ============================================================================
// Test Suite: Thin CLI Wrapper Behavior
// ============================================================================

describe('Thin CLI Wrapper — index.js', () => {
  let actionModule;

  beforeAll(() => {
    // Load the module after mocks are set up
    actionModule = require('../index.js');
  });

  beforeEach(() => {
    jest.clearAllMocks();

    // Default: no lock files found
    glob.create.mockResolvedValue({
      glob: async () => [],
    });
    exec.exec.mockResolvedValue(0);
    core.getInput.mockImplementation((name) => {
      const defaults = {
        'lock-files':
          '**/package-lock.json,**/yarn.lock,**/pnpm-lock.yaml,**/Pipfile.lock,**/poetry.lock,**/uv.lock,**/requirements.txt',
        'fail-on': 'high',
      };
      return defaults[name] || '';
    });
  });

  // --------------------------------------------------------------------------
  // Module structure
  // --------------------------------------------------------------------------

  test('exports expected functions', () => {
    expect(actionModule.run).toBeDefined();
    expect(typeof actionModule.run).toBe('function');
    expect(actionModule.shouldFailOnThreat).toBeDefined();
    expect(actionModule.buildSummary).toBeDefined();
  });

  // --------------------------------------------------------------------------
  // shouldFailOnThreat
  // --------------------------------------------------------------------------

  describe('shouldFailOnThreat', () => {
    test('returns true for "critical"', () => {
      expect(actionModule.shouldFailOnThreat('critical')).toBe(true);
    });

    test('returns true for "high"', () => {
      expect(actionModule.shouldFailOnThreat('high')).toBe(true);
    });

    test('returns false for "medium"', () => {
      expect(actionModule.shouldFailOnThreat('medium')).toBe(false);
    });

    test('returns false for "low"', () => {
      expect(actionModule.shouldFailOnThreat('low')).toBe(false);
    });

    test('returns false for "none"', () => {
      expect(actionModule.shouldFailOnThreat('none')).toBe(false);
    });

    test('is case insensitive', () => {
      expect(actionModule.shouldFailOnThreat('CRITICAL')).toBe(true);
      expect(actionModule.shouldFailOnThreat('HIGH')).toBe(true);
      expect(actionModule.shouldFailOnThreat('Medium')).toBe(false);
    });
  });

  // --------------------------------------------------------------------------
  // buildSummary
  // --------------------------------------------------------------------------

  describe('buildSummary', () => {
    test('returns safe message for empty findings', () => {
      expect(actionModule.buildSummary([])).toBe(
        'No security threats found. All packages are safe.'
      );
    });

    test('counts findings by severity', () => {
      const findings = [
        { severity: 'critical', package: 'CVE-1' },
        { severity: 'critical', package: 'CVE-2' },
        { severity: 'high', package: 'CVE-3' },
        { severity: 'medium', package: 'Issue-1' },
        { severity: 'low', package: 'Issue-2' },
      ];
      expect(actionModule.buildSummary(findings)).toBe(
        '5 threats found: 2 CRITICAL, 1 HIGH, 1 MEDIUM, 1 LOW'
      );
    });

    test('handles single finding', () => {
      const findings = [{ severity: 'critical', package: 'CVE-1' }];
      expect(actionModule.buildSummary(findings)).toBe(
        '1 threats found: 1 CRITICAL'
      );
    });
  });

  // --------------------------------------------------------------------------
  // run() — workflow
  // --------------------------------------------------------------------------

  describe('run() — installation', () => {
    test('installs pkg-defender via pip', async () => {
      await actionModule.run();
      expect(exec.exec).toHaveBeenCalledWith('pip', [
        'install',
        'pkg-defender',
      ]);
    });

    test('runs pkgd --ci setup', async () => {
      await actionModule.run();
      expect(exec.exec).toHaveBeenCalledWith('pkgd', ['--ci', 'setup']);
    });
  });

  describe('run() — glob resolution', () => {
    test('creates globber from lock-files input', async () => {
      await actionModule.run();
      expect(glob.create).toHaveBeenCalledWith(
        '**/package-lock.json,**/yarn.lock,**/pnpm-lock.yaml,**/Pipfile.lock,**/poetry.lock,**/uv.lock,**/requirements.txt'
      );
    });

    test('warns when no lock files found', async () => {
      glob.create.mockResolvedValue({
        glob: async () => [],
      });

      await actionModule.run();
      expect(core.warning).toHaveBeenCalledWith(
        expect.stringContaining('No lock files found')
      );
    });

    test('sets exit-code 0 when no lock files found', async () => {
      glob.create.mockResolvedValue({
        glob: async () => [],
      });

      await actionModule.run();
      expect(core.setOutput).toHaveBeenCalledWith('exit-code', '0');
    });
  });

  describe('run() — audit execution', () => {
    const lockFile1 = '/workspace/package-lock.json';
    const lockFile2 = '/workspace/poetry.lock';

    beforeEach(() => {
      glob.create.mockResolvedValue({
        glob: async () => [lockFile1, lockFile2],
      });
    });

    test('runs pkgd audit with --ci, --json, and --fail-on-threat for high threshold', async () => {
      // exec.mockImplementation captures calls by args
      const execCalls = [];
      exec.exec.mockImplementation(async (cmd, args) => {
        execCalls.push({ cmd, args });
        return 0;
      });

      await actionModule.run();

      // pip install + pkgd setup + 2 audits
      expect(execCalls.length).toBe(4);

      // Check the audit commands
      const auditCalls = execCalls.filter(
        (c) => c.cmd === 'pkgd' && c.args[1] === 'audit'
      );
      expect(auditCalls.length).toBe(2);

      // First audit: package-lock.json
      expect(auditCalls[0].args).toEqual([
        '--ci',
        'audit',
        lockFile1,
        '--json',
        '--fail-on-threat',
      ]);

      // Second audit: poetry.lock
      expect(auditCalls[1].args).toEqual([
        '--ci',
        'audit',
        lockFile2,
        '--json',
        '--fail-on-threat',
      ]);
    });

    test('passes --fail-on-threat when fail-on is critical', async () => {
      core.getInput.mockImplementation((name) => {
        const defaults = {
          'lock-files': '**/package-lock.json',
          'fail-on': 'critical',
        };
        return defaults[name] || '';
      });

      const execCalls = [];
      exec.exec.mockImplementation(async (cmd, args) => {
        execCalls.push({ cmd, args });
        return 0;
      });

      await actionModule.run();

      const auditArgs = execCalls.find(
        (c) => c.cmd === 'pkgd' && c.args[1] === 'audit'
      ).args;
      expect(auditArgs).toContain('--fail-on-threat');
    });

    test('omits --fail-on-threat when fail-on is medium', async () => {
      core.getInput.mockImplementation((name) => {
        const defaults = {
          'lock-files': '**/package-lock.json',
          'fail-on': 'medium',
        };
        return defaults[name] || '';
      });

      const execCalls = [];
      exec.exec.mockImplementation(async (cmd, args) => {
        execCalls.push({ cmd, args });
        return 0;
      });

      await actionModule.run();

      const auditArgs = execCalls.find(
        (c) => c.cmd === 'pkgd' && c.args[1] === 'audit'
      ).args;
      expect(auditArgs).not.toContain('--fail-on-threat');
    });
  });

  describe('run() — exit code propagation', () => {
    const lockFile = '/workspace/package-lock.json';

    beforeEach(() => {
      glob.create.mockResolvedValue({
        glob: async () => [lockFile],
      });
    });

    test('sets exit-code 0 and summary when audit passes', async () => {
      const mockOutput = JSON.stringify({
        lock_file: lockFile,
        total: 10,
        threats: [],
        cooldown_pending: [],
      });
      exec.exec.mockImplementation(async (_cmd, _args, options) => {
        // Only supply output for audit calls (options is undefined for pip/setup)
        if (options && options.listeners && options.listeners.stdout) {
          options.listeners.stdout(mockOutput);
        }
        return 0;
      });

      await actionModule.run();

      expect(core.setOutput).toHaveBeenCalledWith('exit-code', '0');
      expect(core.setOutput).toHaveBeenCalledWith(
        'summary',
        'No security threats found. All packages are safe.'
      );
      expect(core.setFailed).not.toHaveBeenCalled();
    });

    test('sets exit-code 4 and calls setFailed when threat detected', async () => {
      const mockOutput = JSON.stringify({
        lock_file: lockFile,
        total: 10,
        threats: [
          {
            package: 'evil-pkg',
            version: '1.0.0',
            ecosystem: 'npm',
            severity: 'CRITICAL',
            threats: [
              {
                severity: 'CRITICAL',
                summary: 'Remote code execution',
                source: 'CVE-2024-0001',
              },
            ],
          },
        ],
        cooldown_pending: [],
      });
      exec.exec.mockImplementation(async (_cmd, _args, options) => {
        // Only supply output for audit calls (options is undefined for pip/setup)
        if (options && options.listeners && options.listeners.stdout) {
          options.listeners.stdout(mockOutput);
        }
        return 4;
      });

      await actionModule.run();

      expect(core.setOutput).toHaveBeenCalledWith('exit-code', '4');
      expect(core.setOutput).toHaveBeenCalledWith(
        'summary',
        expect.stringContaining('1 threats found')
      );
      expect(core.setFailed).toHaveBeenCalledWith(
        expect.stringContaining('threats')
      );
    });

    test('propagates actual exit code when non-4 failure code returned', async () => {
      const mockOutput = JSON.stringify({
        lock_file: lockFile,
        total: 5,
        threats: [
          {
            package: 'bad-pkg',
            version: '2.0.0',
            ecosystem: 'npm',
            severity: 'HIGH',
            threats: [],
          },
        ],
        cooldown_pending: [],
      });
      exec.exec.mockImplementation(async (_cmd, _args, options) => {
        if (options && options.listeners && options.listeners.stdout) {
          options.listeners.stdout(mockOutput);
        }
        return 3;
      });

      await actionModule.run();

      // Must output '3' (the actual code), not '4' (the old hardcoded fallback)
      expect(core.setOutput).toHaveBeenCalledWith('exit-code', '3');
      expect(core.setFailed).toHaveBeenCalled();
    });

    test('aggregates findings from multiple lock files', async () => {
      glob.create.mockResolvedValue({
        glob: async () => ['/workspace/a.json', '/workspace/b.json'],
      });

      const outputs = {
        '/workspace/a.json': JSON.stringify({
          threats: [
            {
              package: 'pkg-a',
              version: '1.0.0',
              ecosystem: 'npm',
              severity: 'HIGH',
              threats: [],
            },
          ],
        }),
        '/workspace/b.json': JSON.stringify({
          threats: [
            {
              package: 'pkg-b',
              version: '2.0.0',
              ecosystem: 'cargo',
              severity: 'CRITICAL',
              threats: [],
            },
          ],
        }),
      };

      let callCount = 0;
      exec.exec.mockImplementation(async (_cmd, args, options) => {
        if (args[1] === 'audit' && options && options.listeners && options.listeners.stdout) {
          const output = outputs[args[2]] || '{}';
          options.listeners.stdout(output);
        }
        callCount++;
        return callCount >= 3 ? 4 : 0; // 2nd audit fails
      });

      await actionModule.run();

      const findingsCall = core.setOutput.mock.calls.find(
        (c) => c[0] === 'findings'
      );
      expect(findingsCall).toBeDefined();
      const findings = JSON.parse(findingsCall[1]);
      expect(findings.length).toBe(2);
      expect(findings[0].package).toBe('pkg-a');
      expect(findings[1].package).toBe('pkg-b');
      expect(core.setOutput).toHaveBeenCalledWith('exit-code', '4');
    });

    test('handles empty JSON output gracefully', async () => {
      exec.exec.mockImplementation(async (_cmd, _args, options) => {
        if (options && options.listeners && options.listeners.stdout) {
          options.listeners.stdout('');
        }
        return 0;
      });

      // Should not throw
      await expect(actionModule.run()).resolves.toBeUndefined();
    });

    test('handles malformed JSON output gracefully', async () => {
      exec.exec.mockImplementation(async (_cmd, _args, options) => {
        if (options && options.listeners && options.listeners.stdout) {
          options.listeners.stdout('not valid json');
        }
        return 0;
      });

      // Should not throw
      await expect(actionModule.run()).resolves.toBeUndefined();
    });
  });

  describe('run() — error handling', () => {
    test('calls core.setFailed when exec throws', async () => {
      exec.exec.mockRejectedValue(new Error('pip install failed'));

      await actionModule.run();

      expect(core.setFailed).toHaveBeenCalledWith(
        expect.stringContaining('pip install failed')
      );
    });

    test('calls core.setFailed when glob.create throws', async () => {
      glob.create.mockRejectedValue(new Error('Invalid glob pattern'));

      await actionModule.run();

      expect(core.setFailed).toHaveBeenCalledWith(
        expect.stringContaining('Invalid glob pattern')
      );
    });
  });
});
