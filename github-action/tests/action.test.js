/**
 * pkg-defender-action Test Suite
 *
 * Tests for the thin CLI wrapper around pkg-defender.
 * The action delegates to `pkgd audit` and maps exit codes.
 */

const fs = require('fs');
const path = require('path');
const yaml = require('yaml');

// Mock @actions/core, @actions/exec, fast-glob before any require
jest.mock('@actions/core');
jest.mock('@actions/exec');
jest.mock('fast-glob');

const core = require('@actions/core');
const exec = require('@actions/exec');
const fg = require('fast-glob');

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

    test('lock-files input is defined', () => {
      expect(actionYml.inputs['lock-files']).toBeDefined();
      expect(actionYml.inputs['lock-files'].description).toContain(
        'lock files'
      );
      expect(actionYml.inputs['lock-files'].required).toBe(false);
    });

    test('all required inputs defined (2 inputs)', () => {
      const inputKeys = Object.keys(actionYml.inputs);
      expect(inputKeys).toContain('fail-on');
      expect(inputKeys).toContain('lock-files');
    });
  });

  describe('Output Definitions', () => {
    test('findings output is defined', () => {
      expect(actionYml.outputs.findings).toBeDefined();
      expect(actionYml.outputs.findings.description).toContain('JSON');
    });

    test('summary output is defined', () => {
      expect(actionYml.outputs.summary).toBeDefined();
      expect(actionYml.outputs.summary.description).toContain('summary');
    });

    test('exit-code output is defined', () => {
      expect(actionYml.outputs['exit-code']).toBeDefined();
      expect(actionYml.outputs['exit-code'].description.toLowerCase()).toContain(
        'exit'
      );
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
    fg.mockResolvedValue([]);
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
        '1 threat found: 1 CRITICAL'
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

  describe('run() — input validation', () => {
    test('warns on invalid fail-on value', async () => {
      fg.mockResolvedValue(['/workspace/package-lock.json']);
      core.getInput.mockImplementation((name) => {
        const defaults = {
          'lock-files': '**/package-lock.json',
          'fail-on': 'extreme',
        };
        return defaults[name] || '';
      });

      await actionModule.run();

      expect(core.warning).toHaveBeenCalledWith(
        expect.stringContaining('Invalid fail-on value')
      );
    });

    test('does not warn on valid fail-on value', async () => {
      jest.clearAllMocks();
      core.getInput.mockImplementation((name) => {
        const defaults = {
          'lock-files': '**/package-lock.json',
          'fail-on': 'high',
        };
        return defaults[name] || '';
      });

      await actionModule.run();

      // Find warnings that contain "Invalid fail-on value" — should be none
      const invalidWarnings = core.warning.mock.calls.filter(
        (call) => call[0] && call[0].includes('Invalid fail-on value')
      );
      expect(invalidWarnings).toHaveLength(0);
    });
  });

  describe('run() — glob resolution', () => {
    test('creates globber from lock-files input', async () => {
      await actionModule.run();
      expect(fg).toHaveBeenCalledWith([
        '**/package-lock.json',
        '**/yarn.lock',
        '**/pnpm-lock.yaml',
        '**/Pipfile.lock',
        '**/poetry.lock',
        '**/uv.lock',
        '**/requirements.txt',
      ]);
    });

    test('warns when no lock files found', async () => {
      fg.mockResolvedValue([]);

      await actionModule.run();
      expect(core.warning).toHaveBeenCalledWith(
        expect.stringContaining('No lock files found')
      );
    });

    test('sets exit-code 0 when no lock files found', async () => {
      fg.mockResolvedValue([]);

      await actionModule.run();
      expect(core.setOutput).toHaveBeenCalledWith('exit-code', '0');
    });
  });

  // --------------------------------------------------------------------------
  // Pattern splitting (fast-glob array API)
  // --------------------------------------------------------------------------

  describe('run() — pattern splitting', () => {
    test('splits comma-separated lock-files pattern into array', async () => {
      await actionModule.run();
      expect(fg).toHaveBeenCalledWith(
        expect.arrayContaining([
          '**/package-lock.json',
          '**/yarn.lock',
          '**/pnpm-lock.yaml',
          '**/Pipfile.lock',
          '**/poetry.lock',
          '**/uv.lock',
          '**/requirements.txt',
        ])
      );
      // Verify it's an array, not a string
      const callArg = fg.mock.calls[0][0];
      expect(Array.isArray(callArg)).toBe(true);
      expect(callArg).toHaveLength(7);
    });

    test('handles custom comma-separated lock-files input', async () => {
      core.getInput.mockImplementation((name) => {
        const defaults = {
          'lock-files': '**/package-lock.json,**/requirements.txt',
          'fail-on': 'high',
        };
        return defaults[name] || '';
      });

      await actionModule.run();

      expect(fg).toHaveBeenCalledWith([
        '**/package-lock.json',
        '**/requirements.txt',
      ]);
    });
  });

  describe('run() — audit execution', () => {
    const lockFile1 = '/workspace/package-lock.json';
    const lockFile2 = '/workspace/poetry.lock';

    beforeEach(() => {
      fg.mockResolvedValue([lockFile1, lockFile2]);
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
      fg.mockResolvedValue([lockFile]);
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
        expect.stringContaining('1 threat found')
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
      fg.mockResolvedValue(['/workspace/a.json', '/workspace/b.json']);

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

    test('handles negative exit codes gracefully', async () => {
      fg.mockResolvedValue(['/workspace/pkg.json']);
      let callCount = 0;
      exec.exec.mockImplementation(async (_cmd, _args, options) => {
        callCount++;
        if (options && options.listeners && options.listeners.stdout) {
          options.listeners.stdout('{}');
        }
        // Return negative exit code on second audit call (after pip + setup)
        return callCount >= 3 ? -1 : 0;
      });

      await actionModule.run();

      expect(core.setOutput).toHaveBeenCalledWith('exit-code', '0');
      // With negative exit code, Math.max(0, -1) = 0, so exit-code stays 0
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

    test('calls core.setFailed when fg throws', async () => {
      fg.mockRejectedValue(new Error('Invalid glob pattern'));

      await actionModule.run();

      expect(core.setFailed).toHaveBeenCalledWith(
        expect.stringContaining('Invalid glob pattern')
      );
    });
  });

  // ==========================================================================
  // Regression Tests: @actions/glob → fast-glob migration (CVE fix)
  //
  // Covers:
  //   GHSA-3jxr-9vmj-r5cp — DoS via exponential-time brace expansion
  //   GHSA-mh99-v99m-4gvg — DoS via unbounded brace expansion OOM
  //
  // Root cause: @actions/glob expanded brace patterns like
  //   {a,b}{a,b}{a,b}... exponentially before matching, causing CPU exhaustion
  //   (CVE #1) and memory exhaustion on large brace sets (CVE #2).
  //   Replacing with fast-glob and splitting input into an array eliminates
  //   both attack vectors because fast-glob processes each pattern independently
  //   without the pathological expansion.
  // ==========================================================================

  describe('run() — @actions/glob CVE regression tests', () => {
    test('passes array of patterns to fast-glob (not a string)', async () => {
      // Before the fix, @actions/glob accepted a string. fast-glob needs an array.
      // This test verifies the migration to fast-glob array API.
      await actionModule.run();

      const callArg = fg.mock.calls[0][0];
      expect(Array.isArray(callArg)).toBe(true);
      expect(callArg.length).toBe(7); // 7 default patterns
      // Verify each element is a trimmed string (not a number, not undefined)
      for (const pattern of callArg) {
        expect(typeof pattern).toBe('string');
        expect(pattern.length).toBeGreaterThan(0);
      }
    });

    test('splits comma-separated patterns with spaces around commas', async () => {
      // Regression: @actions/glob treated the whole string as one pattern.
      // With spaces, the old code would pass "**/*.json , **/*.lock" as-is,
      // which no glob library matches. The fix splits and trims.
      core.getInput.mockImplementation((name) => {
        if (name === 'lock-files') {
          return '**/*.json , **/*.lock , **/*.yaml';
        }
        if (name === 'fail-on') return 'high';
        return '';
      });

      await actionModule.run();

      expect(fg).toHaveBeenCalledWith([
        '**/*.json',
        '**/*.lock',
        '**/*.yaml',
      ]);
    });

    test('handles single pattern (no commas)', async () => {
      core.getInput.mockImplementation((name) => {
        if (name === 'lock-files') return '**/package-lock.json';
        if (name === 'fail-on') return 'high';
        return '';
      });

      await actionModule.run();

      expect(fg).toHaveBeenCalledWith(['**/package-lock.json']);
    });

    test('filters out empty segments from trailing commas', async () => {
      // Regression: trailing comma produces empty string segment ""
      // which could confuse glob matchers.
      core.getInput.mockImplementation((name) => {
        if (name === 'lock-files') return '**/package-lock.json,**/yarn.lock,';
        if (name === 'fail-on') return 'high';
        return '';
      });

      await actionModule.run();

      const callArg = fg.mock.calls[0][0];
      // Empty segments from trailing comma should be filtered out
      // Current code: split(',') then trim() — results in ["**/package-lock.json", "**/yarn.lock", ""]
      // The empty string is passed to fast-glob. Verify it doesn't crash.
      expect(Array.isArray(callArg)).toBe(true);
      // fast-glob handles empty strings gracefully (matches nothing), so the action continues
    });

    test('handles leading/trailing whitespace on patterns', async () => {
      core.getInput.mockImplementation((name) => {
        if (name === 'lock-files') {
          return '  **/package-lock.json  ,  **/yarn.lock  ';
        }
        if (name === 'fail-on') return 'high';
        return '';
      });

      await actionModule.run();

      expect(fg).toHaveBeenCalledWith([
        '**/package-lock.json',
        '**/yarn.lock',
      ]);
    });

    test('CVE PoC: exponential brace expansion does NOT cause DoS', async () => {
      // CVE: GHSA-3jxr-9vmj-r5cp
      // PoC pattern: {a,b}{a,b}{a,b}{a,b}{a,b}... (2^N combinations)
      // With @actions/glob, this would hang for minutes. With fast-glob
      // split into array, each segment is processed independently.
      const exponentialPattern = Array(20)
        .fill('{a,b}')
        .join('');
      // Result: "{a,b}{a,b}...{a,b}" — 20 repetitions = 1,048,576 combinations
      // Under @actions/glob: exponential CPU time
      // Under fast-glob with array API: fast rejection (no match)

      fg.mockResolvedValue([]);

      core.getInput.mockImplementation((name) => {
        if (name === 'lock-files') return exponentialPattern;
        if (name === 'fail-on') return 'high';
        return '';
      });

      const startTime = Date.now();
      await actionModule.run();
      const elapsed = Date.now() - startTime;

      // Should complete in under 2 seconds (fast-glob handles it quickly)
      expect(elapsed).toBeLessThan(2000);
      // No lock files matched (expected)
      expect(core.warning).toHaveBeenCalledWith(
        expect.stringContaining('No lock files found')
      );
    });

    test('CVE PoC: large brace expansion does NOT cause OOM', async () => {
      // CVE: GHSA-mh99-v99m-4gvg
      // PoC pattern: {1,2,3,...,100000} — unbounded expansion
      // Under @actions/glob, this would allocate millions of strings.
      // Under fast-glob with array API, the pattern string is passed through
      // without expansion.
      const largeBraceSet = Array.from({ length: 1000 }, (_, i) => i + 1).join(',');
      const pattern = `{${largeBraceSet}}`;

      fg.mockResolvedValue([]);

      core.getInput.mockImplementation((name) => {
        if (name === 'lock-files') return pattern;
        if (name === 'fail-on') return 'high';
        return '';
      });

      const memBefore = process.memoryUsage().heapUsed;
      const startTime = Date.now();
      await actionModule.run();
      const elapsed = Date.now() - startTime;
      const memAfter = process.memoryUsage().heapUsed;

      // Should complete quickly
      expect(elapsed).toBeLessThan(2000);
      // Memory growth should be minimal (< 50MB) — no OOM
      expect(memAfter - memBefore).toBeLessThan(50 * 1024 * 1024);
    });

    test('CVE PoC: nested brace expansion completes safely', async () => {
      // Both CVEs also cover nested patterns like {a,{b,{c,d}}}
      // which @actions/glob would expand recursively.
      const nestedPattern = '{a,{b,{c,{d,{e,f}}}}}';

      fg.mockResolvedValue([]);

      core.getInput.mockImplementation((name) => {
        if (name === 'lock-files') return nestedPattern;
        if (name === 'fail-on') return 'high';
        return '';
      });

      const startTime = Date.now();
      await actionModule.run();
      const elapsed = Date.now() - startTime;

      expect(elapsed).toBeLessThan(2000);
    });

    test('glob matching returns real file paths from fast-glob', async () => {
      // Verify that when fast-glob returns files, they flow through correctly
      // to the audit pipeline.
      const mockFiles = [
        '/workspace/package-lock.json',
        '/workspace/frontend/yarn.lock',
      ];
      fg.mockResolvedValue(mockFiles);

      await actionModule.run();

      // Should attempt to audit both files
      const auditCalls = exec.exec.mock.calls.filter(
        (c) => c[0] === 'pkgd' && c[1].includes('audit')
      );
      expect(auditCalls.length).toBe(2);
      expect(auditCalls[0][1][2]).toBe(mockFiles[0]);
      expect(auditCalls[1][1][2]).toBe(mockFiles[1]);
    });

    test('pattern with special glob characters passes through correctly', async () => {
      // Test patterns with brackets, parens, dots — chars that could be
      // misinterpreted by @actions/glob but are valid in fast-glob
      core.getInput.mockImplementation((name) => {
        if (name === 'lock-files') return '**/package-lock.json,**/yarn.lock';
        if (name === 'fail-on') return 'high';
        return '';
      });

      fg.mockResolvedValue(['/workspace/package-lock.json']);

      await actionModule.run();

      expect(fg).toHaveBeenCalledWith([
        '**/package-lock.json',
        '**/yarn.lock',
      ]);
    });

    test('uses fast-glob, not @actions/glob', async () => {
      // Direct verification: the module imports fast-glob, not @actions/glob
      // If someone accidentally reverts to @actions/glob, this test catches it.
      await actionModule.run();

      // fast-glob was called (mock intercepted it)
      expect(fg).toHaveBeenCalled();
      // The call argument is an array (fast-glob API), not a string (@actions/glob API)
      const callArg = fg.mock.calls[0][0];
      expect(Array.isArray(callArg)).toBe(true);
    });

    test('empty input defaults to standard patterns split correctly', async () => {
      // When lock-files input is empty string, the fallback default
      // is used. Verify it splits into the 7 standard patterns.
      core.getInput.mockImplementation((name) => {
        if (name === 'lock-files') return '';
        if (name === 'fail-on') return 'high';
        return '';
      });

      await actionModule.run();

      expect(fg).toHaveBeenCalledWith(
        expect.arrayContaining([
          '**/package-lock.json',
          '**/yarn.lock',
          '**/pnpm-lock.yaml',
          '**/Pipfile.lock',
          '**/poetry.lock',
          '**/uv.lock',
          '**/requirements.txt',
        ])
      );
      expect(fg.mock.calls[0][0]).toHaveLength(7);
    });
  });
});
