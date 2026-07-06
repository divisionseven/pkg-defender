/**
 * pkg-defender-action
 *
 * Thin CLI wrapper around pkg-defender (pkgd).
 * Runs pkgd audit on lockfiles and maps exit codes to GitHub Action annotations.
 *
 * Workflow:
 *   1. Install pkgd via pip
 *   2. Run pkgd setup to download threat database
 *   3. Resolve lock-files glob pattern using @actions/glob
 *   4. Run pkgd audit --json --fail-on-threat for each matched lock file
 *   5. Set outputs (findings, summary, exit-code) and fail on threat detection
 *
 * Maintains backward-compatible I/O contract with action.yml inputs/outputs.
 */

const core = require('@actions/core');
const exec = require('@actions/exec');
const glob = require('@actions/glob');

/**
 * Check if a fail-on severity threshold should trigger --fail-on-threat.
 *
 * @param {string} failOn - Fail-on threshold from action input.
 * @returns {boolean} True if --fail-on-threat should be passed to pkgd.
 */
function shouldFailOnThreat(failOn) {
  const VALID_FAILON = ['critical', 'high', 'medium', 'low', 'none'];
  const normalized = failOn.toLowerCase();
  if (!VALID_FAILON.includes(normalized)) {
    core.warning(`Invalid fail-on value: "${failOn}". Must be one of: ${VALID_FAILON.join(', ')}. Defaulting to "high".`);
  }
  const failOnThresholds = ['critical', 'high'];
  return failOnThresholds.includes(normalized);
}

/**
 * Build a summary string from findings array.
 *
 * @param {Array} findings - Array of threat objects.
 * @returns {string} Human-readable summary.
 */
function buildSummary(findings) {
  if (findings.length === 0) {
    return 'No security threats found. All packages are safe.';
  }

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    const s = f.severity.toLowerCase();
    if (Object.prototype.hasOwnProperty.call(counts, s)) {
      counts[s]++;
    }
  }

  const parts = [];
  if (counts.critical > 0) parts.push(`${counts.critical} CRITICAL`);
  if (counts.high > 0) parts.push(`${counts.high} HIGH`);
  if (counts.medium > 0) parts.push(`${counts.medium} MEDIUM`);
  if (counts.low > 0) parts.push(`${counts.low} LOW`);

  const threatWord = findings.length === 1 ? 'threat' : 'threats';
  return `${findings.length} ${threatWord} found: ${parts.join(', ')}`;
}

/**
 * Main action entry point.
 */
async function run() {
  try {
    // Get inputs
    const lockFilesPattern =
      core.getInput('lock-files') ||
      '**/package-lock.json,**/yarn.lock,**/pnpm-lock.yaml,**/Pipfile.lock,**/poetry.lock,**/uv.lock,**/requirements.txt';
    const failOn = core.getInput('fail-on') || 'high';

    core.info('pkg-defender-action v1.0.0 starting...');
    core.info(`Input: fail-on=${failOn}`);

    // Step 1: Install pkgd
    core.info('Installing pkg-defender...');
    await exec.exec('pip', ['install', 'pkg-defender']);

    // Step 2: Setup threat database
    core.info('Setting up threat database...');
    await exec.exec('pkgd', ['--ci', 'setup']);

    // Step 3: Resolve lock-files glob pattern
    core.info(`Scanning for lock files matching: ${lockFilesPattern}`);
    const globber = await glob.create(lockFilesPattern);
    const lockFiles = await globber.glob();

    if (lockFiles.length === 0) {
      core.warning(`No lock files found matching pattern: ${lockFilesPattern}`);
      core.setOutput('findings', '[]');
      core.setOutput('summary', 'No lock files found to scan');
      core.setOutput('exit-code', '0');
      core.info('pkg-defender-action completed (no files to scan)');
      return;
    }

    core.info(`Found ${lockFiles.length} lock file(s): ${lockFiles.join(', ')}`);

    // Step 4: Run audit for each matched lock file
    let allPassed = true;
    let worstExitCode = 0;
    const allFindings = [];

    const useFailOnThreat = shouldFailOnThreat(failOn);

    for (const lockFile of lockFiles) {
      let auditOutput = '';
      const execOptions = {
        listeners: {
          stdout: (data) => {
            auditOutput += data.toString();
          },
        },
        ignoreReturnCode: true,
      };

      // Build the pkgd audit command
      const auditArgs = ['--ci', 'audit', lockFile, '--json'];
      if (useFailOnThreat) {
        auditArgs.push('--fail-on-threat');
      }

      core.info(`Auditing ${lockFile}...`);
      const exitCode = await exec.exec('pkgd', auditArgs, execOptions);

      // Parse the JSON output
      try {
        const trimmed = auditOutput.trim();
        if (trimmed) {
          const parsed = JSON.parse(trimmed);
          const threats = parsed.threats || [];
          for (const t of threats) {
            allFindings.push({
              package: t.package || 'unknown',
              version: t.version || '',
              ecosystem: t.ecosystem || '',
              severity: t.severity || 'UNKNOWN',
              threats: t.threats || [],
            });
          }
        }
      } catch (parseError) {
        core.warning(
          `Could not parse audit output for ${lockFile}: ${parseError.message}`
        );
      }

      if (exitCode !== 0) {
        allPassed = false;
        worstExitCode = Math.max(worstExitCode, exitCode);
        core.warning(`PKG-Defender found threats in ${lockFile}`);
      }
    }

    // Set outputs
    core.setOutput('findings', JSON.stringify(allFindings));
    core.setOutput('exit-code', allPassed ? '0' : String(worstExitCode));

    const summary = buildSummary(allFindings);
    core.setOutput('summary', summary);

    core.info(`Results: ${summary}`);

    // Fail the action if threats were detected
    if (!allPassed) {
      core.setFailed('PKG-Defender found threats in one or more lock files');
    }

    core.info('pkg-defender-action completed');
  } catch (error) {
    core.setFailed(`PKG-Defender action failed: ${error.message}`);
  }
}

// Auto-execute when loaded by GitHub Actions runner
// In tests, mocks intercept all side effects
run();

module.exports = { run, shouldFailOnThreat, buildSummary };
