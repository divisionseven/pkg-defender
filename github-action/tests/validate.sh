#!/bin/bash
# Validation script for GitHub Action
# Tests the action's contract — validates action.yml structure and dist bundle

# Exit on any error
set -e

echo "=== GitHub Action Validation ==="
echo ""

# Test 1: action.yml exists and is valid YAML
echo "Test 1: Validating action.yml..."
if [ -f "action.yml" ]; then
    if python3 -c "import yaml; yaml.safe_load(open('action.yml'))" 2>/dev/null; then
        echo "  ✓ action.yml is valid YAML"
    else
        echo "  ✗ action.yml is NOT valid YAML"
        exit 1
    fi
else
    echo "  ✗ action.yml missing"
    exit 1
fi

# Test 2: Verify all required inputs defined
echo "Test 2: Checking required inputs..."
REQUIRED_INPUTS=("fail-on" "ecosystems" "db-snapshot" "token" "lock-files")
for input in "${REQUIRED_INPUTS[@]}"; do
    if grep -q "$input:" action.yml; then
        echo "  ✓ Input '$input' is defined"
    else
        echo "  ✗ Input '$input' is missing"
        exit 1
    fi
done

# Test 3: Verify all required outputs defined
echo "Test 3: Checking required outputs..."
REQUIRED_OUTPUTS=("findings" "summary" "exit-code")
for output in "${REQUIRED_OUTPUTS[@]}"; do
    if grep -q "$output:" action.yml; then
        echo "  ✓ Output '$output' is defined"
    else
        echo "  ✗ Output '$output' is missing"
        exit 1
    fi
done

# Test 4: Verify dist/index.js exists
echo "Test 4: Checking compiled action..."
if [ -f "dist/index.js" ]; then
    SIZE=$(stat -f%z dist/index.js 2>/dev/null || stat -c%s dist/index.js)
    echo "  ✓ dist/index.js exists ($SIZE bytes)"
else
    echo "  ✗ dist/index.js missing - run 'npm run package'"
    exit 1
fi

# Test 5: Verify wrapper delegates to pip-installed pkgd
echo "Test 5: Verifying thin wrapper structure..."
if grep -q "exec.exec('pip'" index.js; then
    echo "  ✓ Action installs pkgd via pip"
else
    echo "  ✗ pip install pattern not found in index.js"
    exit 1
fi

if grep -q "pkgd.*audit" index.js; then
    echo "  ✓ Action delegates to pkgd audit"
else
    echo "  ✗ pkgd audit delegation not found in index.js"
    exit 1
fi

# Test 6: Verify package.json has the right dependencies
echo "Test 6: Checking thin wrapper dependencies..."
DEPS=("@actions/core" "@actions/exec" "@actions/glob")
for dep in "${DEPS[@]}"; do
    if grep -q "$dep" package.json; then
        echo "  ✓ Dependency '$dep' present"
    else
        echo "  ✗ Dependency '$dep' missing"
        exit 1
    fi
done

# Warn if legacy heavy dependencies reappear in package.json
OLD_DEPS=("@actions/cache" "@actions/github" "@actions/tool-cache")
for dep in "${OLD_DEPS[@]}"; do
    if grep -q "$dep" package.json; then
        echo "  ⚠ Note: '$dep' still in package.json (may be unused)"
    fi
done

echo ""
echo "=== All Validation Tests Passed ==="
