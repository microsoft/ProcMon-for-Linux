// Run with: node --test tests/packaging.test.cjs
// Requires CMake and Bash (override CMAKE_PATH and BASH_PATH on Windows).
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');

const source = path.resolve(__dirname, '..');
const cmake = process.env.CMAKE_PATH || 'cmake';
const bash = process.env.BASH_PATH || 'bash';
const posix = (file) => file.replaceAll('\\', '/').replace(/^([A-Za-z]):/, (_, drive) => `/${drive.toLowerCase()}`);
const quote = (value) => `'${value.replaceAll("'", "'\\''")}'`;
function fixture(run) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'procmon packaging '));
  try { return run(directory); } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
function command(executable, args, directory, env = {}) {
  const result = spawnSync(executable, args, {
    cwd: directory, env: { ...process.env, ...env }, encoding: 'utf8', timeout: 30000,
  });
  if (result.error) throw result.error;
  return result;
}
function passed(result) { assert.equal(result.status, 0, result.stdout + result.stderr); }

function configure(directory, processor) {
  const script = path.join(directory, 'configure.cmake');
  fs.writeFileSync(script, `
include("${source.replaceAll('\\', '/')}/cmake/PackageArchitecture.cmake")
set(PROJECT_VERSION_MAJOR 2)
set(PROJECT_VERSION_MINOR 2)
set(PROJECT_VERSION_PATCH 2)
configure_file("${source.replaceAll('\\', '/')}/dist/DEBIAN.in/control.in" DEBIANcontrol @ONLY)
`);
  return command(cmake, [`-DCMAKE_SYSTEM_PROCESSOR=${processor}`, '-P', script], directory);
}

function packageDeb(directory, failure = 0) {
  const script = path.join(directory, 'build-package.sh');
  fs.writeFileSync(script, `
set -e
dpkg-deb() {
  if [ "$MOCK_FAILURE" != 0 ]; then return "$MOCK_FAILURE"; fi
  for argument in "$@"; do package="$argument"; done
  test -f "$package/DEBIAN/control"
  test -f "$package/usr/bin/procmon"
  touch "$package.deb"
}
# Source in a POSIX-mode shell so dpkg-deb can be mocked without downloading
# or running a Linux package builder. All staging commands execute normally.
set -- ${quote(posix(source))} ${quote(posix(directory))} procmon 2.2.2 0 deb
. ${quote(posix(path.join(source, 'makePackages.sh')))}
`);
  return command(bash, ['--posix', posix(script)], directory, { MOCK_FAILURE: String(failure) });
}

function stageInputs(directory) {
  for (const file of ['procmon', 'procmon.1.gz', 'changelog.gz']) {
    fs.writeFileSync(path.join(directory, file), 'fixture');
  }
}

for (const [processor, architecture] of [['x86_64', 'amd64'], ['AMD64', 'amd64'], ['aarch64', 'arm64'], ['arm64', 'arm64']]) {
  test(`${processor}: CMake target controls both Debian metadata and filename`, () => fixture((directory) => {
    passed(configure(directory, processor));
    stageInputs(directory);
    passed(packageDeb(directory));
    const name = `procmon_2.2.2_${architecture}`;
    assert.ok(fs.existsSync(path.join(directory, 'deb', `${name}.deb`)));
    const control = fs.readFileSync(path.join(directory, 'deb', name, 'DEBIAN', 'control'), 'utf8');
    assert.match(control, new RegExp(`^Architecture: ${architecture}$`, 'm'));
    assert.doesNotMatch(control, /@DEB_ARCH@/);
    assert.equal(fs.readdirSync(path.join(directory, 'deb')).filter((file) => file.endsWith('.deb')).length, 1);
  }));
}

test('unsupported CMake target is rejected', () => fixture((directory) => {
  const result = configure(directory, 'unknown');
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Unsupported package architecture/);
}));

test('missing or unsupported control architecture is rejected', () => fixture((directory) => {
  stageInputs(directory);
  for (const control of ['Package: procmon\n', 'Architecture: unknown\n', 'Architecture: @DEB_ARCH@\n']) {
    fs.writeFileSync(path.join(directory, 'DEBIANcontrol'), control);
    const result = packageDeb(directory);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Unsupported or missing Debian architecture/);
  }
}));

test('dpkg-deb failure reaches the build job', () => fixture((directory) => {
  passed(configure(directory, 'aarch64'));
  stageInputs(directory);
  assert.equal(packageDeb(directory, 17).status, 17);
}));

test('missing binary fails staging instead of packaging an incomplete install', () => fixture((directory) => {
  passed(configure(directory, 'aarch64'));
  stageInputs(directory);
  fs.unlinkSync(path.join(directory, 'procmon'));
  assert.notEqual(packageDeb(directory).status, 0);
}));