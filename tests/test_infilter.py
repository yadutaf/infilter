import pytest
import subprocess

TEST_CONTAINERFILE = "tests/distroless-container/Containerfile"
TEST_TAG = "infilter-test"
TEST_NAME = "infilter-test"

@pytest.fixture(scope="session")
def target_pid():
    '''
    Build and run a test container
    '''
    # Build the test container
    subprocess.run(
        ['podman', 'build', '-f', TEST_CONTAINERFILE, '-t', TEST_TAG],
        check=True,
    )

    # Run the test container
    subprocess.run(
        ['podman', 'run', '--rm', '--detach', '--name', TEST_NAME, TEST_TAG],
        check=True,
    )

    # Get the main PID
    p = subprocess.run(
        ['podman', 'inspect', TEST_NAME, '--format', '{{.State.Pid}}'],
        check=True,
        capture_output=True,
        universal_newlines=True,
    )

    pid = int(p.stdout.strip())

    yield pid

    subprocess.run(
        ['podman', 'kill', TEST_NAME],
        check=True,
    )

def is_dynamic(path: str) -> bool:
    '''
    Return True is a binary is dynamically linked, False if it is statically linked
    or asserts if this is not an ELF file.
    '''
    p = subprocess.run(
        ['readelf', '-x', '.interp', path],
        capture_output=True,
        universal_newlines=True,
    )

    assert p.returncode == 0, f"Not a valid ELF file: {p.stderr}"

    return 'Hex dump of section' in p.stdout

def test_as_root(target_pid: int):
    '''
    Make sure infilter can work as root (all other tests are unprivileged)
    '''
    p = subprocess.run(
        ['sudo', './infilter', str(target_pid), '/bin/ps', 'aux'],
        capture_output=True,
        universal_newlines=True,
    )

    assert p.returncode == 0, f"Failed to infilter busybox ps: {p.stderr}"

    lines = p.stdout.splitlines()

    assert len(lines) == 3, f"ps should return the following lines: Header, Target, Infiltered. Got: {p.stdout}"

def test_static_busybox_absolute(target_pid: int):
    '''
    Make sure infilter can execute an absolute path inside a container
    '''
    assert not is_dynamic('/bin/busybox'), "This test assumes a statically linked /bin/busybox"

    p = subprocess.run(
        ['./infilter', str(target_pid), '/bin/busybox', 'ps'],
        capture_output=True,
        universal_newlines=True,
    )

    assert p.returncode == 0, f"Failed to infilter busybox ps: {p.stderr}"

    lines = p.stdout.splitlines()

    assert len(lines) == 3, f"ps should return the following lines: Header, Target, Infiltered. Got: {p.stdout}"

def test_static_busybox_path(target_pid: int):
    '''
    Make sure infilter can execute an absolute a binary in PATH inside a container
    '''
    p = subprocess.run(
        ['./infilter', str(target_pid), 'busybox', 'ps'],
        capture_output=True,
        universal_newlines=True,
    )

    assert p.returncode == 0, f"Failed to infilter busybox ps: {p.stderr}"

    lines = p.stdout.splitlines()

    assert len(lines) == 3, f"ps should return the following lines: Header, Target, Infiltered. Got: {p.stdout}"


def test_dynamic_ps(target_pid: int):
    '''
    Make sure infilter can execute a dynamically linked binary in PATH inside a container
    '''
    assert is_dynamic('/bin/ps'), "This test assumes a dynamically linked /bin/ps"

    p = subprocess.run(
        ['./infilter', str(target_pid), '/bin/ps', 'aux'],
        capture_output=True,
        universal_newlines=True,
    )

    assert p.returncode == 0, f"Failed to infilter ps: {p.stderr}"

    lines = p.stdout.splitlines()

    assert len(lines) == 3, f"ps should return the following lines: Header, Target, Infiltered. Got: {p.stdout}"
