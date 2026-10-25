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

def test_busybox_static(target_pid: int):
    p = subprocess.run(
        ['sudo', './infilter', str(target_pid), '/bin/busybox', 'ps'],
        capture_output=True,
        universal_newlines=True,
    )

    assert p.returncode == 0, f"Failed to infilter busybox ps: {p.stderr}"

    lines = p.stdout.splitlines()

    assert len(lines) == 3, f"ps should return the following lines: Header, Target, Infiltered. Got: {p.stdout}"
