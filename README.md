# Infilter

Run *any* (read: most) binary in *any* container.

```
make
sudo ./infilter $(docker inspect --format='{{.State.Pid}}' my-minimal-container) htop
```

## Presentation

``Infilter`` runs any binary executable in any running container without
patching. It is especially useful for minimalistic containers with no
monitoring/debugging tools like alpine, busybox or distroless based containers.

You may use it to:
 - run ``/bin/zsh`` in a container with *no* shell
 - run pre-existing collectors like scollector *inside* any container
 - wrap ``sftp-server`` to enter a customer container on demand
 - ...

``Infilter`` will happily run with any namespace-based Linux container, be it
Pdoman, Docker, LXC, runc, crun, rkt, ... or any other custom implementation
as long as it is based on Linux namespace.

Please note that it currently assumes the amd64 kernel ABI.

> [!NOTE]
> ``Infilter`` will *not* work as expected if it relies on support files
> to be available at runtime. For example, it will not be able to run a python
> program or programs relying on runtime loading of 'terminfo' database like `htop`.

## Infilter vs...

### ``nsenter``, ``lxc-attach``, ``docker-exec``, ...

``nsenter``, ``lxc-attach``, ``docker-exec`` work by first entering the target
container using ``setns`` system call. Once done, they will ``execve`` the
command of your choice. This implies that it actually exists in target container.

Furthermore, in an infrastructure management system, it may be needed to run a
command with only a subset of the namespaces (isolation domains) activated. This
creates a bridge between the Host and the container. Depending on your situation
this may be a security threat. Hence not an option.

### Mounting a special volume with required tools

An alternative approach to the same functionality is to mount a volume with your
preferred tools. This works great when all required tools are well known in
advance and all required shared libraries are either fully trusted or
statically linked. If these tools rely on any library in the container, this is a
potential vulnerability as a malicious user could manipulate a library to run
arbitrary code as privileged user.

### Patching

Another alternative approach is to patch the desired tool with the appropriate
system calls. Patching implies maintenance, keeping up to date with security
fixes and careful tuning to make sure ``setns`` is called at the right time.

## How does it work?

Basically, ``Infilter`` starts target program under ``ptrace``. It then waits for
the first syscall outside of ``ld``, the dynamic linker. At this stage, the program
is still running in the Host context and, based on loaded libraries.

Either way, it is now *inside* the first syscall outside the dynamic linker. This
is when all 6 namespaces are attached. Once attached, the initial syscall is
released. The target program is now running *inside* the container.

For more details, please see the code. It is extensively documented.

## Hacking

### Building

```shell
make
```

### Testing

The tests depends on:

- `uv` for the dependencies
- `podman` as test target

Once both are installed, running the tests is a matter of:

```shell
make test
```

## License

MIT
