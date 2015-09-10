# Infilter

Run *any* binary in *any* container.

```
make
./infilter $(docker inspect --format='{{.State.Pid}}' my-minimal-container) htop
```

## Presentation

``Infilter`` will run any binary executable in any running container, without
patching. It is especially usefull for minimalistic containers with no
monitoring/debugging tools like alpine or busybox based Dockers.

You may use it to:
 - run ``/bin/zsh`` in a container with *no* shell
 - run ``htop`` in any container
 - run pre-existing collectors like scollector *inside* any container
 - wrap ``sftp-server`` to enter a customer container on demand
 - ...

``Infilter`` will happily run with any Namespace based Linux container. Be it
Docker, LXC, runc, rkt or a custom implementation. Please note that it currently
assumes amd64 kernel ABI.

NOTE: ``Infilter`` will *not* work as expected if it relies on support files
to be available at runtime. For example, it will not be able to run a python
program like ``ctop``.

## Infilter vs...

### ``nsenter``, ``lxc-attach``, ``docker-exec``, ...

``nsenter``, ``lxc-attach``, ``docker-exec`` work by first entering the target
container using ``setns`` system call. Once done, they will ``execve`` the
command of your choice. This implies that it actually exists in target container.

Furtermore, in an infrastructure managment system, it may be needed to run a
command with only a subset of the namespaces (isolation domains) activated. This
creates a bridge between the Host and the container. Depending on your situation
this may be a security threat. Hence not an option.

### Mounting a special volume with required tools

Mounting a special volume with required tools works great when all required tools
are well known and all required shared libraries are either fully trusted either
statically linked. If these tools rely on any library in the container, this is a
potential vulnerability as a malicious user could manipulate a library to run
arbitrary code as privileged user.

### Patching

Patching implies maintenance, keeping up to date with security fixes and careful
tunning to make sure ``setns`` are done at the right time.

## How does it work?

Basically, ``Infilter`` starts target program under ``ptrace``. It then waits for
the first syscall outside of ``ld``, the dynamic linker. At this stage, the program
is still running in the Host context and, based on loaded libraries, it is able to
decide wether the target program will need terminfo resources.

terminfo requires special treatment as this support file is necessary to run most
terminal based applications like htop, in the example above.

Either way, it is now *inside* the first syscall outside the dynamic linker. This
is when all 6 namespaces are attached. Once attached, the initial syscall is
released. The target program is now running *inside* the container.

If terminfo was not required, ``infilter`` will simply detach itself and let the
execution go.

If terminfo was potentially required, ``infilter`` will attempt to intercept
terminfo files open/stat/access operations and proxy them in host context at
runtime as soon as one terminfo has been sucessfuly opened, ``infilter`` will
detach itself and let the execution go.

For more details, please see the code. It is extensively documented.

## License

MIT

