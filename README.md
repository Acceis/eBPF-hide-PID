# eBPF hide PID

This project aims to demonstrate a way to hide a _process identifier_ (PID) to a user abusing of a system call.

It is inspired by the work of Pathtofile about [bad BPF programs behaviour](https://github.com/pathtofile/bad-bpf).

If you're looking for a deep dive into this project, you can find the two related articles on the [ACCEIS blog](https://www.acceis.fr/categorie/articles-techniques/). \
You can find the [first article](https://www.acceis.fr/ebpf-program-creation-in-practice-pid-concealment-part-1/) and [the second](https://www.acceis.fr/ebpf-in-practice-pid-concealment-part-2/).

## Dependencies

- Kernel v5.7 or higher
- [golang](https://go.dev/doc/install) v1.21 (not tested on lower versions)
- [clang](https://clang.llvm.org/) v16 or higher(depending on your OS, LLVM may be needed)
- [libbpf](https://github.com/libbpf/libbpf) v1.3.0 or higher

> If you manually install the package in a debian/ubuntu based repository, notice that _libbpf_ is not up to date in the "apt" repositories. So you may have problems compiling the program.

### For ArchLinux

If you are on archlinux you can simply run

```bash
sudo pacman -S llvm clang libbpf go
```

## Run in Docker

If you want a simple way to try this tool, you can use the provided Dockerfile

Build the image first

```bash
docker buildx build -t hide-pid .
```

You need to run the docker in privileged mod in order to inject the program in the kernel

```bash
docker run --rm --privileged -v /sys/kernel/debug:/sys/kernel/debug:rw hide-pid <PID|DIR>
```

## Manual installation

You can build the project using the following command

```bash
make
```

And then you can run the program in sudo

```bash
sudo ./bin/hide-pid 1337
# 2024/02/09 18:59:48 Waiting for events..
# 2024/02/09 18:59:53 Hiding "1337" for process "ps" (pid: 29939)
```

## Licence

The eBPF code is under GPL licence.
The Go code is under MIT licence.
