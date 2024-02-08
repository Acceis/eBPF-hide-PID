# eBPF hide PID

This project aims to provide an "easy-to-understand" overview of how you can hide a PID (_process identifier_) in the Linux kernel, and to help take the first step in eBPF development.

It took his inspiration from the work of Pathtofile about [bad BPF programs behaviour](https://github.com/pathtofile/bad-bpf) presented at the DEF CON 29.

You can find the articles related to this code on the [ACCEIS blog](https://www.acceis.fr/ressources/)

## Dependencies

- [golang](https://go.dev/doc/install) v1.21 (not tested on lower versions)

```bash
sudo apt install build-essential libelf-dev libbfd-dev linux-tools-common linux-tools-generic
```

## Install

You can build the project using the following command

```bash
make build
```

You can remove generated files (and the binary) using the following command

```bash
make clean
```

## Licence

The eBPF code is under GPL licence.
The Go code is under MIT licence.
