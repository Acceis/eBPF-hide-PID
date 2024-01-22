#!/bin/sh

for prog in $BPF_PROGS; do
   go run github.com/cilium/ebpf/cmd/bpf2go -type rb_event $prog bpf/$prog.bpf.c
done
