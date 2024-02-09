BIN_DIR = ./bin
PKG_SRC = ./src
BPF_DIR = ${PKG_SRC}/bpf
LIB_PATH = ${BPF_DIR}/lib
VMLINUX_PATH = ${LIB_PATH}/vmlinux.h

BIN_NAME = hide-pid

export BPF_PROGS = getdents64

all:
	go generate ${PKG_SRC}/main.go
	go build -o ${BIN_DIR}/${BIN_NAME} ${PKG_SRC}

generate_vmlinux:
	@mkdir -p ${LIB_PATH}
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_PATH}

clean:
	-rm -f ./**/*_bpfeb*
	-rm -f ./**/*_bpfel*
