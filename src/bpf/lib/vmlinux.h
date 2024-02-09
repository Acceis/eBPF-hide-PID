// This is a shorten version of vmlinux.h file
// You can generate the full file with bpftool with the below command
// bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long int id;
	long unsigned int args[6];
	char __data[0];
};

struct trace_event_raw_sys_exit {
	struct trace_entry ent;
	long int id;
	long int ret;
	char __data[0];
};

struct linux_dirent64 {
	__u64 d_ino;
	__s64 d_off;
	short unsigned int d_reclen;
	unsigned char d_type;
	char d_name[0];
};

typedef _Bool bool;

enum {
	false = 0,
	true = 1,
};

typedef long long unsigned int __u64;
typedef unsigned int __u32;
typedef short unsigned int __u16;
typedef unsigned char __u8;

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;