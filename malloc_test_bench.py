import subprocess
from malloc import PtMallocState

import subprocess

def run_differential_test(pt_malloc_instance, name, cmds):
    # Build C input
    c_input = ""
    for cmd in cmds:
        if cmd[0] == 'M': c_input += f"M {cmd[1]} {cmd[2]} "
        else: c_input += f"F {cmd[1]} "

    # Get C Output
    proc = subprocess.Popen(['./harness'], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, _ = proc.communicate(input=c_input.encode())
    c_offsets = stdout.decode().splitlines()

    # Run Python Impl
    py_ptrs = {}
    base_addr = None

    try:
        for i, line in enumerate(c_offsets):
            cmd = cmds[i]
            if cmd[0] == 'M':
                size, idx = cmd[1], cmd[2]
                py_ptr = pt_malloc_instance.malloc(size)

                if base_addr is None:
                    base_addr = py_ptr
                    # Synchronize your 'top' if the first malloc
                    # results in a specific heap layout

                py_offset = py_ptr - base_addr
                c_offset = int(line)
                # print(cmd[0], hex(size),  hex(py_offset), hex(c_offset))

                assert py_offset == c_offset, f"Mismatch: C={c_offset:#x}, Py={py_offset:#x}"
                py_ptrs[idx] = py_ptr
            else:
                # print(cmd[0], cmd[1])
                idx = cmd[1]
                pt_malloc_instance.free(py_ptrs[idx])
        print(f"✅ {name}: PASSED")
    except Exception as e:
        print(f"❌ {name}: FAILED - {e}")
        # raise e

# Define scenarios to exercise the logic
scenarios = {
    "tcache_exhaustion": [
        # Fill tcache (limit 7)
        *[('M', 0x20, i) for i in range(8)],
        *[('F', i) for i in range(7)], # Chunks 0-6 go to tcache
        ('F', 7),                      # Chunk 7 goes to fastbin
        ('M', 0x20, 8),                # Should come from tcache (index 6)
    ],

    "unsorted_bin_consolidation": [
        ('M', 0x400, 0), # Large enough to bypass tcache/fastbins
        ('M', 0x400, 1), # Prevent consolidation with top
        ('F', 0),        # Goes to unsorted bin
        ('M', 0x100, 2), # Causes 0 to be split. Remainder stays in unsorted.
    ],

    "backward_coalescing": [
        ('M', 0x400, 0),
        ('M', 0x400, 1),
        ('M', 0x400, 2),
        ('M', 0x10, 3),  # Guard
        ('F', 0),        # Unsorted
        ('F', 1),        # Should merge with 0
        ('F', 2),        # Should merge with 0+1
    ],

    "tcache_stashing": [
        # 1. Fill tcache for 0x20
        *[('M', 0x20, i) for i in range(7)],
        *[('F', i) for i in range(7)],
        # 2. Put a chunk in smallbin
        ('M', 0x20, 7),
        ('M', 0x400, 8), # Guard
        ('F', 7),        # Unsorted
        ('M', 0x500, 9), # Trigger binning: 7 moves from unsorted to smallbin
        # 3. Empty tcache
        *[('M', 0x20, 10+i) for i in range(7)],
        # 4. Request 0x20 again -> triggers smallbin stash to tcache
        ('M', 0x20, 20),
    ]
}

def main():
    for name, commands in scenarios.items():
        allocator = PtMallocState()
        run_differential_test(allocator, name, commands)




if __name__ == "__main__":
    main()
