import subprocess
from malloc import PtMallocState
import argparse

import subprocess

def run_differential_test(pt_malloc_instance: PtMallocState, name: str, cmds):
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
                # print(idx, cmd[0], hex(size), hex(py_offset), hex(c_offset))

                assert py_offset == c_offset, f"Mismatch: C={c_offset:#x}, Py={py_offset:#x}"
                py_ptrs[idx] = py_ptr
            else:
                # print(" ", cmd[0], cmd[1])
                idx = cmd[1]
                pt_malloc_instance.free(py_ptrs[idx])
        print(f"✅ {name}: PASSED")
        return True
    except Exception as e:
        print(f"❌ {name}: FAILED - {e}")
        return False
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

    "tcache_max_size": [
        ('M', 0x400, 0),
        ('M', 0x400, 1),
        ('F', 0),        # will go in the tcache (on super new glibc versions)
        ('M', 0x100, 2),
    ],

    "unsorted_bin_consolidation": [
        ('M', 0x20,  0), # allocate the tcache now
        ('M', 0x410, 1), # Large enough to bypass tcache/fastbins
        ('M', 0x410, 2), # Prevent consolidation with top
        ('F', 0),        # Goes to unsorted bin
        ('M', 0x100, 3), # Causes 0 to be split. Remainder stays in unsorted.
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
    ],
    "tcache_basic": [
        ("M", 0x20, 0), ("M", 0x20, 1),
        ("F", 0), ("F", 1),            # Both to tcache
        ("M", 0x20, 2),                # Should reuse chunk 1 (LIFO)
    ],

    "fastbin_overflow_to_unsorted": [
        *[("M", 0x20, i) for i in range(9)],
        *[("F", i) for i in range(8)], # 7 to tcache, 1 to fastbin
        ("M", 0x400, 9),               # Allocate large to trigger consolidation/binning
        ("M", 0x20, 10),               # Should pull from tcache
    ],

    "unsorted_bin_splitting": [
        ("M", 0x400, 0),               # Chunk A
        ("M", 0x10, 1),                # Guard (prevent top merge)
        ("F", 0),                      # A -> Unsorted Bin
        ("M", 0x100, 2),               # Should split A. Remainder stays in Unsorted.
        ("M", 0x100, 3),               # Should split remainder of A.
    ],

    "coalescing_backward_forward": [
        ("M", 0x400, 0), ("M", 0x400, 1), ("M", 0x400, 2),
        ("M", 0x10, 3),                # Guard
        ("F", 1),                      # Middle to Unsorted
        ("F", 0),                      # Merge 0 into 1
        ("F", 2),                      # Merge 2 into 0+1
    ],

    "tcache_stash_from_smallbin": [
        # 1. Fill tcache for 0x30
        *[("M", 0x30, i) for i in range(7)],
        *[("F", i) for i in range(7)],
        # 2. Put two chunks into Smallbin (via Unsorted)
        ("M", 0x30, 7), ("M", 0x30, 8),
        ("M", 0x10, 9),                # Guard
        ("F", 7), ("F", 8),            # Into Unsorted
        ("M", 0x400, 10),              # Trigger binning: 7 and 8 move to Smallbins
        # 3. Empty tcache
        *[("M", 0x30, 20+i) for i in range(7)],
        # 4. Trigger Stash: Malloc 0x30.
        # It finds one in smallbin, then moves others to tcache.
        ("M", 0x30, 30),
    ],
    "fastbin_no_coalesce": [
        # Chunks in fastbins (or tcache) should NOT merge with neighbors
        ("M", 0x20, 0), ("M", 0x20, 1), ("M", 0x20, 2),
        ("M", 0x10, 3), # Guard top
        # Fill tcache so 0, 1, 2 must go to fastbins
        *[("M", 0x20, i+10) for i in range(7)],
        *[("F", i+10) for i in range(7)],

        ("F", 0), ("F", 1), ("F", 2),
        # If they coalesced, a 0x60 malloc would work.
        # In glibc, they stay 0x20, so 0x60 comes from 'top'.
        ("M", 0x60, 4),
    ],

    "largebin_sorting_and_fd_nextsize": [
        ("M", 0x10, 17), # make sure to allocate tcache
        # Largebins are sorted by size. We test if the correct 'closest fit' is picked.
        ("M", 0x430, 0), ("M", 0x10, 1),  # Chunk A + Guard
        ("M", 0x450, 2), ("M", 0x10, 3),  # Chunk B + Guard
        ("M", 0x410, 4), ("M", 0x10, 5),  # Chunk C + Guard

        # Move A, B, and C to Unsorted Bin
        ("F", 2), ("F", 0), ("F", 4),

        # Trigger binning into Largebins by requesting something that
        # doesn't fit in Unsorted (or exceeds a threshold)
        ("M", 0x600, 6),

        # Now request a size that specifically fits the 'middle' largebin chunk
        # To see if your skip-list (fd_nextsize) or sorting logic is correct
        ("M", 0x420, 7), # Should pick the 0x430 chunk (index 0)
    ],

    "malloc_consolidate_trigger": [
        # Fastbins are only merged when a "Large" allocation is requested.
        ("M", 0x20, 0), ("M", 0x20, 1), ("M", 0x10, 2), # Guard
        # Fill tcache
        *[("M", 0x20, i+10) for i in range(7)],
        *[("F", i+10) for i in range(7)],

        ("F", 0), ("F", 1), # These sit in fastbins, uncoalesced.

        # This large request triggers 'malloc_consolidate'
        ("M", 0x410, 3),

        # Now, 0 and 1 should be merged in the Unsorted Bin.
        # A request for 0x40 should now be satisfied by the merged chunk 0+1.
        ("M", 0x40, 4),
    ],

    "top_chunk_consolidation": [
        # Freeing a chunk adjacent to 'top' should immediately merge it into top
        # (Unless it's a fastbin/tcache chunk)
        ("M", 0x100, 0),
        ("F", 0), # No guard between chunk 0 and top.
        ("M", 0x200, 1), # Should start at the same address as chunk 0
    ],
    "stale_last_remainder": [
        # freeing a chunk that was once the last remainder should bring it back to be the last remainder
        ("M", 0x10, 0), # allocate tcache
        ("M", 0x700, 1),
        ("M", 0x1b00, 2),
        ("M", 0x10, 3),
        ("F", 2),
        ("M", 0x10, 4),
        ("M", 0x1700, 5),
        ("F", 1),
        ("F", 5),
        ("M", 0x100, 6)

    ],
    "last_remainder_basic_split": [
        ("M", 0x20, 17), # make sure the cache is allocated
        # 1. Setup: Get a chunk into the Unsorted Bin
        ("M", 0x420, 0),
        ("M", 0x20, 1),   # Guard chunk to prevent top-consolidation
        ("F", 0),         # Chunk 0 -> Unsorted Bin

        # 2. Trigger splitting
        # Requesting 0x100. Chunk 0 (0x410) is split.
        # 0x110 is returned, 0x300 becomes 'last_remainder'
        ("M", 0x100, 2),

        # 3. Use the last remainder
        # This should come directly from the remainder of Chunk 0
        ("M", 0x100, 3),
    ],

    "smallbin_order": [
        ("M", 0x90, 0),
        ("M", 0x20, 1),
        ("M", 0x90, 2),
        ("M", 0x20, 3),
        *([("M", 0x90, i) for i in range(4, 11)] + [("F", i) for i in range(4,11)]) ,
        ("F", 0),
        ("F", 2),
        ("M", 0x50, 4),
        ("M", 0x50, 5),
    ],

    "last_remainder_locality_priority": [
        ("M", 0x20, 17), # make sure the cache is allocated
        # 1. Put TWO chunks in Unsorted Bin
        ("M", 0x420, 0), ("M", 0x20, 1), # A + Guard
        ("M", 0x420, 2), ("M", 0x20, 3), # B + Guard
        ("F", 0),
        ("F", 2), # Unsorted Bin now has [B] -> [A]

        # 2. Split chunk B
        # This makes the remainder of B the 'last_remainder'
        ("M", 0x100, 4),

        # 3. Request another small chunk
        # Even though Chunk A (at index 0) is a perfect fit or
        # available in the bin, glibc should check the remainder
        # of B first because it is the 'last_remainder'.
        ("M", 0x100, 5),
    ],

    "last_remainder_tcache_bypass": [
        ("M", 0x20, 17), # make sure the cache is allocated
        # Since tcache exists, we must fill it to see Unsorted Bin behavior
        # for sizes that would otherwise fit in tcache.
        *[("M", 0x80, i) for i in range(7)],
        *[("F", i) for i in range(7)], # Tcache(0x90) is now full

        ("M", 0x420, 7), ("M", 0x20, 8), # Large chunk + Guard
        ("F", 7), # Into Unsorted Bin

        ("M", 0x80, 9), # Splits from 7, remainder is last_remainder
        ("M", 0x80, 10), # Should come from last_remainder
    ],
    "largebin_ordering": [
        ('M', 0x10, 0), # allocate tcache
        ('M', 0x1030, 1),
        ('M', 0x10, 2),
        ('M', 0x1000, 3),
        ('M', 0x10, 4),
        ('F', 3),
        ('F', 1),
        ('M', 0x20, 5), # should allocate from the 0x1000 chunk
    ]
}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("test_name", nargs="?")
    args = parser.parse_args()
    if args.test_name:
        allocator = PtMallocState()
        run_differential_test(allocator, args.test_name,  scenarios[args.test_name])
        return

    for name, commands in scenarios.items():
        allocator = PtMallocState()
        run_differential_test(allocator, name, commands)




if __name__ == "__main__":
    main()
