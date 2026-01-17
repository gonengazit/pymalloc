import subprocess
from malloc import MMAP_SENTINEL, PtMallocState
from math import ceil
import argparse

import subprocess

import random

class MallocFuzzer:
    def __init__(self):
        # Probability weights for different size classes
        self.size_weights = [
            (range(0x10, 0x80), 0.50),   # Tcache/Fastbins (Very common)
            (range(0x90, 0x400), 0.35),  # Smallbins
            (range(0x410, 0x2000), 0.15) # Largebins
        ]
        self.live_ptrs = [] # List of (index, size)
        self.next_idx = 0

    def generate_commands(self, num_ops=500):
        # always start by allocating the tcache (for now)
        # TODO: when we implement tcache allocation - remove this
        commands = [('M', 0x10, 0)]
        self.next_idx += 1
        for _ in range(num_ops):
            # Decide: Malloc or Free?
            # We weight Malloc higher initially to grow the heap
            action_weight = 0.6 if len(self.live_ptrs) < 20 else 0.4

            if random.random() < action_weight or not self.live_ptrs:
                # --- Malloc Path ---
                # Select a size range based on weights
                r = random.random()
                cumulative = 0
                selected_range = range(0x10, 0x100)
                for r_range, weight in self.size_weights:
                    cumulative += weight
                    if r <= cumulative:
                        selected_range = r_range
                        break

                size = random.choice(selected_range)
                idx = self.next_idx
                self.next_idx += 1
                commands.append(('M', size, idx))
                self.live_ptrs.append((idx, size))
            else:
                # --- Free Path ---
                # Randomly pick a live pointer to free
                list_idx = random.randrange(len(self.live_ptrs))
                ptr_idx, _ = self.live_ptrs.pop(list_idx)
                commands.append(('F', ptr_idx))

        return commands

def run_differential_test(name: str, cmds):
    # Build C input
    c_input = ""
    for cmd in cmds:
        if cmd[0] == 'M': c_input += f"M {cmd[1]} {cmd[2]} "
        else: c_input += f"F {cmd[1]} "

    # Get C Output
    proc = subprocess.Popen(['./harness'], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # print(c_input)
    stdout, _ = proc.communicate(input=c_input.encode())
    c_addrs = stdout.decode().splitlines()
    top = int(c_addrs[0])

    first_allocation_size = ceil((cmds[0][1] + 8)/0x10) * 0x10
    first_allocation_size = max(0x20, first_allocation_size)

    if first_allocation_size < 0x411:
        top -= 0x300

    # this assumes that between 0x0000 and 0x1000 bytes are allocated after top is first padded
    # we know that top ends in a page aligned allocation and was originally 0x21000 bytes
    # subtract 0x10 because of the first allocation containing metadata
    size_till_next_page = ((top-0x10+0xfff)&~0xfff)-top
    top_size = 0x20000 + size_till_next_page
    top_size -= size_till_next_page - first_allocation_size


    pt_malloc_instance = PtMallocState(top=top, top_size=top_size)

    # Run Python Impl
    py_ptrs = {}

    # we assume the first chunk allocated is not mmaped
    c_base = int(c_addrs[0])

    try:
        for i, line in enumerate(c_addrs):
            cmd = cmds[i]
            if cmd[0] == 'M':
                size, idx = cmd[1], cmd[2]
                py_ptr = pt_malloc_instance.malloc(size)

                c_ptr = int(line)
                # print(size, idx, cmd, hex(py_ptr), hex(c_ptr))
                # mmaped page
                if c_ptr - c_base > 0x100000000:
                    assert py_ptr == MMAP_SENTINEL, f"Mismatch at step {i}: C is mmap'd and python is not"
                else:
                    assert py_ptr == c_ptr, f"Mismatch at step {i}: C={c_ptr:#x}, Py={py_ptr:#x}"
                py_ptrs[idx] = py_ptr
            else:
                idx = cmd[1]
                pt_malloc_instance.free(py_ptrs[idx])
        print(f"✅ {name}: PASSED")
        return True
    except Exception as e:
        print(f"❌ {name}: FAILED - {e}")
        return False

def run_fuzzer_test(num_ops=1000):
    fuzzer = MallocFuzzer()
    commands = fuzzer.generate_commands(num_ops)

    return run_differential_test("fuzz", commands)

def get_reduced_fail(num_ops=500):
    while True:
        fuzzer = MallocFuzzer()
        commands = fuzzer.generate_commands(num_ops)
        commands = [("M", 0x1f000, 1020)] + commands
        if not run_differential_test("fuzz", commands):
            break

    reduce_test(commands)


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
        ('M', 0x420, 0), # Large enough to bypass tcache/fastbins
        ('M', 0x420, 1), # Prevent consolidation with top
        ('F', 0),        # Goes to unsorted bin
        ('M', 0x100, 3), # Causes 0 to be split. Remainder stays in unsorted.
    ],

    "backward_coalescing": [
        ('M', 0x420, 0),
        ('M', 0x420, 1),
        ('M', 0x420, 2),
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
        ("M", 0x420, 9),               # Allocate large to trigger consolidation/binning
        ("M", 0x20, 10),               # Should pull from tcache
    ],

    "unsorted_bin_splitting": [
        ("M", 0x420, 0),               # Chunk A
        ("M", 0x10, 1),                # Guard (prevent top merge)
        ("F", 0),                      # A -> Unsorted Bin
        ("M", 0x100, 2),               # Should split A. Remainder stays in Unsorted.
        ("M", 0x100, 3),               # Should split remainder of A.
    ],

    "coalescing_backward_forward": [
        ("M", 0x420, 0), ("M", 0x420, 1), ("M", 0x420, 2),
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
        ("M", 0x420, 10),              # Trigger binning: 7 and 8 move to Smallbins
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
        ('M', 0x1030, 1),
        ('M', 0x10, 2),
        ('M', 0x1000, 3),
        ('M', 0x10, 4),
        ('F', 3),
        ('F', 1),
        ('M', 0x20, 5), # should allocate from the 0x1000 chunk
    ],
    "int_free_maybe_consolidate":
        [('M', 96, 0),
         ('M', 96, 1),
         ('M', 96, 2),
         ('M', 96, 3),
         ('M', 96, 4),
         ('M', 96, 5),
         ('M', 96, 6),
         ('M', 96, 7),
         ('F', 0),
         ('F', 1),
         ('F', 2),
         ('F', 3),
         ('F', 4),
         ('F', 5),
         ('F', 6),
         ('M', 6000, 8),
         ('F', 7),
         ('F', 8),
         ('M', 48, 9)],
    "mmaped_chunk": [
        ("M", 0x20, 0),
        ("M", 0x21000, 1),
        ("M", 0x420, 2),
    ],
    "sysmalloc_default_expansion": [
        # 1. First allocation establishes the initial heap/top
        ("M", 0x420, 0),
        # Allocate large chunks to exhaust top - but not enough to force an mmap
        ("M", 0x10000, 1),
        ("M", 0x10000, 2),
        # 3. Allocation after expansion
        ("M", 0x420, 3),
    ],
    "top_size_exact":
    # this test coalesces with top pretty close to it being 65536 -so if we calculated it wrong we'll probably fail
    [
        ('M', 112, 0),
        ('M', 112, 1),
        ('M', 112, 5),
        ('M', 112, 7),
        ('M', 112, 8),
        ('M', 112, 9),
        ('M', 112, 10),
        ('M', 112, 11),
        ('F', 1),
        ('F', 5),
        ('F', 7),
        ('F', 8),
        ('F', 9),
        ('F', 10),
        ('F', 11),
        ('M', 28996, 2),
        ('M', 112, 19),
        ('M', 6320, 20),
        ('M', 2880, 21),
        ('F', 19),
        ('F', 0),
        ('F', 21),
        ('M', 96, 22)
    ]
}

def reduce_test(cmds):
    good_cmds = cmds
    cnt=0
    while cnt<1000:
        cnt+=1
        rm = random.choice(cmds)
        cmds = []
        for cmd in good_cmds:
            if cmd==rm:
                continue
            if rm[0]=='M' and cmd[-1]==rm[-1]:
                continue
            cmds.append(cmd)

        if not run_differential_test("tst", cmds):
            cnt=0
            good_cmds = cmds

    simplified_cmds=[]
    idxs={}
    for cmd in good_cmds:
        cmd =list(cmd)
        if cmd[0]=="M":
            cmd[1]=cmd[1]+7 - (cmd[1]+7)%16
        if cmd[-1] not in idxs:
            idxs[cmd[-1]]=len(idxs)
        cmd[-1]=idxs[cmd[-1]]
        cmd = tuple(cmd)
        simplified_cmds.append(cmd)
    print(simplified_cmds, len(simplified_cmds))
    return cmds




def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("test_name", nargs="?", choices=list(scenarios.keys()) + ["fuzz", "search_fail"])
    args = parser.parse_args()
    if args.test_name:
        if args.test_name == "fuzz":
            run_fuzzer_test()
        elif args.test_name == "search_fail":
            get_reduced_fail()
        else:
            run_differential_test(args.test_name,  scenarios[args.test_name])
        return

    for name, commands in scenarios.items():
        run_differential_test(name, commands)

# [('M', 48, 0), ('M', 832, 1), ('M', 5648, 2), ('M', 7296, 3), ('M', 208, 4), ('F', 2), ('M', 784, 5), ('M', 112, 6), ('M', 7120, 7), ('M', 64, 8), ('M', 464, 9), ('M', 464, 10), ('M', 272, 11), ('M', 944, 12), ('M', 5936, 13), ('M', 64, 14), ('M', 1008, 15), ('M', 4432, 16), ('M', 992, 17), ('M', 64, 18), ('M', 704, 19), ('M', 320, 20), ('M', 64, 21), ('F', 16), ('M', 480, 22), ('M', 64, 23), ('M', 64, 24), ('M', 64, 25), ('M', 64, 26), ('F', 14), ('F', 8), ('F', 21), ('F', 24), ('M', 816, 27), ('M', 64, 28), ('F', 23), ('F', 25), ('F', 18), ('F', 26), ('M', 3552, 29), ('M', 3584, 30), ('M', 800, 31), ('F', 28), ('F', 30), ('M', 80, 32)] 45


# [('M', 126976, 0), ('M', 4064, 1), ('M', 80, 2), ('M', 80, 3), ('M', 2608, 4), ('M', 7504, 5), ('M', 80, 6), ('M', 80, 7), ('M', 7504, 8), ('M', 80, 9), ('M', 80, 10), ('M', 80, 11), ('M', 80, 12), ('F', 11), ('F', 3), ('M', 7024, 13), ('F', 12), ('F', 9), ('F', 7), ('F', 2), ('M', 7472, 14), ('F', 6), ('M', 6144, 15), ('F', 10), ('F', 15), ('M', 32, 16)] 26

# [('M', 112, 0), ('M', 112, 1), ('M', 384, 2), ('M', 400, 3), ('M', 64, 4), ('M', 112, 5), ('M', 6944, 6), ('M', 112, 7), ('M', 112, 8), ('M', 112, 9), ('M', 112, 10), ('M', 112, 11), ('F', 7), ('F', 10), ('M', 80, 12), ('F', 8), ('F', 11), ('F', 0), ('F', 1), ('M', 496, 13), ('M', 7360, 14), ('F', 5), ('M', 8016, 15), ('M', 3600, 16), ('M', 560, 17), ('M', 816, 18), ('M', 112, 19), ('M', 6320, 20), ('F', 9), ('M', 2880, 21), ('F', 19), ('F', 21), ('M', 96, 22)] 33

if __name__ == "__main__":
    main()
