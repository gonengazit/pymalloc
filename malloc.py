from math import ceil
from collections import deque
from dataclasses import dataclass
from enum import Enum
MAX_FAST_SIZE=0x80 # Note that this is equal to the glibc macro DEFAULT_MXFAST and not the glibc macro MAX_FAST_SIZE
MAX_TCACHE_SIZE = 0x411 # 0x408 in glibc versions that aren't super-duper new (July 2025)
MIN_LARGE_SIZE = 0x400
MIN_CHUNK_SIZE = 0x20
MALLOC_HEADER_SIZE = 8
MAX_TCACHE_LEN = 7
NBINS = 128
NUM_SMALL_BINS = MIN_LARGE_SIZE//0x10
NUM_LARGE_BINS = NBINS - NUM_SMALL_BINS
SIZEOF_TCACHE_PERTHREAD_STRUCT = 0x2f8

MMAP_THRESHOLD = 128 * 1024
TRIM_THRESHOLD = 128 * 1024

# in the glibc source code - this is 0 but it is actually a compiler tunable. it seems like it is set to 0x20000 by most distros
# you can check the value using /lib64/ld-linux-x86-64.so.2 --list-tunables | grep top_pad
TOP_PAD = 0x20000
PAGE_SIZE = 0x1000

class BinType(Enum):
    TCACHE = "tcache"
    FASTBIN = "fastbin"
    SMALLBIN = "smallbin"
    LARGEBIN = "largebin"
    UNSORTED_BIN = "unsorted_bin"
    TOP = "top"
    UNKNOWN = "unknown"

@dataclass
class MallocChunk:
    size: int
    address: int
    bin: BinType # which bin the chunk is in if it is free
    def __repr__(self) -> str:
        return f"MallocChunk(size={self.size:#x}, address={self.address:#x}, bin={self.bin})"


#TODO: try to somehow deal with the fact that the tcache is allocated dynamically at runtime and thus can consume chunks from the unsorted bin. ugh
class PtMallocState:
    def __init__(self, tcache_allocated=False) -> None:
        self.tcache: list[deque[MallocChunk]] = [deque() for _ in range(0, MAX_TCACHE_SIZE + 1, 0x10)] # stack
        self.fastbins: list[deque[MallocChunk]] = [deque() for _ in range(0, MAX_FAST_SIZE + 1, 0x10)] # stack
        self.unsorted_bin: deque[MallocChunk] = deque() # queue
        self.smallbins: list[deque[MallocChunk]] = [deque() for _ in range(0, MIN_LARGE_SIZE, 0x10)] # queue
        self.largebins: list[list[MallocChunk]] = [[] for _ in range(NUM_LARGE_BINS)] # queue-ish - sorted smallest to largest
        self.last_remainder: MallocChunk | None = None
        self.top = MallocChunk(0, 0x0, BinType.TOP)

        # because our chunks aren't actually contiguous in memory - we'll store a big lookup table of all the chunks
        self.free_chunks_by_start: dict[int, MallocChunk]  = {}
        self.free_chunks_by_end: dict[int, MallocChunk]  = {}
        self.allocated_chunks: dict[int, MallocChunk] = {}

        # the tcache is only allocated on the first tcache-sized allocation
        self.tcache_allocated = tcache_allocated

    def split_chunk(self, victim: MallocChunk, alloc_sz: int) ->tuple[MallocChunk, MallocChunk]:
        """split victim into 2 chunks - the first of size alloc_sz"""
        remainder_size = victim.size - alloc_sz
        assert remainder_size >= MIN_CHUNK_SIZE
        remainder = MallocChunk(remainder_size, victim.address + alloc_sz, BinType.UNKNOWN)
        split_victim = MallocChunk(alloc_sz, victim.address, BinType.UNKNOWN)

        self.remove_from_free_chunks(victim)
        self.add_to_free_chunks(remainder)
        self.add_to_free_chunks(split_victim)

        return split_victim, remainder

    def merge_chunks(self, l: MallocChunk, r: MallocChunk) -> MallocChunk:
        assert r.address == l.address + l.size
        merged_chunk = MallocChunk(l.size + r.size, l.address, BinType.UNKNOWN)

        self.add_to_free_chunks(merged_chunk)

        return merged_chunk

    def add_to_free_chunks(self, victim: MallocChunk):
        self.free_chunks_by_start[victim.address]=victim
        self.free_chunks_by_end[victim.address + victim.size] = victim
        pass

    def remove_from_free_chunks(self, victim: MallocChunk, remove_from_bins=False):
        del self.free_chunks_by_start[victim.address]
        del self.free_chunks_by_end[victim.address + victim.size]
        #TODO: improve the performance of this

        if remove_from_bins:
            match victim.bin:
                case BinType.TCACHE:
                    tcache_idx = victim.size // 0x10
                    self.tcache[tcache_idx].remove(victim)

                case BinType.FASTBIN:
                    fastbin_idx = victim.size // 0x10
                    self.fastbins[fastbin_idx].remove(victim)

                case BinType.SMALLBIN:
                    smallbin_idx = victim.size // 0x10
                    self.smallbins[smallbin_idx].remove(victim)

                case BinType.LARGEBIN:

                    largebin_idx = self.largebin_index(victim.size)
                    bin = self.bin_at(largebin_idx)
                    bin.remove(victim)

                case BinType.UNSORTED_BIN:
                    self.unsorted_bin.remove(victim)

                case _:
                    assert False

    def consolidate(self):
        for fb in self.fastbins:
            while fb:
                p = fb.pop()
                coalsced = self.coalesce_chunk(p)
                if coalsced is None:
                    continue
                coalsced.bin = BinType.UNSORTED_BIN
                self.unsorted_bin.append(coalsced)

    def coalesce_chunk(self, chunk: MallocChunk) -> MallocChunk | None:
        """Coalesce a chunk with its neighbours if they are free
        if the chunk is next to the heap top - extend the top with it instead and return None"""
        if chunk.address in self.free_chunks_by_end:
            prev = self.free_chunks_by_end[chunk.address]
            if prev.bin not in (BinType.TCACHE, BinType.FASTBIN):
                self.remove_from_free_chunks(prev, remove_from_bins=True)
                self.remove_from_free_chunks(chunk)
                chunk = self.merge_chunks(prev, chunk)

        if chunk.address + chunk.size in self.free_chunks_by_start:
            next = self.free_chunks_by_start[chunk.address + chunk.size]
            if next.bin not in (BinType.TCACHE, BinType.FASTBIN):
                self.remove_from_free_chunks(chunk)
                self.remove_from_free_chunks(next, remove_from_bins=True)
                chunk = self.merge_chunks(chunk, next)

        elif chunk.address + chunk.size == self.top.address:
            self.top = MallocChunk(self.top.size + chunk.size, chunk.address, BinType.TOP)
            self.remove_from_free_chunks(chunk)
            return None



        return chunk

    def bin_at(self, idx: int) -> deque[MallocChunk] | list[MallocChunk]:
        assert idx < NBINS
        if idx < len(self.smallbins):
            return self.smallbins[idx]
        return self.largebins[idx - NUM_SMALL_BINS]

    # shamelessly stolen from pwndbg
    def largebin_index(self, sz: int) -> int:
        return (
            48 + (sz >> 6)
            if (sz >> 6) <= 48
            else (
                91 + (sz >> 9)
                if (sz >> 9) <= 20
                else (
                    110 + (sz >> 12)
                    if (sz >> 12) <= 10
                    else (
                        119 + (sz >> 15)
                        if (sz >> 15) <= 4
                        else 124 + (sz >> 18)
                        if (sz >> 18) <= 2
                        else 126
                    )
                )
            )
        )



    def malloc(self, sz: int) -> int:
        chunk = self._malloc(sz)
        self.remove_from_free_chunks(chunk)
        self.allocated_chunks[chunk.address] = chunk
        return chunk.address

    def _malloc(self, sz: int) -> MallocChunk:
        # make size the actual chunk allocation size, rounded to 0x10 and including heap metadata
        sz = ceil((sz + MALLOC_HEADER_SIZE)/0x10) * 0x10
        sz = max(sz, MIN_CHUNK_SIZE)

        # if we're small enough for the tcache and the relevant tcache is not empty - return the top element from it
        tcache_idx = sz // 0x10
        if tcache_idx < len(self.tcache):
            if not self.tcache_allocated:
                self.tcache_allocated = True
                self.malloc(SIZEOF_TCACHE_PERTHREAD_STRUCT)
            if self.tcache[tcache_idx]:
                return self.tcache[tcache_idx].pop()

        # if we're small enough for the fastbins and the relevant fastbin is not empty - return the top element from it
        fastbin_idx = sz // 0x10
        if fastbin_idx < len(self.fastbins) and self.fastbins[fastbin_idx]:
            victim = self.fastbins[fastbin_idx].pop()

            # while we're here - fill the tcache from the fastbin
            while self.fastbins[fastbin_idx] and len(self.tcache[tcache_idx]) < MAX_TCACHE_LEN:
                self.tcache[tcache_idx].append(self.fastbins[fastbin_idx].pop())

            return victim

        # if we're small enough for the smallbins and the relevant smallbin is not empty (exact fit) - return the first element from it
        smallbin_idx = sz // 0x10
        if smallbin_idx < len(self.smallbins):
            if self.smallbins[smallbin_idx]:
                victim = self.smallbins[smallbin_idx].popleft()

                # while we're here - fill the tcache from the smallbin
                while self.smallbins[smallbin_idx] and len(self.tcache[tcache_idx]) < MAX_TCACHE_LEN:
                    back = self.smallbins[smallbin_idx].popleft()
                    back.bin = BinType.TCACHE
                    self.tcache[tcache_idx].append(back)

                return victim
        else:
            self.consolidate()

        # sort the unsorted bin
        iters = 0
        while self.unsorted_bin:
            victim = self.unsorted_bin.popleft()
            # if this is a small request and the only chunk left in the unsorted bin is the last remainder - split and allocate it.
            # this is the only exception to best-fit
            if smallbin_idx < len(self.smallbins) and not self.unsorted_bin and self.last_remainder and victim.address == self.last_remainder.address and victim.size > sz + MIN_CHUNK_SIZE:
                split_victim, remainder = self.split_chunk(victim, sz)

                remainder.bin = BinType.UNSORTED_BIN
                self.unsorted_bin.append(remainder)
                self.last_remainder = remainder

                return split_victim

            # if the chunk exactly fits our request - fill the tcache, and return the chunk if the tcache is full
            if victim.size == sz:
                if tcache_idx < len(self.tcache) and len(self.tcache[tcache_idx]) < MAX_TCACHE_LEN:
                    victim.bin=BinType.TCACHE
                    self.tcache[tcache_idx].append(victim)
                    continue
                else:
                    return victim

            # put the chunk in the relvant bin
            if victim.size < MIN_LARGE_SIZE:
                victim_smallbin_idx = victim.size // 0x10
                victim.bin=BinType.SMALLBIN
                self.smallbins[victim_smallbin_idx].append(victim)
            else:
                victim_largebin_idx = self.largebin_index(victim.size)
                bin = self.bin_at(victim_largebin_idx)
                # make sure we got a largebin
                assert isinstance(bin, list)
                # insert chunk into bin maintaining sorted order.
                # if there bin already contains some chunks of the exact same size - we'll insert our new chunk to be 2nd to last of them
                victim.bin = BinType.LARGEBIN
                prev = None
                for i, chunk in enumerate(bin):
                    if chunk.size > victim.size:
                        if prev and prev.size == victim.size:
                            bin.insert(i-1, victim)
                        else:
                            bin.insert(i, victim)
                        break
                    prev = chunk

                # this will be the largest (maybe tied) chunk in the bin
                else:
                    if prev and prev.size == victim.size:
                        bin.insert(-1, victim)
                    else:
                        bin.append(victim)

            iters += 1
            MAX_ITERS = 10000
            if iters >= MAX_ITERS:
                break

        # if we put chunks in the relevant tcache during sorting - return one now
        if tcache_idx < len(self.tcache) and self.tcache[tcache_idx]:
            return self.tcache[tcache_idx].pop()

        idx = smallbin_idx
        if smallbin_idx >= len(self.smallbins):
            # check if there's a fitting chunk in the current bin
            idx = self.largebin_index(sz)
            bin = self.bin_at(idx)
            # make sure we got a largebin
            assert isinstance(bin, list)
            for i, chunk in enumerate(bin):
                # found a large enough chunk in the bin
                if chunk.size >= sz:
                    # If this is the only chunk in the bin of this size, return it
                    if i + 1 >= len(bin) or bin[i+1].size != chunk.size:
                        victim = bin.pop(i)
                    else:
                        # if there's multiple chunks of the same size - allocate the 2nd to last one
                        while i+1 < len(bin) and bin[i+1].size == chunk.size:
                            i+=1
                        victim = bin.pop(i-1)

                    # Split chunk
                    if victim.size - sz >= MIN_CHUNK_SIZE:
                        victim, remainder = self.split_chunk(victim, sz)
                        remainder.bin = BinType.UNSORTED_BIN
                        self.unsorted_bin.append(remainder)

                    return victim


        # scan the bins from smallest to largest - looking for a fitting chunk
        idx += 1
        while idx < NBINS:
            bin = self.bin_at(idx)
            # if we're out of bins - continue to use top
            if bin is None:
                break
            # if the bin is empty - continue to the next bin
            # we don't implement the allocator optimizations that can jump to the next free bin
            if not bin:
                idx += 1
                continue

            victim = bin.pop(0) if isinstance(bin, list) else bin.popleft()
            assert victim.size >= sz
            remainder_size = victim.size - sz

            # Exhaust
            if remainder_size < MIN_CHUNK_SIZE:
                return victim

            # Split
            else:
                split_victim, remainder = self.split_chunk(victim, sz)
                remainder.bin = BinType.UNSORTED_BIN
                self.unsorted_bin.append(remainder)
                if sz < MIN_LARGE_SIZE:
                    self.last_remainder = remainder
                return split_victim

        # allocate from the top chunk

        if self.top.size >= sz + MIN_CHUNK_SIZE:
            victim = MallocChunk(sz, self.top.address, BinType.UNKNOWN)
            self.add_to_free_chunks(victim) # this is just because (non _) malloc expects to get a chunk in the free list
            self.top = MallocChunk(self.top.size - sz, self.top.address + sz, BinType.TOP)
            return victim

        # if we have anything in the fastbins - consolidate, then resort and scan bins
        elif any(self.fastbins):
            self.consolidate()
            assert False
        else:
            self.sysmalloc(sz)


    def sysmalloc(self, sz: int) -> MallocChunk:
        if sz >= MMAP_THRESHOLD:
            #TODO: mmaped chunks
            assert False


        alloc_size = sz + MIN_CHUNK_SIZE + TOP_PAD - self.top.size

        # align alloc_size up to a multiple of a page
        alloc_size = (alloc_size + PAGE_SIZE - 1)& ~PAGE_SIZE

        # here malloc would call sbrk(size) - effectively allocating size bytes to top
        self.top.size += alloc_size


        assert self.top.size >= sz + MIN_CHUNK_SIZE

        victim = MallocChunk(sz, self.top.address, BinType.UNKNOWN)
        self.add_to_free_chunks(victim)
        self.top = MallocChunk(self.top.size - sz, self.top.address + sz, BinType.TOP)

        return victim




    def free(self, addr: int) -> None:
        #TODO: int_free_maybe_consolidate
        #TODO: systrim
        chunk = self.allocated_chunks.pop(addr)
        self.add_to_free_chunks(chunk)

        sz = chunk.size

        if sz <= MAX_TCACHE_SIZE:
            tcache_idx = sz // 0x10
            if len(self.tcache[tcache_idx]) < MAX_TCACHE_LEN:
                chunk.bin = BinType.TCACHE
                self.tcache[tcache_idx].append(chunk)
                return

        if sz <= MAX_FAST_SIZE:
            fastbin_idx = sz // 0x10
            chunk.bin = BinType.FASTBIN
            return self.fastbins[fastbin_idx].append(chunk)

        # TODO: add support for mmaped chunks

        chunk = self.coalesce_chunk(chunk)
        # coalsced with top
        if chunk is None:
            return
        sz = chunk.size

        if sz >= MIN_LARGE_SIZE:
            # if the chunk is large place it in the unsorted bin
            chunk.bin = BinType.UNSORTED_BIN
            self.unsorted_bin.append(chunk)
        else:
            # if the chunk is small place it directly in the smallbin
            # this is only true since e2436d6f5aa47ce8da80c2ba0f59dfb9ffde08f3 (Nov 2024)
            smallbin_idx = sz // 0x10
            chunk.bin = BinType.SMALLBIN
            self.smallbins[smallbin_idx].append(chunk)
        return
