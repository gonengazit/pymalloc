from math import ceil
from collections import deque
from dataclasses import dataclass
MAX_FAST_SIZE=0xA0
MAX_TCACHE_SIZE = 0x408
MIN_LARGE_SIZE = 0x400
MIN_CHUNK_SIZE = 0x20
MALLOC_HEADER_SIZE = 8
MAX_TCACHE_LEN = 7

@dataclass
class MallocChunk:
    size: int
    address: int
    next_size: int


class PtMallocState:
    def __init__(self) -> None:
        self.tcache = [deque() for _ in range(0, MAX_TCACHE_SIZE, 0x10)] # stack
        self.fastbins = [deque() for _ in range(0, MAX_FAST_SIZE, 0x10)] # stack
        self.unsorted_bin = deque() # queue
        self.smallbins = [deque() for _ in range(0, MIN_LARGE_SIZE, 0x10)] # queue
        self. last_remainder = None
        self.top = 0x400000

    def malloc(self, sz) -> MallocChunk:
        # make size the actual chunk allocation size, rounded to 0x10 and including heap metadata
        sz = ceil((sz + MALLOC_HEADER_SIZE)/0x10) * 0x10
        sz = max(sz, MIN_CHUNK_SIZE)

        # if we're small enough for the tcache and the relevant tcache is not empty - return the top element from it
        tcache_idx = sz // 0x20
        if tcache_idx < len(self.tcache) and self.tcache[tcache_idx]:
            return self.tcache[tcache_idx].pop()

        # if we're small enough for the fastbins and the relevant fastbin is not empty - return the top element from it
        fastbin_idx = sz // 0x20
        if fastbin_idx < len(self.fastbins) and self.fastbins[fastbin_idx]:
            victim = self.fastbins[fastbin_idx].pop()

            # while we're here - fill the tcache from the fastbin
            while self.fastbins[fastbin_idx] and len(self.tcache[tcache_idx]) < MAX_TCACHE_LEN:
                self.tcache[tcache_idx].append(self.fastbins[fastbin_idx].pop())

            return victim

        # if we're small enough for the smallbins and the relevant smallbin is not empty (exact fit) - return the first element from it
        smallbin_idx = sz // 0x20
        if smallbin_idx < len(self.smallbins):
            victim = self.smallbins[smallbin_idx].popleft()

            # while we're here - fill the tcache from the smallbin
            while self.smallbins[smallbin_idx] and len(self.tcache[tcache_idx]) < MAX_TCACHE_LEN:
                self.tcache[tcache_idx].append(self.smallbins[smallbin_idx].popleft())

            return victim

        else:
            self.consolidate()

        # sort the unsorted bin
        iters = 0
        while self.unsorted_bin:
            victim = self.unsorted_bin.popleft()
            # if this is a small request and the only chunk left in the unsorted bin is the last remainder - split and allocate it.
            # this is the only exception to best-fit
            if smallbin_idx < len(self.smallbins) and not self.unsorted_bin and victim == self.last_remainder and sz > victim.size + MIN_CHUNK_SIZE:
                remainder_size = victim.size - sz
                remainder = MallocChunk(remainder_size, victim.address + sz, victim.next_size)
                split_victim = MallocChunk(sz, victim.address, remainder_size)

                self.unsorted_bin.append(remainder)
                self.last_remainder = remainder

                return split_victim

            # if the chunk exactly fits our request - fill the tcache, and return the chunk if the tcache is full
            if victim.size == sz:
                if tcache_idx < len(self.tcache) and len(self.tcache[tcache_idx]) < MAX_TCACHE_LEN:
                    self.tcache[tcache_idx].append(victim)
                    continue
                else:
                    return victim

            # put the chunk in the relvant bin
            if smallbin_idx < len(self.smallbins):
                self.smallbins[smallbin_idx].append(victim)
            else:
                # TODO: fill largebin
                assert False

            iters += 1
            MAX_ITERS = 10000
            if iters >= MAX_ITERS:
                break

        # if we put chunks in the relevant tcache during sorting - return one now
        if tcache_idx < len(self.tcache) and self.tcache[tcache_idx]:
            return self.tcache[tcache_idx].pop()

        # TODO: scan through the bins
        # TODO: split top
        # TODO: if we fail - consolidate, then sort and retry






        assert False






