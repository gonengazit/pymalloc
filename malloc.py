from math import ceil
from collections import deque
from dataclasses import dataclass
MAX_FAST_SIZE=0xA0
MAX_TCACHE_SIZE = 0x408
MIN_LARGE_SIZE = 0x400
MIN_CHUNK_SIZE = 0x20
MALLOC_HEADER_SIZE = 8
MAX_TCACHE_LEN = 7
NBINS = 128
NUM_SMALL_BINS = MIN_LARGE_SIZE//0x10
NUM_LARGE_BINS = NBINS - NUM_SMALL_BINS

@dataclass
class MallocChunk:
    size: int
    address: int


class PtMallocState:
    def __init__(self) -> None:
        self.tcache = [deque() for _ in range(0, MAX_TCACHE_SIZE, 0x10)] # stack
        self.fastbins = [deque() for _ in range(0, MAX_FAST_SIZE, 0x10)] # stack
        self.unsorted_bin = deque() # queue
        self.smallbins = [deque() for _ in range(0, MIN_LARGE_SIZE, 0x10)] # queue
        self.largebins = [[] for _ in range(NUM_LARGE_BINS)] # queue-ish - sorted smallest to largest
        self.last_remainder = None
        self.top = 0x400000

        # because our chunks aren't actually contiguous in memory - we'll store a big lookup table of all the chunks
        self.free_chunks_by_start = {}
        self.free_chunks_by_end = {}
        self.allocated_chunks = {}

    def split_chunk(self, victim: MallocChunk, alloc_sz: int) ->tuple[MallocChunk, MallocChunk]:
        """split victim into 2 chunks - the first of size alloc_sz"""
        remainder_size = victim.size - alloc_sz
        assert remainder_size >= MIN_CHUNK_SIZE
        remainder = MallocChunk(remainder_size, victim.address + alloc_sz)
        split_victim = MallocChunk(alloc_sz, victim.address)

        self.remove_from_free_chunks(victim)
        self.add_to_free_chunks(remainder)
        self.add_to_free_chunks(split_victim)

        return split_victim, remainder

    def merge_chunks(self, l: MallocChunk, r: MallocChunk) -> MallocChunk:
        assert r.address == l.address + l.size
        merged_chunk = MallocChunk(l.size + r.size, l.address)

        self.remove_from_free_chunks(l)
        self.remove_from_free_chunks(r)
        self.add_to_free_chunks(merged_chunk)

        return merged_chunk

    def add_to_free_chunks(self, victim: MallocChunk):
        self.free_chunks_by_start[victim.address]=victim
        self.free_chunks_by_end[victim.address + victim.size] = victim
        pass

    def remove_from_free_chunks(self, victim: MallocChunk):
        del self.free_chunks_by_start[victim.address]
        del self.free_chunks_by_end[victim.address + victim.size]
        #TODO: improve the performance of this
        for bin in self.tcache:
            if victim in bin:
                bin.remove(victim)

        for bin in self.smallbins:
            if victim in bin:
                bin.remove(victim)

        for bin in self.largebins:
            if victim in bin:
                bin.remove(victim)

        if victim in self.unsorted_bin:
            self.unsorted_bin.remove(victim)

    def consolidate(self):
        for fb in self.fastbins:
            while fb:
                p = fb.pop()
                self.coalesce_chunk(p)

    def coalesce_chunk(self, chunk: MallocChunk) -> MallocChunk | None:
        """Coalesce a chunk with its neighbours if they are free, and move the colesced chunk to the unsorted bin
        if the chunk is next to the heap top - extend the top with it instead and return None"""
        if chunk.address in self.free_chunks_by_end:
            prev = self.free_chunks_by_end[chunk.address]
            chunk = self.merge_chunks(prev, chunk)

        if chunk.address + chunk.size in self.free_chunks_by_start:
            next = self.free_chunks_by_start[chunk.address + chunk.size]

            chunk = self.merge_chunks(chunk, next)

        elif chunk.address + chunk.size == self.top:
            self.top = chunk.address
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
        if tcache_idx < len(self.tcache) and self.tcache[tcache_idx]:
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
        if smallbin_idx < len(self.smallbins) and self.smallbins[smallbin_idx]:
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
            if smallbin_idx < len(self.smallbins) and not self.unsorted_bin and victim == self.last_remainder and victim.size > sz + MIN_CHUNK_SIZE:
                split_victim, remainder = self.split_chunk(victim, sz)

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
            if victim.size < MIN_LARGE_SIZE:
                victim_smallbin_idx = victim.size // 0x10
                self.smallbins[victim_smallbin_idx].append(victim)
            else:
                victim_largebin_idx = self.largebin_index(victim.size)
                bin = self.bin_at(victim_largebin_idx)
                # make sure we got a largebin
                assert isinstance(bin, list)
                # insert chunk into bin maintaining sorted order.
                # if there bin already contains some chunks of the exact same time - we'll insert our new chunk to be 2nd with them
                for i, chunk in enumerate(bin):
                    if chunk.size > sz:
                        bin.insert(i, victim)
                        break
                    elif chunk.size == sz:
                        bin.insert(i+1, victim)
                        break
                # this will be the largest chunk in the bin
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

                    # if there's multiple chunks of the same size - allocate the 2nd one
                    if i + 1 < len(bin) and bin[i+1].size == chunk.size:
                        victim = bin.pop(i+1)
                    else:
                        victim = bin.pop(i)

                    # Split chunk
                    if victim.size - sz >= MIN_CHUNK_SIZE:
                        victim, remainder = self.split_chunk(victim, sz)
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

            victim = bin[0]
            assert victim.size >= sz
            remainder_size = victim.size - sz
            bin.remove(victim)
            # Exhaust
            if remainder_size < MIN_CHUNK_SIZE:
                return victim

            # Split
            else:
                split_victim, remainder = self.split_chunk(victim, sz)
                self.unsorted_bin.append(remainder)
                if sz < MIN_LARGE_SIZE:
                    self.last_remainder = remainder
                return split_victim

        # allocate from the top chunk
        # TODO: have the top actually have a size. if it fails - before we allocate from it we consolidate and retry
        victim = MallocChunk(sz, self.top)
        self.add_to_free_chunks(victim)
        self.top += sz
        return victim

    def free(self, addr: int) -> None:
        chunk = self.allocated_chunks.pop(addr)
        self.add_to_free_chunks(chunk)

        sz = chunk.size

        if sz < MAX_TCACHE_SIZE:
            tcache_idx = sz // 0x10
            self.tcache[tcache_idx].append(chunk)
            return

        if sz <= MAX_FAST_SIZE:
            fastbin_idx = sz // 0x10
            return self.fastbins[fastbin_idx].pop()

        # TODO: add support for mmaped chunks

        chunk = self.coalesce_chunk(chunk)
        # coalsced with top
        if chunk is None:
            return
        sz = chunk.size

        if sz >= MIN_LARGE_SIZE:
            # if the chunk is large place it in the unsorted bin
            self.unsorted_bin.append(chunk)
        else:
            # if the chunk is small place it directly in the smallbin
            smallbin_idx = sz // 0x10
            self.smallbins[smallbin_idx].append(chunk)
        return























