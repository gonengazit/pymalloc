from malloc import PtMallocState
import random
def main():
    malloc = PtMallocState()

    chunks = []
    for i in range(100):
        if random.random() < 0.5 or not chunks:

            sz = random.randint(1,1500) & ~0xf
            chunk = malloc.malloc(sz)
            print(f"malloc({sz:#x}) = {chunk:#x}")
            chunks.append(chunk)

        else:
            chunk = random.choice(chunks)
            chunks.remove(chunk)
            malloc.free(chunk)
            print(f"free({chunk:#x})")

# malloc = PtMallocState()
# def test_malloc(sz):
#     chunk = malloc.malloc(sz)
#     print(f"malloc({sz:#x}) = {chunk:#x}")
#
# def test_free(chunk):





if __name__ == "__main__":
    main()
