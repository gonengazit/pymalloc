from malloc import PtMallocState
import random
malloc = PtMallocState()
def test_malloc(sz):
    print(f"malloc({sz:#x}) = ", end="")
    chunk = malloc.malloc(sz)
    print(f"{chunk:#x}")
    return chunk

def test_free(addr):
    print(f"free({addr:#x})")
    malloc.free(addr)
def main():

    chunks = []
    for i in range(100000):
        if random.random() < 0.5 or not chunks:

            sz = random.randint(1,1500) & ~0xf
            chunk = test_malloc(sz)
            chunks.append(chunk)

        else:
            chunk = random.choice(chunks)
            chunks.remove(chunk)
            test_free(chunk)



# def main():
#     a=test_malloc(0x400)
#     test_malloc(0x1d0)
#     b=test_malloc(0x100)
#     test_malloc(0x10)
#     test_free(a)
#     test_malloc(0x3a0)
#     test_free(b)
#     test_malloc(0xc0)




if __name__ == "__main__":
    main()
