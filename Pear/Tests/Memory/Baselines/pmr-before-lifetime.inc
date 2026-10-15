namespace fextl { namespace pmr {
  class named_monotonic_page_buffer_resource final : public std::pmr::memory_resource {
  public:
    explicit named_monotonic_page_buffer_resource(const char* Name)
      : Name {Name} {}

    void release() noexcept {
      for (auto& Iter : Buffers) {
        FEXCore::Allocator::VirtualFree(Iter.Buffer, Iter.BufferSize);
      }
      Buffers.clear();

      CurrentBufferRemaining = 0;
      CurrentAllocationSize = FEXCore::Utils::FEX_PAGE_SIZE;
    }

  protected:
    void* do_allocate(std::size_t bytes, std::size_t alignment) override {
      LOGMAN_THROW_A_FMT(bytes != 0, "Nope");
      LOGMAN_THROW_A_FMT(alignment <= FEXCore::Utils::FEX_PAGE_SIZE, "Nope");

      // Wow, an actual use case of std::align in the wild.
      void* NewPointer = std::align(alignment, bytes, CurrentBuffer, CurrentBufferRemaining);
      if (!NewPointer) [[unlikely]] {
        AllocateNewBuffer(bytes, alignment);
        NewPointer = CurrentBuffer;
      }

      CurrentBuffer = static_cast<char*>(CurrentBuffer) + bytes;
      CurrentBufferRemaining -= bytes;

      return NewPointer;
    }

    void do_deallocate(void*, std::size_t, std::size_t) override {
      // Explicit no-op.
    }

    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
      return this == &other;
    }

  private:
    const char* Name;

    // Allocate a new buffer that can at least fit the passed in bytes with alignment.
    void AllocateNewBuffer(std::size_t bytes, std::size_t) {
      bytes = FEXCore::AlignUp(bytes, CurrentAllocationSize);
      void* Ptr = FEXCore::Allocator::VirtualAlloc(bytes);
      if (Name) {
        FEXCore::Allocator::VirtualName(Name, Ptr, bytes);
      }

      Buffers.emplace_back(BufferData {
        .Buffer = Ptr,
        .BufferSize = bytes,
      });

      CurrentBuffer = Ptr;
      CurrentBufferRemaining = bytes;

      // Multiply the allocation size by 1.5 for the next allocation
      // Avoid double math because of ugly conversions.
      CurrentAllocationSize = FEXCore::AlignUp(CurrentAllocationSize + (CurrentAllocationSize >> 1), FEXCore::Utils::FEX_PAGE_SIZE);
    }

    // Current buffer management.
    void* CurrentBuffer {};
    size_t CurrentBufferRemaining {};

    struct BufferData final {
      void* Buffer;
      size_t BufferSize;
    };

    fextl::list<BufferData> Buffers {};

    size_t CurrentAllocationSize = FEXCore::Utils::FEX_PAGE_SIZE;
  };

} }
