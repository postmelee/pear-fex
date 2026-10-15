// SPDX-License-Identifier: MIT
// Compiler-sized resource evidence for the finite three-thread EC profile.
// No code is linked into the runtime and no constructor is executed.
#include "Interface/Context/Context.h"
#include "Interface/Core/CPUBackend.h"
#include "Interface/Core/JIT/JITClass.h"
#include "Interface/Core/Dispatcher/Dispatcher.h"
#include "Interface/Core/LookupCache.h"
#include "Interface/Core/SharedCodeBufferManager.h"
#include <FEXCore/Debug/InternalThreadState.h>
#define PEAR_LAYOUT(Name, Type) extern "C" { unsigned char pear_layout_##Name[sizeof(Type)]; }
PEAR_LAYOUT(context, FEXCore::Context::ContextImpl)
PEAR_LAYOUT(thread, FEXCore::Core::InternalThreadState)
PEAR_LAYOUT(backend, FEXCore::CPU::CPUBackend)
PEAR_LAYOUT(dispatcher, FEXCore::CPU::Dispatcher)
PEAR_LAYOUT(lookup, FEXCore::LookupCache)
PEAR_LAYOUT(buffer, FEXCore::CPU::CodeBuffer)
PEAR_LAYOUT(token, FEXCore::Utils::PearFEXMemory::TokenState)
PEAR_LAYOUT(lifetime, FEXCore::Utils::PearFEXMemory::SourceLifetime)
PEAR_LAYOUT(jit, FEXCore::CPU::Arm64JITCore)
