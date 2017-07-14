#!/usr/bin/env python
import angr, simuvex, claripy, archinfo
from simuvex.s_type import SimTypeLength, SimTypeTop

class WinAbi(simuvex.DefaultCC['AMD64']):
    ARG_REGS = ['rcx', 'rdx', 'r8', 'r9']
    STACKARG_SP_BUFF = 0x20

class WinState(simuvex.SimStatePlugin):
    def __init__(self):
        simuvex.SimStatePlugin.__init__(self)
        self.module_handles = []
        self.fls = []#[claripy.BVS("unconstrained fls (wtf)", 64)]
        self.objects = [None]

    def new(self, o):
        h = len(self.objects)
        self.objects.append(o)
        return h

    def copy(self):
        ret = WinState()
        ret.module_handles = self.module_handles # clone
        ret.fls = self.fls # clone
        ret.objects = self.objects # bug
        return ret

    #def merge(self, others, flag, flag_values):
    #def widen(self, others):   

class WinMutex:
    def __init__(self, initial):
        if initial:
            self.locked = 1
        else:
            self.locked = 0
    def wait(self):
        assert self.locked == 0
        self.locked += 1
    def unlock(self):
        self.locked -= 1
        assert self.locked == 0

class WinEvent:
    def __init__(self, manual, initial):
        self.is_set = initial
        self.manual = manual
    def wait(self):
        assert self.is_set
        if not self.manual:
            self.is_set = False
    def set(self):
        self.is_set = True
    def reset(self):
        self.is_set = False
        
    
class WinProc(simuvex.SimProcedure):
    ALIASES = []
    def __init__(self, *args, **kwargs):
        global cc
        simuvex.SimProcedure.__init__(self, convention=cc, *args, **kwargs)

    def load_str(self, x, encoding=None, maxlen=32):
        if self.state.se.any_int(x) == 0:
            return '<null>'
        else:
            s = self.state.se.any_str(self.state.memory.load(x, maxlen))
            if encoding:
                s = s.decode(encoding).encode('ascii')
            else:
                s += '\0'
            s, _ = s.split('\0', 1)
            return s

    def obj(self, handle):
        return self.state.win.objects[self.state.se.any_int(handle)]

class malloc(WinProc):
    def run(self, sim_size):
        self.argument_types = {0: SimTypeLength(self.state.arch)}
        self.return_type = self.ty_ptr(SimTypeTop(sim_size))

        if self.state.se.symbolic(sim_size):
            size = self.state.se.max_int(sim_size)
            if size > self.state.libc.max_variable_size:
                size = self.state.libc.max_variable_size
        else:
            size = self.state.se.any_int(sim_size)

        addr = self.state.libc.heap_location
        self.state.libc.heap_location += size
        print 'malloc(%08x) = %08x' % (size, addr)
        return addr

class CreateMutexA(WinProc):
    def run(self, attr, initial_owner, name):
        initial_owner = self.state.se.any_int(initial_owner) != 0
        print 'CreateMutexA(%s, %s, %s)' % (attr, initial_owner, self.load_str(name))
        return self.state.win.new(WinMutex(initial_owner))

class CreateEventA(WinProc):
    def run(self, attr, manual, initial, name):
        manual = self.state.se.any_int(manual) != 0
        initial = self.state.se.any_int(initial) != 0
        print 'CreateEventA(%s, %s, %s, %s)' % (attr, manual, initial, self.load_str(name))
        return self.state.win.new(WinEvent(manual, initial))

class WaitForSingleObject(WinProc):
    def run(self, handle, millis):
        print 'WaitForSingleObject(%s, %s)' % (handle, millis)
        self.obj(handle).wait()
        return 0

class RegOpenKeyExA(WinProc):
    def run(self, key, subkey, options, sam, result):
        print 'RegOpenKeyExA(%s, %s, %s, %s, %s)' % (key, self.load_str(subkey), options, sam, result)
        self.state.memory.store(result, claripy.BVV(0xdeadbeefdeadbeef, 64))
        return 0

class RegQueryValueExA(WinProc):
    def run(self, key, name, resv, typ, data, data2):
        print 'RegQueryValueExA(%s, %s, %s, %s, %s, %s)' % (key, self.load_str(name), resv, typ, data, data2)
        #path = 'C:\Brogram Files\iTunes\CoreFP.dll'
        self.state.memory.store(data2, claripy.BVV(0x04000000, 32))
        if self.state.se.any_int(data) != 0:
            self.state.memory.store(data, claripy.BVV(0x00333333, 32))
        return 0

class ResetEvent(WinProc):
    def run(self, handle):
        print 'ResetEvent(%s)' % handle
        self.obj(handle).reset()
        return 1

class ReleaseMutex(WinProc):
    def run(self, handle):
        print 'ReleaseMutex(%s)' % handle
        self.obj(handle).unlock()
        return 1

class GetCurrentThreadId(WinProc):
    ALIASES = ['GetCurrentProcessId']
    def run(self):
        print 'GetCurrentThreadId()'
        return 42

class InitializeCriticalSectionEx(WinProc):
    def run(self, ptr, spinCount, flags):
        print 'InitializeCriticalSectionEx(???)'
        return 1

class HeapAlloc(WinProc):
    def run(self, heap, flags, sim_size):
        #self.argument_types = {0: SimTypeLength(self.state.arch)}
        #self.return_type = self.ty_ptr(SimTypeTop(sim_size))
        
        if self.state.se.symbolic(sim_size):
            size = self.state.se.max_int(sim_size)
            if size > self.state.libc.max_variable_size:
                size = self.state.libc.max_variable_size
        else:
            size = self.state.se.any_int(sim_size)
                
        addr = self.state.libc.heap_location
        self.state.libc.heap_location += size
        print 'HeapAlloc(%s, %s, %08x) = %08x' % (heap, flags, size, addr)
        self.state.memory.store(addr, claripy.BVV(0, size * 8)) # ???
        return addr

class HeapSize(WinProc):
    def run(self, heap, flags, mem):
        print 'HeapSize(%s, %s, %s)' % (heap, flags, mem)
        return -1
    
class FlsAlloc(WinProc):
    def run(self, ptr):
        print 'FlsAlloc(%s)' % ptr
        i = len(self.state.win.fls)
        self.state.win.fls.append(0)
        return i
    
class FlsSetValue(WinProc):
    def run(self, index, data):
        print 'FlsSetValue(%s, %s)' % (index, data)
        #global fls
        #fls = data
        #self.state.win.fls = data
        #return 1
        self.state.win.fls[self.state.se.any_int(index)] = data
        return 1

class FlsGetValue(WinProc):
    def run(self, index):
        print 'FlsGetValue(%s)' % index
        #global fls
        #fls = self.state.win.fls
        #return fls
        return self.state.win.fls[self.state.se.any_int(index)]

class WideCharToMultiByte(WinProc):
    def run(self, CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar):
        print 'WideCharToMultiByte(%s, %s, %s, %s, %s, %s, %s, %s)' % (CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar)
        return 1

class GetStdHandle(WinProc):
    def run(self, kind):
        print 'GetStdHandle(%s)' % kind
        return self.state.win.new(kind)

class GetFileType(WinProc):
    def run(self, handle):
        print 'GetFileType(%s)' % handle
        return 1
    
class GetACP(WinProc):
    def run(self):
        print 'GetACP()'
        return 65001

class GetLastError(WinProc):
    def run(self):
        print 'GetLastError()'
        return 0

class HeapFree(WinProc):
    def run(self, hHeap, dwFlags, lpMem):
        print 'HeapFree(%s, %s, %s)' % (hHeap, dwFlags, lpMem)
        return 1

class GetModuleFileNameA(WinProc):
    def run(self, hModule, lpFilename, nSize):
        print 'GetModuleFileName(%s, %s, %s)' % (hModule, lpFilename, nSize)
        self.state.memory.store(lpFilename, claripy.BVV(0, 16))
        return 1

class GetCommandLineA(WinProc):
    def run(self):
        addr = self.state.libc.heap_location
        self.state.libc.heap_location += 1
        self.state.memory.store(addr, claripy.BVV(0, 8))
        print 'GetCommandLineA() = %s' % hex(addr)
        return addr
    
RAMBO = True
#ReturnUnconstrained = simuvex.SimProcedures['stubs']['ReturnUnconstrained']
class ReturnUnconstrained(WinProc):
    def run(self, resolves=None):
        self.resolves = resolves
        self.successors.artifacts['resolves'] = resolves
        print '[UC] %s' % resolves
        if RAMBO:
            return 1
        else:
            return self.state.se.Unconstrained("unconstrained_ret_%s" % resolves, self.state.arch.bits)

simuvex.SimProcedures['stubs']['ReturnUnconstrained'] = ReturnUnconstrained

module_handles = [None]
modules = {
    'kernel32.dll': '''{
        'FlsAlloc': FlsAlloc,
        'FlsFree': None,
        'FlsGetValue': FlsGetValue,
        'FlsSetValue': FlsSetValue,
        'InitializeCriticalSectionEx': InitializeCriticalSectionEx,
        'CreateSemaphoreExW': None,
        'SetThreadStackGuarantee': None,
        'CreateThreadpoolTimer': None,
        'SetThreadpoolTimer': None,
        'WaitForThreadpoolTimerCallbacks': None,
        'CloseThreadpoolTimer': None,
        'CreateThreadpoolWait': None,
        'SetThreadpoolWait': None,
        'CloseThreadpoolWait': None,
        'FlushProcessWriteBuffers': None,
        'FreeLibraryWhenCallbackReturns': None,
        'GetCurrentProcessorNumber': None,
        'GetLogicalProcessorInformation': None,
        'CreateSymbolicLinkW': None,
        'SetDefaultDllDirectories': None,
        'EnumSystemLocalesEx': None,
        'CompareStringEx': None,
        'GetDateFormatEx': None,
        'GetLocaleInfoEx': None,
        'GetTimeFormatEx': None,
        'GetUserDefaultLocaleName': None,
        'IsValidLocaleName': None,
        'LCMapStringEx': None,
        'GetCurrentPackageId': None,
    }''',
}

class LoadLibraryA(WinProc):
    def run(self, name):
        lname = self.load_str(name, maxlen=11)
        name = lname[1:] if lname == '\CoreFP.dll' else self.load_str(name)
        print 'LoadLibraryA(%s)' % (name,)
        module_handles.append(name)
        return len(module_handles) - 1

class GetModuleHandleW(WinProc):
    def run(self, name):
        name = self.load_str(name, 'utf-16') #.decode('utf-16')
        print 'GetModuleHandleW(%s)' % (name,)
        module_handles.append(name)
        return len(module_handles) - 1

class GetProcAddress(WinProc):
    def run(self, handle, proc_name):
        mod = module_handles[self.state.se.any_int(handle)]
        proc = self.load_str(proc_name)
        print 'GetProcAddress(%s, %s)' % (mod, proc)
        #try:
        if mod == 'kernel32.dll':
            #module = modules[mod]
            return get_winapi_hook(proc)
        #except KeyError:
        else:
            return b.loader.shared_objects[mod].get_symbol(proc).rebased_addr
        #return module[proc]
        #return b.loader.shared_objects['CoreFP.dll'].get_symbol(proc).rebased_addr
        #return 0xfeedfeedfeedfeed

class GetSystemTimeAsFileTime(WinProc):
    def run(self, ptr):
        print 'GetSystemTimeAsFileTime(%s)' % ptr
        self.state.memory.store(ptr, claripy.BVV(0x0000000000000000, 64))
        return 0

class QueryPerformanceCounter(WinProc):
    def run(self, ptr):
        print 'QueryPerformanceCounter(%s)' % ptr
        self.state.memory.store(ptr, claripy.BVV(0x0000000000000000, 64))
        return 1

class AllocaProbe(WinProc):
    def run(self):
        return None

class GetEnvironmentStringsW(WinProc):
    def run(self):
        addr = self.state.libc.heap_location
        self.state.libc.heap_location += 4
        self.state.memory.store(addr, claripy.BVV(0x00000000, 32))
        return addr

class GetProcessHeap(WinProc):
    def run(self):
        print 'GetProcessHeap()'
        return self.state.win.new(None)
    
class NopcodePointer(WinProc):
    ALIASES = ['EncodePointer', 'DecodePointer']
    def run(self, ptr):
        print '##codePointer(%s)' % ptr
        return ptr

class VirtualAlloc(WinProc):
    def run(self, addr, sim_size, typ, protect):
        print 'VirtualAlloc(%s, %s, %s, %s)' % (addr, sim_size, typ, protect)
        if self.state.se.symbolic(sim_size):
            size = self.state.se.max_int(sim_size)
            if size > self.state.libc.max_variable_size:
                size = self.state.libc.max_variable_size
        else:
            size = self.state.se.any_int(sim_size)
                
        addr = self.state.libc.heap_location
        self.state.libc.heap_location += size
        return addr

class GetSystemInfo(WinProc):
    def run(self, ptr):
        ptr = self.state.se.any_int(ptr)
        print 'GetSystemInfo(%s)' % ptr
        #self.state.memory.store(ptr, claripy.BVV(0, 6*8*8)) #lmao
        self.state.memory.store(ptr, claripy.BVV(9, 16).reversed) #amd64
        self.state.memory.store(ptr + 4, claripy.BVV(4096, 32).reversed) #page size
        self.state.memory.store(ptr + 5*8, claripy.BVV(4096, 32).reversed) 
        return 0

'''
  _Out_ HCRYPTPROV *phProv,
  _In_  LPCTSTR    pszContainer,
  _In_  LPCTSTR    pszProvider,
  _In_  DWORD      dwProvType,
  _In_  DWORD      dwFlags
'''

class CryptAcquireContextA(WinProc):
    def run(self, phProv, pszContainer, pszProvider, dwProvType, dwFlags):
        pszContainer = self.load_str(pszContainer)
        pszProvider = self.load_str(pszProvider)
        print 'CryptAcquireContextA(%s, %s, %s, %s, %s)' % (phProv, pszContainer, pszProvider, dwProvType, dwFlags)
        return 1

import random
class CryptGenRandom(WinProc):
    def run(self, hProv, dwLen, pbBuffer):
        print 'CryptGenRandom(%s, %s, %s)' % (hProv, dwLen, pbBuffer)
        l = self.state.se.any_int(dwLen) * 8
        self.state.memory.store(pbBuffer, claripy.BVV(random.getrandbits(l), l))
        return 1

class CryptReleaseContext(WinProc):
    def run(self, hProv, dwFlags):
        print 'CryptReleaseContext(%s, %s)' % (hProv, dwFlags)
        return 1


# 50 mins wtf
b = angr.Project("iTunes.exe",
                 #support_selfmodifying_code=True,
                 load_options={'auto_load_libs':False, 'force_load_libs': ['CoreFP.dll']})
#b.factory.full_init_state(
#    add_options={simuvex.options.UNICORN},
#    remove_options={ simuvex.options.LAZY_SOLVES }
#)
cc = WinAbi(arch=b.arch, args=None, ret_val=None, sp_delta=None, func_ty=None)

#fancymath = b.factory.callable(0x1400623b0, cc=cc)
#raise ValueError()

'''
for mod in modules.itervalues():
    for k, v in mod.iteritems():
        pseudo_addr = b._extern_obj.get_pseudo_addr(k)
        if v is None:
            b.hook(pseudo_addr, ReturnUnconstrained, kwargs={'resolves': k})
        else:
            b.hook(pseudo_addr, v)
        mod[k] = pseudo_addr
        print '%s is at 0x%08x' % (k, pseudo_addr)
'''
def get_winapi_hook(name):
    try:
        return winapi_hooks[name]
    except KeyError:
        pseudo_addr = b._extern_obj.get_pseudo_addr(name)
        b.hook(pseudo_addr, ReturnUnconstrained, kwargs={'resolves': name})
        winapi_hooks[name] = pseudo_addr
        return pseudo_addr

rax = b.factory.cc.SimRegArg("rax", 8)
rcx = b.factory.cc.SimRegArg("rcx", 8)
rdx = b.factory.cc.SimRegArg("rdx", 8)
r8 = b.factory.cc.SimRegArg("r8", 8)
r9 = b.factory.cc.SimRegArg("r9", 8)
sa1 = b.factory.cc.SimStackArg(24, 8)
sa2 = b.factory.cc.SimStackArg(32, 8)

winapi_hooks = {}
def resolve_dependency(name, func):
    pseudo_addr = b._extern_obj.get_pseudo_addr(name)
    pseudo_offset = pseudo_addr - b._extern_obj.rebase_addr
    b.loader.provide_symbol(b._extern_obj, name, pseudo_offset)
    winapi_hooks[name] = pseudo_addr
    for alias in func.ALIASES:
        winapi_hooks[alias] = pseudo_addr
        b.loader.provide_symbol(b._extern_obj, alias, pseudo_offset)
    b.hook(pseudo_addr, func)

'''
resolve_dependency('GetModuleHandleW', GetModuleHandleW)
resolve_dependency('GetProcAddress', GetProcAddress)
resolve_dependency('GetCurrentThreadId', GetCurrentThreadId)
resolve_dependency('GetCurrentProcessId', GetCurrentThreadId) #HACK
resolve_dependency('GetSystemTimeAsFileTime', GetSystemTimeAsFileTime)
resolve_dependency('QueryPerformanceCounter', QueryPerformanceCounter)
resolve_dependency('HeapAlloc', HeapAlloc)
resolve_dependency('GetEnvironmentStringsW', GetEnvironmentStringsW)
resolve_dependency('EncodePointer', NopcodePointer)
resolve_dependency('DecodePointer', NopcodePointer)
resolve_dependency('VirtualAlloc', VirtualAlloc)
resolve_dependency('WaitForSingleObject', WaitForSingleObject)
resolve_dependency('CreateMutexA', CreateMutexA)
resolve_dependency('ReleaseMutex', ReleaseMutex)
resolve_dependency('CreateEventA', CreateEventA)
resolve_dependency('ResetEvent', ResetEvent)
resolve_dependency('GetSystemInfo', GetSystemInfo)
resolve_dependency('CryptAcquireContextA', CryptAcquireContextA)
resolve_dependency('CryptGenRandom', CryptGenRandom)
resolve_dependency('CryptReleaseContext', CryptReleaseContext)
resolve_dependency('GetProcessHeap', GetProcessHeap)
'''
for p in WinProc.__subclasses__():
    resolve_dependency(p.__name__, p)

plugins = {'win': WinState()}

#resolve_dependency('InitializeCriticalSectionEx', InitializeCriticalSectionEx)
'''
b.hook(0x1416c68c4, malloc) #simuvex.SimProcedures['libc.so.6']['malloc'])
#b.hook(0x1416c6ee4, CreateMutexA)
#b.hook(0x1416c7034, CreateEventA)
#b.hook(0x1416c4646, WaitForSingleObject)
b.hook(0x1416c6972, RegOpenKeyExA)
b.hook(0x1416c6978, RegQueryValueExA)
#b.hook(0x1416c6ef6, ResetEvent)
#b.hook(0x1416c6eea, ReleaseMutex)
b.hook(0x1416c7028, LoadLibraryA)
b.hook(0x1416c4640, GetProcAddress)
'''
b.hook(0x7df5d890, AllocaProbe)
b.hook(0x1416c7080, AllocaProbe)

ss = b.factory.call_state(b.loader.shared_objects['CoreFP.dll'].entry, 0, 1, 0, cc=cc, plugins=plugins)
#def cslul(state):
#    print state.inspect.mem_write_expr
#    print state.regs.rsp
#ss.inspect.b('mem_write', mem_write_address=0x7e60ce40, action=cslul)

#ppg = b.factory.path_group(ss)
#while (not ppg.errored) and (len(ppg.deadended) <= 1):
#    print ppg
#    ppg.step()

#if len(ppg.deadended) > 1:
#    print ppg.deadended[1].state.regs.rax
#    print ppg.deadended[1].trace[-1]
#    print ppg.deadended[1].trace[-2]
#    print ppg.deadended[1].trace[-3]
#else:
#    print ppg.errored[0].error

#raise ValueError()

RAMBO = False #feelsbadman

pp = b.factory.path(ss)
while pp.step():
    assert len(pp.successors) == 1
    pp = pp.successors[0]

RAMBO = False


print '=' * 30
print '=' * 30
print '=' * 30

# fuckingshit(foo, buf, len, &bufptr, &buflen)
deadbeef0 = claripy.BVS("unconstrained INPUT 0", 64)
deadbeef1 = claripy.BVS("unconstrained INPUT 1", 64)
deadbeef2 = claripy.BVS("unconstrained INPUT 2", 64)
deadbeef3 = claripy.BVS("unconstrained INPUT 3", 64)
deadbeef4 = claripy.BVS("unconstrained INPUT 4", 64)

csf = b.factory.call_state(0x1400556c0, deadbeef0, deadbeef1, deadbeef2, deadbeef3, deadbeef4, cc=cc, base_state=pp.state, plugins=plugins,
                           add_options=simuvex.o.unicorn)
                           #add_options={simuvex.options.UNICORN},
                           #remove_options={simuvex.options.LAZY_SOLVES})
#csf.regs.
#csf = b.factory.call_state(0x1400556c0, deadbeef, 0x42000, 64, 0x43000, 0x44000, cc=cc, base_state=pp.state) #, add_options=simuvex.o.unicorn)
#csf.memory.store(0x44000, claripy.BVV(0, 64))
#csf = b.factory.call_state(0x1400556c0, 0xdeadbeef0badbeef, 1337, 0xbebebebe, 0xebebebeb, cc=cc, base_state=pp.state) #, add_options=simuvex.o.unicorn)
#raise ValueError()

#p = b.factory.path(csf)
#while p.addr != 0x7d020c17:
#    #print p
#    r = p.step()
#    #print r
#    p = r[0]
#raise ValueError()

#csf.inspect.b('mem_read', mem_read_address=

pg = b.factory.path_group(csf)

pg.use_technique(angr.exploration_techniques.Oppologist())
pg.explore()
raise ValueError()


while len(pg.deadended) == 0 and len(pg.errored) == 0: # and len(pg.active) == 1:
    print pg, hex(pg.active[0].addr)
    pg.step()

if pg.deadended:
    print pg.deadended[0].state.regs.rax
    print pg.deadended[0].trace[-1]
    print pg.deadended[0].trace[-2]
    print pg.deadended[0].trace[-3]
else:
    print pg.errored[0].error
