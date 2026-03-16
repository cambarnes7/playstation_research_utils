#!/usr/bin/env python3
"""
Prosperous RPC Client for PS5 FW 4.03.

Ported from fail0verflow's prosperous kpayload/client.py.

Connects to the kernel RPC server on port 6670 and provides high-level
APIs for kernel memory access, hardware register manipulation, and
SBL service communication.

Usage:
    from client import Client, Dmap, TmrAccess

    with Client(('ps5_ip', 6670)) as c:
        info = c.runtime_info()
        print(f"Kernel base: {info.kernel_base:#x}")

        # Read kernel memory
        data = c.mem_read(info.kernel_base, 0x100)

        # SMN register access
        val = c.smn_read32(0x02400000)

        # MP4 coprocessor access
        mp4_data = c.mp4_read(0x03230000, 0x100)
"""

import socket
import struct
import os

PS5_IP = os.getenv('PS5_IP', '192.168.2.1')

PAGE_SIZE = 0x4000
PAGE_MASK = PAGE_SIZE - 1


def align_down(val, align):
    return val - val % align


def align_up(val, align):
    return align_down(val + align - 1, align)


def pci_cfg_addr(bus, device, function, offset=0):
    MMCFG_BASE = 0xF0000000
    return MMCFG_BASE | (bus << 20) | (device << 15) | (function << 12) | offset


def make_cmd_hdr(cmd, send_len, resp_len, handle):
    return struct.pack('<IHHQQ', cmd, send_len, resp_len, 0, handle)


def make_sys_mail_hdr(send_len, resp_len, handle):
    return make_cmd_hdr(5, send_len, resp_len, handle)


def make_svc_mail_hdr(handle):
    return make_cmd_hdr(6, 0x80, 0x80, handle)


class Client:
    """RPC client for the prosperous kernel payload on port 6670."""

    def __init__(self, address=None):
        if address is None:
            address = (PS5_IP, 6670)
        self.c = socket.create_connection(address)
        self.sm_tasks = []
        self.buffers = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        for task in self.sm_tasks:
            task.exit_task()
        for buf in self.buffers:
            buf.free()
        return False

    def send(self, data):
        return self.c.sendall(data)

    def recv(self, size):
        return self.c.recv(size, socket.MSG_WAITALL)

    def cmd(self, cmd, buf=b''):
        self.send(struct.pack('<I', cmd) + buf)

    def recv_fmt(self, fmt):
        val = struct.unpack(fmt, self.recv(struct.calcsize(fmt)))
        if len(val) == 1:
            val = val[0]
        return val

    def close(self):
        self.cmd(0)

    def ping(self):
        self.cmd(1)
        return self.recv(5) == b'pong\0'

    # -- Memory allocation --

    def malloc(self, size):
        self.cmd(2, struct.pack('<2Q', 0, size))
        return self.recv_fmt('<Q')

    def free(self, addr):
        self.cmd(3, struct.pack('<3Q', 0, addr, 0))

    def malloc_contig(self, size):
        self.cmd(2, struct.pack('<2Q', 1, size))
        return self.recv_fmt('<Q')

    def free_contig(self, addr, size):
        self.cmd(3, struct.pack('<3Q', 1, addr, size))

    # -- Function calls --

    def call(self, rva, *args):
        num_args = len(args)
        if num_args > 10:
            raise Exception('too many args')
        args = list(args) + [0] * (10 - num_args)
        self.cmd(4, struct.pack('<QQ10Q', rva, num_args, *args))
        return self.recv_fmt('<Q')

    # -- Memory read/write --

    def mem_read(self, addr, size):
        self.cmd(5, struct.pack('<QQ', addr, size))
        return self.recv(size)

    def mem_read_fmt(self, fmt, addr):
        return struct.unpack(fmt, self.mem_read(addr, struct.calcsize(fmt)))[0]

    def mem_read_u8(self, addr):
        return self.mem_read_fmt('<B', addr)

    def mem_read_u32(self, addr):
        return self.mem_read_fmt('<I', addr)

    def mem_read_u64(self, addr):
        return self.mem_read_fmt('<Q', addr)

    def mem_read_str(self, addr, size, encoding='ascii', errors='ignore'):
        return self.mem_read(addr, size).rstrip(b'\0').decode(encoding, errors=errors)

    def mem_write(self, addr, buf):
        self.cmd(6, struct.pack('<QQ', addr, len(buf)) + buf)

    def mem_write_fmt(self, fmt, addr, val):
        self.mem_write(addr, struct.pack(fmt, val))

    def mem_write_u8(self, addr, val):
        self.mem_write_fmt('<B', addr, val)

    def mem_write_u32(self, addr, val):
        self.mem_write_fmt('<I', addr, val)

    def mem_write_u64(self, addr, val):
        self.mem_write_fmt('<Q', addr, val)

    # -- Runtime info --

    def runtime_info(self):
        self.cmd(7)

        class RuntimeInfo:
            def __init__(self, arr):
                self.sdk_ver_ppr, self.kernel_base, self.sym_addr, self.sym_size = arr
        return RuntimeInfo(self.recv_fmt('<4Q'))

    def vtophys(self, va):
        self.cmd(8, struct.pack('<Q', va))
        return self.recv_fmt('<Q')

    # -- SBL service --

    def sblServiceRequest(self, hdr, req, poll=False):
        assert len(hdr) == 0x18
        self.cmd(9, hdr + struct.pack('<I', poll) + req)
        rv = self.recv_fmt('<i')
        if rv == 0x1337dead:
            return None, None
        resp_len = self.recv_fmt('<H')
        return rv, self.recv(resp_len)

    # -- SMN access --

    def smn_read(self, addr, size):
        size_aligned = align_up(size, 4)
        self.cmd(10, struct.pack('<3I', addr, size_aligned // 4, 4))
        status = self.recv_fmt('<I')
        if status != 0:
            return None
        buf = self.recv(size_aligned)
        return buf[:size]

    def smn_read32(self, addr):
        return struct.unpack('<I', self.smn_read(addr, 4))[0]

    def smn_read64(self, addr):
        return struct.unpack('<Q', self.smn_read(addr, 8))[0]

    def smn_write(self, addr, buf):
        size_aligned = align_up(len(buf), 4)
        self.cmd(11, struct.pack('<3I', addr, size_aligned // 4, 4) + buf)
        status = self.recv_fmt('<I')
        return status == 0

    def smn_write32(self, addr, val):
        self.smn_write(addr, struct.pack('<I', val))

    def smn_write64(self, addr, val):
        self.smn_write(addr, struct.pack('<Q', val))

    # -- MP4 access --

    def mp4_read(self, addr, size):
        size_aligned = align_up(size, 4)
        self.cmd(12, struct.pack('<3I', addr, size_aligned // 4, 4))
        status = self.recv_fmt('<I')
        if status != 0:
            return None
        buf = self.recv(size_aligned)
        return buf[:size]

    def mp4_write(self, addr, buf):
        size_aligned = align_up(len(buf), 4)
        self.cmd(13, struct.pack('<3I', addr, size_aligned // 4, 4) + buf)
        status = self.recv_fmt('<I')
        return status == 0

    # -- Data Fabric access --

    def df_read32(self, instance, function, offset):
        self.cmd(14, struct.pack('<5I', 0, instance, function, offset, 0))
        return self.recv_fmt('<I')

    def df_write32(self, instance, function, offset, val):
        self.cmd(14, struct.pack('<5I', 1, instance, function, offset, val))
        return self.recv_fmt('<I') == 0

    # -- SBL service mailbox --

    def sceSblServiceMailbox(self, handle, func_id, mail=b''):
        mail = struct.pack('<HHi', func_id, 0, 0) + mail
        if len(mail) > 0x80:
            raise Exception('mail too big')
        mail = mail.ljust(0x80, b'\0')
        hdr = make_svc_mail_hdr(handle)
        rv, resp = self.sblServiceRequest(hdr, mail)
        return rv, resp

    def sceSblServiceSpawn(self, name):
        req = struct.pack('<Q4I8sQ', 0, 0, 0, 0, 0, bytes(name, 'ascii'), 0)
        assert len(req) == 0x28
        rv, resp = self.sblServiceRequest(make_sys_mail_hdr(0x28, 0x8, 1), req)
        if rv != 0:
            print('sceSblServiceSpawn: %d' % rv)
        else:
            return struct.unpack('<Q', resp)[0]

    # -- Buffer management --

    class RemoteBuffer:
        def __init__(self, size, client):
            self.client = client
            self.size = size
            self.contig = True
            self.va = self.client.malloc_contig(self.size)
            if self.va == 0:
                self.contig = False
                self.va = self.client.malloc(self.size)
            assert self.va != 0
            self.pa = None

        def free(self):
            if self.va is None:
                return
            if self.contig:
                self.client.free_contig(self.va, self.size)
            else:
                self.client.free(self.va)
            self.va = None

        def get_va(self):
            return self.va

        def get_pa(self):
            if self.pa is None:
                self.pa = self.client.vtophys(self.va)
            return self.pa

        def read(self, size=None):
            if size is None:
                size = self.size
            return self.client.mem_read(self.va, size)

        def write(self, buf):
            self.client.mem_write(self.va, buf)

    def buffer_alloc(self, size):
        buf = self.RemoteBuffer(size, self)
        self.buffers.append(buf)
        return buf


class Dmap:
    """Direct physical memory access via the DMAP mapping."""

    def __init__(self, client):
        self.client = client
        self.base = 0xFFFFFFE000000000

    def read(self, pa, size):
        return self.client.mem_read(self.base | pa, size)

    def read_u8(self, pa):
        return self.client.mem_read_u8(self.base | pa)

    def read_u32(self, pa):
        return self.client.mem_read_u32(self.base | pa)

    def read_u64(self, pa):
        return self.client.mem_read_u64(self.base | pa)

    def write(self, pa, buf):
        self.client.mem_write(self.base | pa, buf)

    def write_u8(self, pa, val):
        self.client.mem_write_u8(self.base | pa, val)

    def write_u32(self, pa, val):
        self.client.mem_write_u32(self.base | pa, val)

    def write_u64(self, pa, val):
        self.client.mem_write_u64(self.base | pa, val)


class TmrAccess:
    """TMR (Trusted Memory Region) read access via kpayload RPC."""

    class Tmr:
        def __init__(self, base, limit, ctl, requestors):
            self.base = base
            self.limit = limit
            self.ctl = ctl
            self.requestors = requestors

        def __repr__(self):
            return (f"Tmr(base={self.base:#010x}, limit={self.limit:#010x}, "
                    f"ctl={self.ctl:#010x}, req={self.requestors:#010x})")

    def __init__(self, client):
        self.client = client
        self.dmap = Dmap(self.client)
        self.ind_index = pci_cfg_addr(0, 0x18, 2, 0x80)
        self.ind_data = self.ind_index + 4

    def read32(self, addr):
        self.dmap.write_u32(self.ind_index, addr)
        return self.dmap.read_u32(self.ind_data)

    def write32(self, addr, val):
        self.dmap.write_u32(self.ind_index, addr)
        self.dmap.write_u32(self.ind_data, val)

    def read(self, index):
        return self.Tmr(*[self.read32(index * 0x10 + i * 4) for i in range(4)])

    def dump_all(self):
        for i in range(22):
            tmr = self.read(i)
            if tmr.ctl != 0 or tmr.base != 0:
                print(f"  TMR {i:2d}: {tmr}")


def iter_procs(c):
    """Iterate over all processes in the kernel process list."""
    proc = c.runtime_info().kernel_base + 0x333DC58  # allproc for 4.03
    while proc != 0:
        pid = c.mem_read_u32(proc + 0xBC)
        title = c.mem_read_str(proc + 0x470, 10)
        name = c.mem_read_str(proc + 0x59C, 0x20)
        if name == 'eboot.bin':
            name = title + '_' + name
        yield pid, proc, name
        proc = c.mem_read_u64(proc + 0)


if __name__ == '__main__':
    import sys

    ip = sys.argv[1] if len(sys.argv) > 1 else PS5_IP
    print(f"Connecting to {ip}:6670...")

    with Client((ip, 6670)) as c:
        if c.ping():
            print("Connected! Kernel RPC server is alive.")
        else:
            print("Ping failed!")
            sys.exit(1)

        info = c.runtime_info()
        print(f"  SDK version: {info.sdk_ver_ppr:#018x}")
        print(f"  Kernel base: {info.kernel_base:#018x}")
        print(f"  Sym address: {info.sym_addr:#018x}")
        print(f"  Sym size:    {info.sym_size:#x}")

        print("\nTMR status:")
        tmr = TmrAccess(c)
        tmr.dump_all()

        print("\nProcesses:")
        for pid, proc, name in iter_procs(c):
            print(f"  PID {pid:5d} {name}")
