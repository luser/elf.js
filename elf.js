var ELF = (function() {
    // Constructor, accepts an ArrayBuffer
    function ELF(buffer) {
        Object.defineProperties(this, {
            buffer: {
                value: buffer,
                enumerable: false, writable: false, configurable: false
            }
        });
        parseHeaders(this);
    }

    ELF.prototype = {
        getMemoryAtAddress: function(addr) {
            if (!(addr instanceof Uint64))
                addr = new Uint64(addr);
            for (var i = 0; i < this.memoryRegions.length; i++) {
                if (this.memoryRegions[i].startAddress.lte(addr) &&
                    this.memoryRegions[i].endAddress.gt(addr))
                    return this.memoryRegions[i];
            }
            return null;
        }
    };

    const consts = {
        // Length of e_ident in bytes
        EI_NIDENT:     16,
        // Byte offsets of entries in e_ident
        EI_MAG0:       0,
        EI_MAG1:       1,
        EI_MAG2:       2,
        EI_MAG3:       3,
        EI_CLASS:      4,  // File class (32 or 64 bits)
        EI_DATA:       5,  // Endianness
        EI_VERSION:    6,  // File version
        EI_OSABI:      7,  // OS/ABI identification
        EI_ABIVERSION: 8,
        EI_PAD:        9,  // Padding bytes
        // EI_MAG
        ELFMAG0: 0x7f,
        ELFMAG1: 'E'.charCodeAt(0),
        ELFMAG2: 'L'.charCodeAt(0),
        ELFMAG3: 'F'.charCodeAt(0),
        // EI_CLASS
        ELFCLASS32:    1,  // 32-bit
        ELFCLASS64:    2,  // 64-bit
        // EI_DATA
        ELFDATA2LSB:   1,
        ELFDATA2MSB:   2,
        // e_type
        ET_REL:        1,
        ET_EXEC:       2,
        ET_DYN:        3,
        ET_CORE:       4,
        // e_machine (lots of values elided)
        EM_386:        3,
        EM_PPC:        20,
        EM_X86_64:     62,
        EM_ARM:        40,
        // e_version
        EV_CURRENT:    1,
        // section types
        SHT_NULL:      0,
        SHT_PROGBITS:  1,
        SHT_SYMTAB:    2,
        SHT_STRTAB:    3,
        SHT_RELA:      4,
        SHT_HASH:      5,
        SHT_DYNAMIC:   6,
        SHT_NOTE:      7,
        SHT_NOBITS:    8,
        SHT_REL:       9,
        SHT_SHLIB:     10,
        SHT_DYNSYM:    11,
        SHT_UNKNOWN12: 12,
        SHT_UNKNOWN13: 13,
        SHT_INIT_ARRAY: 14,
        SHT_FINI_ARRAY: 15,
        SHT_PREINIT_ARRAY: 16,
        SHT_GROUP: 17,
        SHT_SYMTAB_SHNDX: 18,
        // program types
        PT_NULL: 0,
        PT_LOAD: 1
    };
    Object.defineProperty(ELF, "consts", {
        value: consts,
        enumerable: true, writable: false, configurable: false
    });

    function ElfMachineToStr(em) {
        switch (em) {
        case ELF.consts.EM_386:
            return "x86";
        case ELF.consts.EM_PPC:
            return "ppc";
        case ELF.consts.EM_X86_64:
            return "x86_64";
        case ELF.consts.EM_ARM:
            return "arm";
        }
        return "unknown";
    }

    function SHTypeToStr(t) {
        var types = [
            "null",
            "progbits",
            "symtab",
            "strtab",
            "rela",
            "hash",
            "dynamic",
            "note",
            "nobits",
            "rel",
            "shlib",
            "dynsym",
            "unknown12",
            "unknown13",
            "init array",
            "fini array",
            "preinit array",
            "group",
            "symtab shndx"
        ];
        if (t < types.length && t >= 0)
            return types[t];
        return "unknown";
    }

    // Read an address value of size |addrsize| bytes from |buffer|.
    function readAddr(buffer, addrsize, little_endian) {
        var bytes = [];
        for (var i=0; i<addrsize; i++)
            bytes.push(buffer.readUnsignedByte());
        return Uint64.fromBytes(bytes);
    }

    // Read a null terminated C string from a Uint8Array
    function readCString(array, offset) {
        if (offset >= array.byteLength || offset < 0)
            return "";
        var chars = [];
        while (offset < array.byteLength && array[offset] != 0) {
            chars.push(array[offset]);
            offset++;
        }
        return String.fromCharCode.apply(String, chars);
    }

    // Seek BufferView |bv| to |offset|, which is a Uint64 value.
    function seek(bv, offset) {
        bv.index = offset.lo;
        if (offset.hi >= 0) {
            var hi = offset.hi;
            var max = Math.pow(2,32);
            while (hi > 0) {
                bv.index += max;
                hi--;
            }
        }
    }

    function MemoryRegion(buffer, addr, size) {
        Object.defineProperties(this, {
            bytes: {
                value: buffer,
                enumerable: true, writable: false, configurable: false
            },
            startAddress: {
                value: addr,
                enumerable: true, writable: false, configurable: false
            },
            endAddress: {
                get: function() {
                    return this.startAddress.plus(this.size);
                },
                enumerable: true, configurable: false
            },
            size: {
                value: size,
                enumerable: true, writable: false, configurable: false
            }
        });
    }

    // Read the ELF header as well as the section and program headers.
    function parseHeaders(elf) {
        var e_ident = new Uint8Array(elf.buffer, 0, ELF.consts.EI_NIDENT);
        if (e_ident[ELF.consts.EI_MAG0] != ELF.consts.ELFMAG0 ||
            e_ident[ELF.consts.EI_MAG1] != ELF.consts.ELFMAG1 ||
            e_ident[ELF.consts.EI_MAG2] != ELF.consts.ELFMAG2 ||
            e_ident[ELF.consts.EI_MAG3] != ELF.consts.ELFMAG3)
            throw "Not an ELF file, bad magic number!";
        var addrsize;
        if (e_ident[ELF.consts.EI_CLASS] == ELF.consts.ELFCLASS32)
            addrsize = 4;
        else if (e_ident[ELF.consts.EI_CLASS] == ELF.consts.ELFCLASS64)
            addrsize = 8;
        else
            throw "Invalid ELF class!";

        var little_endian;
        if (e_ident[ELF.consts.EI_DATA] == ELF.consts.ELFDATA2LSB)
            little_endian = true;
        else if (e_ident[ELF.consts.EI_DATA] == ELF.consts.ELFDATA2MSB)
            little_endian = false;
        else
            throw "Invalid byte order!";

        var bv = new BufferView(elf.buffer, 0, elf.buffer.byteLength, little_endian ? BufferView.LE : BufferView.BE);
        bv.skip(ELF.consts.EI_NIDENT);
        var type = "unknown";
        switch (bv.readShort()) {
        case ELF.consts.ET_REL:
            type = "relocatable object";
            break;
        case ELF.consts.ET_EXEC:
            type = "executable";
            break;
        case ELF.consts.ET_DYN:
            type = "shared library";
            break;
        case ELF.consts.ET_CORE:
            type = "core";
            break;
        default:
            throw "Unknown file type!";
            break;
        }
        Object.defineProperty(elf, "type", {
            value: type,
            enumerable: true, writable: false, configurable: false
        });
        Object.defineProperty(elf, "machine", {
            value: ElfMachineToStr(bv.readShort()),
            enumerable: true, writable: false, configurable: false
        });
        if (bv.readInt() != ELF.consts.EV_CURRENT)
            throw "Unknown ELF format version!";
        Object.defineProperty(elf, "entry", {
            value: readAddr(bv, addrsize),
            enumerable: true, writable: false, configurable: false
        });
        var phoff = readAddr(bv, addrsize);
        var shoff = readAddr(bv, addrsize);
        // skip past e_flags
        bv.readInt();
        // e_ehsize
        var ehsize = bv.readUnsignedShort();
        // e_phentsize
        var phentsize = bv.readUnsignedShort();
        // e_phnum
        var phnum = bv.readUnsignedShort();
        // e_shentsize
        var shentsize = bv.readUnsignedShort();
        // e_shnum
        var shnum = bv.readUnsignedShort();
        // e_shstrndx
        var shstrndx = bv.readUnsignedShort();
        //TODO: sanity-check shentsize/phentsize
        Object.defineProperties(elf, {
            sections: {
                value: [],
                enumerable: true, writable: false, configurable: false
            },
            programs: {
                value: [],
                enumerable: true, writable: false, configurable: false
            },
            memoryRegions: {
                value: [],
                enumerable: true, writable: false, configurable: false
            }
        });
        // Read section headers
        // seek to shoff
        seek(bv, shoff);
        for (var i=0; i<shnum; i++) {
            // read section header
            var sh = {};
            sh.nameindex = bv.readUnsignedInt();
            sh.type = bv.readUnsignedInt();
            sh.typestr = SHTypeToStr(sh.type);
            sh.flags = readAddr(bv, addrsize);
            sh.addr = readAddr(bv, addrsize);
            sh.offset = readAddr(bv, addrsize);
            sh.size = readAddr(bv, addrsize);
            sh.link = bv.readUnsignedInt();
            sh.info = bv.readUnsignedInt();
            sh.addralign = readAddr(bv, addrsize);
            sh.entsize = readAddr(bv, addrsize);
            elf.sections.push(sh);
        }
        // Should have the section header string table now.
        if (shstrndx >= elf.sections.length)
            throw "Couldn't find section header string table!";
        //XXX: handle 64-bit offsets here
        var strtable = new Uint8Array(buffer, elf.sections[shstrndx].offset.lo,
                                      elf.sections[shstrndx].size.lo);
        for (var i=0; i<elf.sections.length; i++) {
            elf.sections[i].name = readCString(strtable, elf.sections[i].nameindex);
            delete elf.sections[i].nameindex;
        }
        // Read program headers
        seek(bv, phoff);
        for (var i=0; i<phnum; i++) {
            var ph = {};
            ph.type = bv.readUnsignedInt();
            if (addrsize == 8) {
                ph.flags = bv.readUnsignedInt();
            }
            ph.offset = readAddr(bv, addrsize);
            ph.vaddr = readAddr(bv, addrsize);
            ph.paddr = readAddr(bv, addrsize);
            ph.filesize = readAddr(bv, addrsize);
            ph.memsize = readAddr(bv, addrsize);
            if (addrsize == 4) {
                ph.flags = bv.readUnsignedInt();
            }
            ph.align = readAddr(bv, addrsize);
            elf.programs.push(ph);

            if (ph.type == ELF.consts.PT_LOAD) {
                //XXX: properly handle 64-bit offsets
                var mr = new MemoryRegion(new Uint8Array(elf.buffer,
                                                         ph.offset.lo,
                                                         ph.filesize.lo),
                                          ph.vaddr,
                                          ph.filesize);

                elf.memoryRegions.push(mr);
                if (ph.filesize.ne(ph.memsize)) {
                    // probably something like bss, just tack on an extra
                    // empty memory region
                    elf.memoryRegions.push(
                        new MemoryRegion(
                            new Uint8Array(ph.memsize.minus(ph.filesize).lo),
                            ph.vaddr.plus(ph.filesize),
                            ph.memsize.minus(ph.filesize)));
                }
            }
        }
        return elf;
    }

    return ELF;
})();