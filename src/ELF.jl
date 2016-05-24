VERSION >= v"0.4.0-dev+6641" && __precompile__()
module ELF
    include("constants.jl")
    using StructIO
    using FileIO
    using ObjFileBase
    import Base: start, next, done, endof, length, getindex
    import Base: read, readuntil, write, readbytes, seek, seekstart, position
    import Base: show, showcompact
    import Base: sizeof
    import ObjFileBase: readmeta, debugsections, deref, sectionoffset, sectionaddress,
        sectionsize, Section, endianness, replace_sections_from_memory, strtab_lookup,
        getSectionLoadAddress, sectionname, load_strtab, handle, symname, isundef,
        symbolvalue
    import StructIO: unpack

    abstract ELFFile

    #
    # Represents the actual ELF file
    #
    immutable ELFHandle{T<:IO} <: ObjectHandle
        io::T
        start::Int
        file::ELFFile
    end
    __init__() = push!(ObjFileBase.ObjHandles, ELFHandle)
    Base.eof(handle::ELFHandle) = eof(handle.io)
    ObjFileBase.handle(handle::ELFHandle) = handle

    abstract ELFHeader
    abstract ELFSectionHeader <: Section{ELFHandle}
    abstract ELFSymtabEntry
    abstract ELFRel
    abstract ELFRela
    abstract ELFProgramHeader

    sheader(::Type{ELFHeader}) = ELFSectionHeader
    pheader(::Type{ELFHeader}) = ELFProgramHeader
    symtype(::Type{ELFSectionHeader}) = ELFSymtabEntry

    module ELF32
        import ELF
        using StructIO

        @struct immutable Header <: ELF.ELFHeader
            e_type::UInt16
            e_machine::UInt16
            e_version::UInt32
            e_entry::UInt32
            e_phoff::UInt32
            e_shoff::UInt32
            e_flags::UInt32
            e_ehsize::UInt16
            e_phentsize::UInt16
            e_phnum::UInt16
            e_shentsize::UInt16
            e_shnum::UInt16
            e_shstrndx::UInt16
        end

        @struct immutable SectionHeader <: ELF.ELFSectionHeader
            sh_name::UInt32
            sh_type::UInt32
            sh_flags::UInt32
            sh_addr::UInt32
            sh_offset::UInt32
            sh_size::UInt32
            sh_link::UInt32
            sh_info::UInt32
            sh_addralign::UInt32
            sh_entsize::UInt32
        end

        @struct immutable SymtabEntry <: ELF.ELFSymtabEntry
            st_name::UInt32
            st_value::UInt32
            st_size::UInt32
            st_info::UInt8
            st_other::UInt8
            st_shndx::UInt16
        end

        @struct immutable Rel <: ELF.ELFRel
            r_offset::UInt32
            r_info::UInt32
        end

        @struct immutable Rela <: ELF.ELFRel
            r_offset::UInt32
            r_info::UInt32
            r_addend::Int32
        end

        @struct immutable ProgramHeader <: ELF.ELFProgramHeader
            p_type::UInt32
            p_offset::UInt32
            p_vaddr::UInt32
            p_paddr::UInt32
            p_filesz::UInt32
            p_memsz::UInt32
            p_flags::UInt32
            p_align::UInt32
        end

        type File <: ELF.ELFFile
            endianness::Symbol
            ei_version::UInt8
            ei_osabi::UInt8
            header::Header
        end
        ELF.sheader(::Type{File}) = SectionHeader
        ELF.pheader(::Type{File}) = ProgramHeader
        ELF.symtype(::Type{SectionHeader}) = SymtabEntry
    end

    module ELF64
        import ELF
        using StructIO

        @struct immutable Header <: ELF.ELFHeader
            e_type::UInt16
            e_machine::UInt16
            e_version::UInt32
            e_entry::UInt64
            e_phoff::UInt64
            e_shoff::UInt64
            e_flags::UInt32
            e_ehsize::UInt16
            e_phentsize::UInt16
            e_phnum::UInt16
            e_shentsize::UInt16
            e_shnum::UInt16
            e_shstrndx::UInt16
        end

        @struct immutable SectionHeader <: ELF.ELFSectionHeader
            sh_name::UInt32
            sh_type::UInt32
            sh_flags::UInt64
            sh_addr::UInt64
            sh_offset::UInt64
            sh_size::UInt64
            sh_link::UInt32
            sh_info::UInt32
            sh_addralign::UInt64
            sh_entsize::UInt64
        end

        @struct immutable SymtabEntry <: ELF.ELFSymtabEntry
            st_name::UInt32
            st_info::UInt8
            st_other::UInt8
            st_shndx::UInt16
            st_value::UInt32
            st_size::UInt64
        end

        @struct immutable Rel <: ELF.ELFRel
            r_offset::UInt64
            r_info::UInt64
        end

        @struct immutable Rela <: ELF.ELFRel
            r_offset::UInt64
            r_info::UInt64
            r_addend::Int64
        end

        @struct immutable ProgramHeader <: ELF.ELFProgramHeader
            p_type::UInt32
            p_flags::UInt32
            p_offset::UInt64
            p_vaddr::UInt64
            p_paddr::UInt64
            p_filesz::UInt64
            p_memsz::UInt64
            p_align::UInt64
        end

        type File <: ELF.ELFFile
            endianness::Symbol
            ei_version::UInt8
            ei_osabi::UInt8
            header::Header
        end
        ELF.sheader(::Type{File}) = SectionHeader
        ELF.pheader(::Type{File}) = ProgramHeader
        ELF.symtype(::Type{SectionHeader}) = SymtabEntry
    end

    sectionsize(sh::ELFSectionHeader) = sh.sh_size
    sectionoffset(sh::ELFSectionHeader) = sh.sh_offset
    sectionaddress(sh::ELFSectionHeader) = sh.sh_addr

    # Definitions for ELF Handle
    ELFHandle{T<:IO}(io::T, file::ELFFile) = ELFHandle{T}(io,position(io),file)
    function show(io::IO,h::ELFHandle)
        print(io,"ELF Handle (")
        if typeof(h.file) == ELF32.File
            print(io,"32-bit")
        elseif typeof(h.file) == ELF64.File
            print(io,"64-bit")
        else
            error("Unrecognized ELF type")
        end
        print(io,")")
    end

    for f in (:readuntil,:write)
        @eval $(f){T<:IO}(io::ELFHandle{T},args...) = $(f)(io.io,args...)
    end
    readbytes{T<:IO}(io::ELFHandle{T},num::Integer) = readbytes(io.io,num)
    seek{T<:IO}(io::ELFHandle{T},pos::Integer) = seek(io.io,io.start+pos)
    seekstart(io::ELFHandle) = seek(io.io,io.start)
    position{T<:IO}(io::ELFHandle{T}) = position(io.io)-io.start
    unpack{T,ioT<:IO}(h::ELFHandle{ioT},::Type{T}) = unpack(h.io,T)
    endianness(h::ELFHandle) = h.file.endianness


    function endianness(ei_data::UInt8)
        if ei_data == ELFDATA2MSB
            :BigEndian
        elseif ei_data == ELFDATA2LSB
            :LittleEndian
        else
            error("Invalid Data Specification")
        end
    end

    function readmeta(io::IO,::Type{ELFHandle})
        start = position(io)
        mag0 = read(io,UInt8)
        mag1 = read(io,UInt8)
        mag2 = read(io,UInt8)
        mag3 = read(io,UInt8)
        if((mag0 != UInt32('\177')) || (mag1 != UInt32('E')) || (mag2 != UInt32('L')) || (mag3 != UInt32('F')))
            throw(ObjFileBase.MagicMismatch("Magic Number does not match"))
        end
        class = read(io,UInt8)
        data = read(io,UInt8)
        version = read(io,UInt8)
        osabi = read(io,UInt8)
        abiversion = read(io,UInt8)
        skip(io,7)
        if class == ELFCLASS32
            header = unpack(io,ELF32.Header,endianness(data))
            file = ELF32.File(endianness(data),version,osabi,header)
        elseif class == ELFCLASS64
            header = unpack(io,ELF64.Header,endianness(data))
            file = ELF64.File(endianness(data),version,osabi,header)
        else
            error("Invalid File Class")
        end
        seek(io,start)
        ELFHandle(io,file)
    end
    FileIO.load(s::Stream{format"ELF"}) = readmeta(stream(s))
    function FileIO.save(f::File{format"ELF"},oh::ELFHandle)
        # First we need to calculate the total size of the object file. To this,
        # iterate through all sections and fine which one (if placed last)
        # yields the largest object file
        header = oh.file.header
        size = max(
            maximum(map(sec->(sectionoffset(sec)+sectionsize(sec)),Sections(oh))),
            (header.e_shoff+header.e_shentsize*header.e_shnum))
        open(f,"w") do s
            seekstart(oh)
            write(s,readbytes(oh,size))
        end
    end
    FileIO.save(s::AbstractString,oh::ELFHandle) =
        save(File{format"ELF"}(s),oh)


    function read(io::IO,::Type{ELFProgramHeader},f::ELFFile)
        s = sizeof(pheader(typeof(f)))
        if s > f.header.e_phentsize
            error("Missing data for program header")
        end
        ret = unpack(io,pheader(typeof(f)),f.endianness)
        skip(io,f.header.e_phentsize-s)
        ret
    end

    function read(io::IO,::Type{ELFSectionHeader},f::ELFFile)
        s = sizeof(sheader(typeof(f)))
        if s > f.header.e_shentsize
            error("Missing data for section header")
        end
        ret = unpack(io,sheader(typeof(f)),f.endianness)
        skip(io,f.header.e_shentsize-s)
        ret
    end

    function strtab_lookup(io,strtable::ELFSectionHeader,index)
        seek(io,strtable.sh_offset+index)
        strip(readuntil(io,'\0'),'\0')
    end

    function read(io::IO,x::Array{UInt8,1},file::ELFFile,header::ELFProgramHeader)
        seek(io,header.p_offset)
        read(io,x)
    end

    function read(io::IO,x::Array{UInt8,1},file::ELFFile,header::ELFSectionHeader)
        seek(io,header.sh_offset)
        read(io,x)
    end

    function read(io::IO,file::ELFFile,header::ELFSectionHeader)
        x = Array(UInt8,header.sh_size)
        read(io,x,file,header)
        x
    end

    function read(io::IO,file::ELFFile,header::ELFProgramHeader)
        x = Array(UInt8,header.p_filesz)
        read(io,x,file,header)
        x
    end

    # Program Header iteration
    immutable ProgramHeaders
        handle::ELFHandle
    end
    handle(phs::ProgramHeaders) = phs.handle
    endof(phs::ProgramHeaders) = handle(phs).file.header.e_phnum
    length(phs::ProgramHeaders) = endof(phs)
    start(phs::ProgramHeaders) = 1
    done(phs::ProgramHeaders,n) = n > length(phs)
    next(phs::ProgramHeaders,n) = (phs[n],n+1)
    function getindex(phs::ProgramHeaders, n)
        @assert 0 < n <= length(phs)
        file = handle(phs).file
        seek(handle(phs),file.header.e_phoff + (n-1)*file.header.e_phentsize)
        read(handle(phs),ELFProgramHeader,file)
    end

    function show(io::IO, header::ELFProgramHeader; strtab = nothing, sections = nothing)
        printentry(io,"Type",P_TYPE[header.p_type])
        printentry(io,"Offset","0x",hex(header.p_offset))
        printentry(io,"Virtual Address","0x",hex(header.p_vaddr))
        printentry(io,"Physical Address","0x",hex(header.p_paddr))
        printentry(io,"Size in File","0x",hex(header.p_filesz))
        printentry(io,"Size in Memory","0x",hex(header.p_memsz))
        printentry(io,"Flags","0x",hex(header.p_flags))
        printentry(io,"Align","0x",hex(header.p_align))
    end

    # Access to sections
    function sectionname(header::ELFSectionHeader; strtab = nothing, errstrtab = true)
        if strtab == nothing
            errstrtab && error("No Strtab given")
            return string("strtab@",header.sh_name)
        end
        return strtab_lookup(strtab,header.sh_name)
    end

    sizeof(header::ELFSectionHeader) = header.sh_size

    function secttype(sh_type::UInt32)
        if haskey(SHT_TYPES, sh_type)
            return SHT_TYPES[sh_type]
        end
        return string("Unknown (0x",hex(sh_type),")")
    end

    function show(io::IO, header::ELFSectionHeader; strtab = nothing, sections = nothing)
        printentry(io,"Name",sectionname(header;strtab=strtab,errstrtab=false))
        printentry(io,"Type",secttype(header.sh_type))
        printentry(io,"Size","0x",hex(header.sh_size))
        printentry(io,"Offset","0x",hex(header.sh_offset))
        printentry(io,"Load Address","0x",hex(header.sh_addr))
        if header.sh_link != 0
            target = ""
            if strtab !== nothing && sections !== nothing
                target = string(" -> ",sectionname(sections[header.sh_link+1].header; strtab = strtab))
            end
            printentry(io,"Link Section",header.sh_link,target)
        end
        if header.sh_info != 0
            if header.sh_type == SHT_REL || header.sh_type == SHT_RELA
                target = ""
                if strtab !== nothing && sections !== nothing
                    target = string(" -> ",sectionname(sections[header.sh_info+1].header; strtab = strtab))
                end
                printentry(io,"Info Section",header.sh_info,target)
            elseif header.sh_type == SHT_SYMTAB || header.sh_type == SHT_DYNSYM
                printentry(io,"Last Local Idx",header.sh_info)
            end
        end
        flags = String[]
        for (k,v) in SHF_FLAGS
            ((k&header.sh_flags) != 0) && push!(flags, v)
        end
        !isempty(flags) && printentry(io,"Flags",join(flags,","))
        printentry(io,"Align","0x",hex(header.sh_addralign))
        if header.sh_entsize != 0
            printentry(io,"Entry Size","0x",hex(header.sh_entsize))
        end
    end

    function filetype(e_type)
        if haskey(ET_TYPES, e_type)
            return ET_TYPES[e_type]
        end
        return string("Unknown (0x",hex(e_type),")")
    end
    function machinetype(e_machine)
        if haskey(EM_MACHINES, e_machine)
            return EM_MACHINES[e_machine]
        end
        return string("Unknown (0x",hex(e_machine),")")
    end
    function show(io::IO, header::ELFHeader)
        printentry(io,"Type",filetype(header.e_type))
        printentry(io,"Machine",machinetype(header.e_machine))
        # Skip e_version (not particularly useful)
        printentry(io,"Entrypoint","0x",hex(header.e_entry))
        printentry(io,"PH Offset","0x",hex(header.e_phoff))
        printentry(io,"SH Offset","0x",hex(header.e_shoff))
        # Skip flags
        printentry(io,"Header Size","0x",hex(header.e_ehsize))
        printentry(io,"PH Entry Size","0x",hex(header.e_phentsize))
        printentry(io,"PH Entry Count",dec(header.e_phnum))
        printentry(io,"SH Entry Size","0x",hex(header.e_shentsize))
        printentry(io,"SH Entry Count",dec(header.e_shnum))
        printentry(io,"Strtab Index",dec(header.e_shstrndx))
    end

    ObjFileBase.isrelocatable(handle::ELFHandle) =
        handle.file.header.e_type == ELF.ET_REL

    ObjFileBase.isexecutable(handle::ELFHandle) =
        handle.file.header.e_type == ELF.ET_EXEC

    immutable SectionRef{T<:ELFHandle, hdr} <: ObjFileBase.SectionRef{ELFHandle}
        handle::T
        header::hdr
    end
    @Base.pure ObjFileBase.SectionRef{T<:ELFHandle}(::Type{T}) = SectionRef{T}
    handle(sec::SectionRef) = sec.handle
    sectionname(sec::SectionRef; strtab=load_strtab(sec.handle), errstrtab = true) = sectionname(sec.header; strtab = strtab, errstrtab = true)
    show(io::IO, sr::SectionRef; strtab = load_strtab(sr.handle), sections = nothing) = show(io,sr.header; strtab = strtab, sections = sections)
    sizeof(s::SectionRef) = sizeof(s.header)
    deref(s::SectionRef) = s.header
    seek(s::SectionRef, offs) = seek(s.handle, sectionoffset(s) + offs)
    Base.seekstart(s::SectionRef) = seek(handle(s), sectionoffset(s))
    Base.read(s::SectionRef) = (seek(s,0); read(s.handle.io, sectionsize(s)))

    immutable StrTab{T<:SectionRef} <: ObjFileBase.StrTab
        strtab::T
    end
    call(::Type{ObjFileBase.StrTab},strtab::SectionRef) = StrTab(strtab)
    strtab_lookup(s::StrTab,index) = strtab_lookup(s.strtab.handle,s.strtab.header,index)

    immutable Sections{T<:ELFHandle} <: ObjFileBase.Sections{ELFHandle}
        handle::T
    end
    ObjFileBase.handle(sections::Sections) = sections.handle
    ObjFileBase.Sections(handle::ELFHandle) = Sections(handle)
    ObjFileBase.mangle_sname(h::ELFHandle, name) = string(".", name)
    endof(s::Sections) = s.handle.file.header.e_shnum
    length(s::Sections) = endof(s)
    function getindex{T}(s::Sections{T}, n)
        @assert 0 < n <= length(s)
        file = s.handle.file
        seek(s.handle,file.header.e_shoff + (n-1)*file.header.e_shentsize)
        SectionRef(s.handle, read(s.handle,ELFSectionHeader,file))
    end

    load_strtab(h::ELFHandle) = StrTab(Sections(h)[h.file.header.e_shstrndx+1])
    load_strtab{T}(s::Sections{T}) = StrTab(s[s.handle.file.header.e_shstrndx+1])
    load_strtab{T}(s::SectionRef{T}) = StrTab(s)
    const strtab = load_strtab

    start(s::Sections) = 1
    done(s::Sections,n) = n > length(s)
    next(s::Sections,n) = (s[n],n+1)

    function show(io::IO,s::Sections)
        println(io,"ELF Section Table")
        for section in s
            show(io,section; strtab=strtab(s), sections = s)
            println(io)
        end
    end

    link_sec(sec::SectionRef) = Sections(sec.handle)[sec.header.sh_link+1]
    info_sec(sec::SectionRef) = Sections(sec.handle)[sec.header.sh_info+1]

    # # Symbols
    immutable Symbols{T<: SectionRef}
        symtab::T
    end
    handle(s::Symbols) = handle(s.symtab)
    Symbols(h::ELFHandle) =
        Symbols(first(filter(x->sectionname(x) in (".dynsym",".symtab"),Sections(h))))
    ObjFileBase.StrTab(symtab::Symbols) = StrTab(symtab)
    StrTab(symtab::Symbols) = StrTab(link_sec(symtab.symtab))

    immutable SymbolRef <: ObjFileBase.SymbolRef{ELFHandle}
        syms::Symbols
        num::UInt16
        offset::Int
        entry::ELFSymtabEntry
    end
    handle(sym::SymbolRef) = handle(sym.syms)
    symname(sym::SymbolRef; strtab = StrTab(sym.syms), kwargs...) = symname(sym.entry; strtab=strtab, kwargs...)
    deref(ref::SymbolRef) = ref.entry
    symbolnum(ref::SymbolRef) = ref.num

    function symname(sym::ELFSymtabEntry; strtab = nothing, errstrtab = true)
        if strtab == nothing
            errstrtab && error("No Strtab given")
            return string("strtab@",sym.st_name)
        end
        return strtab_lookup(strtab,sym.st_name)
    end

    st_bind(st_info) = st_info>>4
    st_type(st_info) = st_info & 0xf
    st_type(x::ELFSymtabEntry) = st_type(x.st_info)
    isglobal(x) = (st_bind(x.st_info) & STB_GLOBAL) != 0
    islocal(x) = !isglobal(x)
    isweak(x) = (st_bind(x.st_info) & STB_WEAK) != 0
    isdebug(x) = false
    isundef(x::ELFSymtabEntry) = x.st_shndx == SHN_UNDEF
    isundef(x::SymbolRef) = isundef(deref(x))

    function symbolvalue(sym::Union{SymbolRef, ELFSymtabEntry}, sections)
        value = deref(sym).st_value
        shndx = deref(sym).st_shndx
        if shndx != ELF.SHN_UNDEF && shndx < ELF.SHN_LORESERVE
            sec = sections[shndx+1]
            # What to do here depends on the object kind. Shared Libraries and
            # executable's st_value's are virtual addresses
            if deref(sec).sh_addr != 0 && handle(sec).file.header.e_type == ET_REL
                value += deref(sec).sh_addr
            end
            if handle(sec).file.header.e_type == ET_EXEC ||
                 handle(sec).file.header.e_type == ET_DYN
                for ph in ProgramHeaders(handle(sec))
                    ph.p_type != PT_LOAD && continue
                    value -= ph.p_vaddr
                    break
                end
            end
        end
        value
    end

    # Symbol printing stuff
    function showcompact(io::IO, x::SymbolRef; shstrtab = load_strtab(handle(x)), strtab = StrTab(x.syms), sections = Sections(handle(x)))
        print(io,'[')
        printfield(io,dec(symbolnum(x)),5)
        print(io,"] ")
        showcompact(io, x.entry; shstrtab = shstrtab, strtab = strtab, sections = sections)
    end
    show(io::IO, x::SymbolRef) = showcompact(io, x)

    # Try to follow the same format as llvm-objdump
    function showcompact(io::IO,x::ELFSymtabEntry; shstrtab = nothing, strtab = nothing, sections = nothing)
        # Value
        print(io,string("0x",hex(x.st_value,2*sizeof(x.st_value))))
        print(io," ")

        # Size
        print(io,string("0x",hex(x.st_size,2*sizeof(x.st_size))))
        print(io," ")

        # Symbol flags
        print(io, isglobal(x) ? "g" : islocal(x) ? "l" : "-")
        print(io, isweak(x) ? "w" : "-")
        print(io, "-"^3) # Unsupported
        print(io, isdebug(x) ? "d" : "-")
        STT = st_type(x)
        # Symbol type
        print(io, STT == STT_FILE ? "F" : STT == STT_FUNC ? "f" : STT == STT_OBJECT ? "O" : "-")

        print(io, " ")
        if x.st_shndx == SHN_UNDEF
            printfield(io,"*UND*",20; align = :left)
        elseif x.st_shndx == SHN_COMMON
            printfield(io,"*COM*",20; align = :left)
        elseif x.st_shndx == SHN_ABS
            printfield(io,"*ABS*",20; align = :left)
        elseif sections !== nothing
            printfield(io, sectionname(sections[x.st_shndx+1];
                strtab = shstrtab, errstrtab=true), 20; align = :left)
        else
            printfield(io, "Section #$(x.st_shndx)", 20; align = :left)
        end
        print(io, " ")

        print(io,symname(x; strtab = strtab, errstrtab = false))
    end

    function show(io::IO, s::Symbols)
        h = s.symtab.handle
        shstrtab = strtab(h)
        symstrtab = strtab(Sections(h)[s.symtab.header.sh_link+1])
        for sym in s
            showcompact(io, sym; shstrtab = shstrtab, strtab = symstrtab)
            println(io)
        end
    end

    SymtabEntrySize(s::Symbols) = sizeof(symtype(typeof(s.symtab.header)))
    endof(s::Symbols) = div(s.symtab.header.sh_size,SymtabEntrySize(s))
    function getindex(s::Symbols,n)
        if n < 1 || n > endof(s)
            throw(BoundsError())
        end
        h = s.symtab.handle
        offset = s.symtab.header.sh_offset + (n-1)*SymtabEntrySize(s)
        seek(h,offset)
        SymbolRef(s,n,offset,unpack(h, symtype(typeof(s.symtab.header))))
    end

    start(s::Symbols) = 1
    done(s::Symbols,n) = n > endof(s)
    next(s::Symbols,n) = (x=s[n];(x,n+1))
    length(s::Symbols) = endof(s)

    # Access to relocations
    immutable Relocations{T <: ELFRel, S <: SectionRef}
        sec::S
    end
    function Relocations(sec::SectionRef)
        is64 = isa(sec.handle.file,ELF64.File)
        isRela = sec.header.sh_type == SHT_RELA
        Relocations{is64 ? (isRela ? ELF64.Rela : ELF64.Rel) : (isRela ? ELF32.Rela : ELF32.Rel),typeof(sec)}(sec)
    end

    immutable RelocationRef{T <: ELFRel} <: ObjFileBase.RelocationRef{ELFHandle}
        h::ELFHandle
        reloc::T
    end

    deref(x::RelocationRef) = x.reloc

    entrysize{T}(s::Relocations{T}) = sizeof(T)
    endof{T}(s::Relocations{T}) = div(s.sec.header.sh_size,entrysize(s))
    length(r::Relocations) = endof(r)
    function getindex{T}(s::Relocations{T},n)
        if n < 1 || n > length(s)
            throw(BoundsError())
        end
        offset = sectionoffset(s.sec) + (n-1)*entrysize(s)
        seek(s.sec.handle,offset)
        RelocationRef{T}(s.sec.handle,unpack(s.sec.handle, T))
    end


    start(s::Relocations) = 1
    done(s::Relocations,n) = n > length(s)
    next(s::Relocations,n) = (x=s[n];(x,n+1))


    # DWARF support
    #=
    function read(io::IO,file::ELFFile,h::ELFSectionHeader,::Type{DWARF.ARTable})
        seek(io,h.sh_offset)
        ret = DWARF.ARTable(Array(DWARF.ARTableSet,0))
        while position(io) < h.sh_offset + h.sh_size
            push!(ret.sets,read(io,DWARF.ARTableSet,f.endianness))
        end
        ret
    end

    function read(io::IO,file::ELFFile,h::ELFSectionHeader,::Type{DWARF.PUBTable})
        seek(io,h.sh_offset)
        ret = DWARF.PUBTable(Array(DWARF.PUBTableSet,0))
        while position(io) < h.sh_offset + h.sh_size
            push!(ret.sets,read(io,DWARF.PUBTableSet,f.endianness))
        end
        ret
    end

    function read(io::IO,f::ELFFile,h::ELFSectionHeader,::Type{DWARF.AbbrevTableSet})
        seek(io,h.sh_offset)
        read(io,AbbrevTableSet,f.endianness)
    end

    function read(io::IO,f::ELFFile,h::ELFSectionHeader,s::DWARF.PUBTableSet,::Type{DWARF.DWARFCUHeader})
        seek(io,h.sh_offset+s.header.debug_info_offset)
        read(io,DWARF.DWARFCUHeader,f.endianness)
    end

    function read(io::IO,f::ELFFile,debug_info::ELFSectionHeader,debug_abbrev::ELFSectionHeader,
        s::DWARF.PUBTableSet,e::DWARF.PUBTableEntry,header::DWARF.DWARFCUHeader,::Type{DWARF.DIE})
        ats = read(io,f,debug_abbrev,header,DWARF.AbbrevTableSet)
        seek(io,debug_info.sh_offset+s.header.debug_info_offset+e.offset)
        read(io,header,ats,DWARF.DIE)
    end

    function read(io::IO,f::ELFFile,h::ELFSectionHeader,s::DWARF.DWARFCUHeader,::Type{DWARF.AbbrevTableSet})
        seek(io,h.sh_offset+s.debug_abbrev_offset)
        read(io,AbbrevTableSet,f.endianness)
    end

    function debugsections(io::IO,f::ELFFile)
        snames = names(io,f,f.sheaders)
        sections = Dict{String,ELFSectionHeader}()
        for i in 1:length(snames)
            # Remove leading "."
            ind = findfirst(DEBUG_SECTIONS,snames[i][2:end])
            if ind != 0
                sections[DEBUG_SECTIONS[ind]] = f.sheaders[ind]
            end
        end
        sections
    end

    function read(io::IO,f::ELFFile,debug_info::ELFSectionHeader,debug_abbrev::ELFSectionHeader,
        s::DWARF.PUBTableSet,e::DWARF.PUBTableEntry,header::DWARF.DWARFCUHeader,::Type{DWARF.DIETree})
        ats = read(io,f,debug_abbrev,header,DWARF.AbbrevTableSet)
        seek(io,debug_info.sh_offset+s.header.debug_info_offset+e.offset)
        ret = DIETree(Array(DWARF.DIETreeNode,0))
        read(io,header,ats,ret,DWARF.DIETreeNode,f.endianness)
        ret
    end
    =#

    immutable dl_phdr_info
        dlpi_addr::UInt64
        dlpi_name::Ptr{UInt8}
        dlpi_phdr::Ptr{Void}
        dlpi_phnum::UInt16
    end

    function callback(info::Ptr{dl_phdr_info},size::Csize_t, data::Ptr{Void})
        push!(unsafe_pointer_to_objref(data),unsafe_load(info))
        convert(Cint,0)
    end

    function loaded_libraries()
        x = Array(dl_phdr_info,0)
        ccall(:dl_iterate_phdr, Cint, (Ptr{Void}, Any), cfunction(callback, Cint, (Ptr{dl_phdr_info},Csize_t,Ptr{Void})), x)
        x
    end

    ## DWARF Support
    function debugsections(h::ELFHandle)
        sects = collect(Sections(h))
        strt = strtab(h)
        snames = map(s->sectionname(s.header;strtab=strt),sects)
        sections = Dict{String,SectionRef}()
        for i in 1:length(snames)
            # remove leading "."
            ind = findfirst(ObjFileBase.DEBUG_SECTIONS,bytestring(snames[i])[2:end])
            if ind != 0
                sections[ObjFileBase.DEBUG_SECTIONS[ind]] = sects[i]
            end
        end
        ObjFileBase.DebugSections(h,sections)
    end

    # JIT Utils
    function replace_sections_from_memory(h::ELFHandle, new_buffer)
        for sec in Sections(h)
            if ObjFileBase.is_jit_section(sec)
                seek(new_buffer,sectionoffset(sec))
                write(new_buffer,pointer_to_array(
                    reinterpret(Ptr{UInt8},sectionaddress(sec)),
                    sectionsize(sec),false))
            end
        end
        seekstart(new_buffer)
        new_buffer
    end

    # Other things
    include("relocate.jl")
end
