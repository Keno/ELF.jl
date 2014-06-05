module ELF
    include("constants.jl")
    using StrPack
    import Base.read

    abstract ELFHeader
    abstract ELFSectionHeader
    abstract ELFSymtabEntry
    abstract ELFRel
    abstract ELFRela
    abstract ELFProgramHeader
    abstract ELFFile

    module ELF32
        import ELF
        using StrPack
        @struct immutable Header <: ELF.ELFHeader
            e_type::Uint16
            e_machine::Uint16
            e_version::Uint32
            e_entry::Uint32
            e_phoff::Uint32
            e_shoff::Uint32
            e_flags::Uint32
            e_ehsize::Uint16
            e_phentsize::Uint16
            e_phnum::Uint16
            e_shentsize::Uint16
            e_shnum::Uint16
            e_shstrndx::Uint16
        end

        @struct immutable SectionHeader <: ELF.ELFSectionHeader
            sh_name::Uint32
            sh_type::Uint32
            sh_flags::Uint32
            sh_addr::Uint32
            sh_offset::Uint32
            sh_size::Uint32
            sh_link::Uint32
            sh_info::Uint32
            sh_addralign::Uint32
            sh_entsize::Uint32
        end

        @struct immutable SymtabEntry <: ELF.ELFSymtabEntry
            st_name::Uint32
            st_value::Uint32
            st_size::Uint32
            st_info::Uint8
            st_other::Uint8
            st_shndx::Uint16
        end

        @struct immutable Rel <: ELF.ELFRel
            r_offset::Uint32
            r_info::Uint32
        end

        @struct immutable Rela <: ELF.ELFRel
            r_offset::Uint32
            r_info::Uint32
            r_addend::Int32
        end

        @struct immutable ProgramHeader <: ELF.ELFProgramHeader
            p_type::Uint32
            p_offset::Uint32
            p_vaddr::Uint32
            p_paddr::Uint32
            p_filesz::Uint32
            p_memsz::Uint32
            p_flags::Uint32
            p_align::Uint32
        end

        type File <: ELF.ELFFile
            endianness::Symbol
            ei_version::Uint8
            ei_osabi::Uint8
            header::Header
            pheaders::Array{ProgramHeader,1}
            sheaders::Array{SectionHeader,1}
        end
    end

    module ELF64
        import ELF
        using StrPack
        @struct immutable Header <: ELF.ELFHeader
            e_type::Uint16
            e_machine::Uint16
            e_version::Uint32
            e_entry::Uint64
            e_phoff::Uint64
            e_shoff::Uint64
            e_flags::Uint32
            e_ehsize::Uint16
            e_phentsize::Uint16
            e_phnum::Uint16
            e_shentsize::Uint16
            e_shnum::Uint16
            e_shstrndx::Uint16
        end

        @struct immutable SectionHeader <: ELF.ELFSectionHeader
            sh_name::Uint32
            sh_type::Uint32
            sh_flags::Uint64
            sh_addr::Uint64
            sh_offset::Uint64
            sh_size::Uint64
            sh_link::Uint32
            sh_info::Uint32
            sh_addralign::Uint64
            sh_entsize::Uint64
        end

        @struct immutable SymtabEntry <: ELF.ELFSymtabEntry
            st_name::Uint32
            st_info::Uint8
            st_other::Uint8
            st_shndx::Uint16
            st_value::Uint32
            st_size::Uint64
        end

        @struct immutable Rel <: ELF.ELFRel
            r_offset::Uint64
            r_info::Uint64
        end

        @struct immutable Rela <: ELF.ELFRel
            r_offset::Uint64
            r_info::Uint64
            r_addend::Int64
        end

        @struct immutable ProgramHeader <: ELF.ELFProgramHeader
            p_type::Uint32
            p_flags::Uint32
            p_offset::Uint64
            p_vaddr::Uint64
            p_paddr::Uint64
            p_filesz::Uint64
            p_memsz::Uint64
            p_align::Uint64
        end

        type File <: ELF.ELFFile
            endianness::Symbol
            ei_version::Uint8
            ei_osabi::Uint8
            header::Header
            pheaders::Array{ProgramHeader,1}
            sheaders::Array{SectionHeader,1}
        end
    end

    function endianness(ei_data::Uint8) 
        if ei_data == ELFDATA2MSB
            :BigEndian
        elseif ei_data == ELFDATA2LSB
            :LittleEndian
        else
            error("Invalid Data Specification")
        end
    end

    function readmeta(io::IO)
        mag0 = read(io,Uint8)
        mag1 = read(io,Uint8)
        mag2 = read(io,Uint8)
        mag3 = read(io,Uint8)
        if((mag0 != '\177') || (mag1 != 'E') || (mag2 != 'L') || (mag3 != 'F'))
            error("Magic Number does not match")
        end
        class = read(io,Uint8)
        data = read(io,Uint8)
        version = read(io,Uint8)
        osabi = read(io,Uint8)
        abiversion = read(io,Uint8)
        skip(io,7)
        if class == ELFCLASS32
            header = unpack(io,ELF32.Header,endianness(data))
            return ELF32.File(endianness(data),version,osabi,header,Array(ELF32.ProgramHeader,header.e_phnum),
                                                                    Array(ELF32.SectionHeader,header.e_shnum))
        elseif class == ELFCLASS64
            header = unpack(io,ELF64.Header,endianness(data))
            return ELF64.File(endianness(data),version,osabi,header,Array(ELF64.ProgramHeader,header.e_phnum),
                                                                    Array(ELF64.SectionHeader,header.e_shnum))
        else 
            error("Invalid File Class")
        end
    end 

    function read(io::IO,::Type{ELFProgramHeader},f::ELFFile)
        s = StrPack.calcsize(eltype(f.pheaders))
        if s > f.header.e_phentsize
            error("Missing data for program header")
        end 
        ret = unpack(io,eltype(f.pheaders),f.endianness)
        skip(io,f.header.e_phentsize-s)
        ret
    end

    function read(io::IO,::Type{ELFSectionHeader},f::ELFFile)
        s = StrPack.calcsize(eltype(f.sheaders))
        if s > f.header.e_shentsize
            error("Missing data for program header")
        end 
        ret = unpack(io,eltype(f.sheaders),f.endianness)
        skip(io,f.header.e_shentsize-s)
        ret
    end

    function readheaders(io::IO)
        file = readmeta(io)
        if file.header.e_phnum>0
            seek(io,file.header.e_phoff)
            for i = 1:file.header.e_phnum
                file.pheaders[i] = read(io,ELFProgramHeader,file);
            end
        end
        if file.header.e_shnum>0
            seek(io,file.header.e_shoff)
            for i = 1:file.header.e_shnum
                file.sheaders[i] = read(io,ELFSectionHeader,file);
            end
        end
        file
    end

    function strtable_lookup(io::IO,strtable::ELFSectionHeader,index)
        seek(io,strtable.sh_offset+index)
        strip(readuntil(io,'\0'),"\0")
    end

    name(io::IO,file::ELFFile,symtab::ELFSymtabEntry) = 
        strtable_lookup(io,file.sheaders[file.header.e_shstrndx+1],symtab.st_name)
    name(io::IO,file::ELFFile,header::ELFSectionHeader) = 
        strtable_lookup(io,file.sheaders[file.header.e_shstrndx+1],header.sh_name)
    names(io,file,headers) = map(x->name(io,file,x),headers)

    function read(io::IO,x::Array{Uint8,1},file::ELFFile,header::ELFProgramHeader)
        seek(io,header.p_offset)
        read(io,x)
    end

    function read(io::IO,x::Array{Uint8,1},file::ELFFile,header::ELFSectionHeader)
        seek(io,header.sh_offset)
        read(io,x)
    end

    function read(io::IO,file::ELFFile,header::ELFSectionHeader)
        x = Array(Uint8,header.sh_size)
        read(io,x,file,header)
        x
    end

    function read(io::IO,file::ELFFile,header::ELFProgramHeader)
        x = Array(Uint8,header.p_filesz)
        read(io,x,file,header)
        x
    end

    # DWARF support
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
        sections = Dict{ASCIIString,ELFSectionHeader}()
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
end