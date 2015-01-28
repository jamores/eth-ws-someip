-- File : sd.lua
-- Who  : Jose Amores
-- What : SD-over-SOMEIP dissector, called heuristically from SOMEIP

-- bitwise ops helpers
local band,bor = bit.band,bit.bor
local lshift, rshift = bit.lshift,bit.rshift
local tohex = bit.tohex

-- SD protocol
p_sd = Proto("sd","SD")

local f_flags       = ProtoField.uint8("sd.flags","Flags",base.HEX)
local f_res         = ProtoField.uint24("sd.res","Reserved",base.HEX)
local f_ents_len    = ProtoField.uint32("sd.len_ent","LenghtEntries",base.HEX)
local f_ents        = ProtoField.bytes("sd.ent","EntriesArray")
local f_opts_len    = ProtoField.uint32("sd.len_opt","LenghtOptions",base.HEX)
local f_opts        = ProtoField.bytes("sd.opt","OptionsArray")

p_sd.fields = {f_flags,f_res,f_ents_len,f_ents,f_opts_len,f_opts}

function p_sd.dissector(buf,pinfo,root)
    pinfo.cols.protocol = "SOME-IP/SD"

    -- create subtree
    local subtree = root:add(p_sd,buf(0))

    -- add protocol fields to subtree
    --
    local offset = 0
    
    -- Flags
    subtree:add(f_flags,buf(offset,1))
    offset = offset+1
    -- Reserved
    subtree:add(f_res,buf(offset,4))
    offset = offset+3

    -- Entries length
    local e_len = buf(offset,4):uint()
    subtree:add(f_ents_len,buf(offset,4))
    offset = offset+4
    -- Entries
    --e_tree = subtree:add(f_ents,buf(offset,e_len))
    e_tree = subtree:add("EntriesArray")
    Dissector.get("sd_entries"):call(buf(offset-4):tvb(),pinfo,e_tree)
    offset = offset + e_len

    -- Options length
    local o_len = buf(offset,4):uint()
    subtree:add(f_opts_len,buf(offset,4))
    offset = offset+4
    -- Options
    --o_tree = subtree:add(f_ents,buf(offset,o_len))
    o_tree = subtree:add("OptionsArray")
    Dissector.get("sd_options"):call(buf(offset-4):tvb(),pinfo,o_tree)
    offset = offset + o_len

end
