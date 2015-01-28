-- File : sd_options.lua
-- Who  : Jose Amores
-- What : SD subdissector in charge of parsing Options within at OptionsArray

local p_sd_opts = Proto("sd_options","sd_option")

local f_o_len       = ProtoField.uint16("sd.o.len","Length",base.HEX)
local f_o_type      = ProtoField.uint8("sd.o.type","Type",base.HEX)
local f_o_cfg_str   = ProtoField.string("sd.o.cfg_str","ConfigString") 
local f_o_prio      = ProtoField.uint16("sd.o.prio","Priority") 
local f_o_weight    = ProtoField.uint16("sd.o.weight","Weight") 
local f_o_ipv4      = ProtoField.ipv4("sd.o.ipv4","IPv4") 
local f_o_ipv6      = ProtoField.ipv6("sd.o.ipv6","IPv6") 
local f_o_l4        = ProtoField.uint8("sd.o.l4","L4-Protocol",base.HEX) 
local f_o_port      = ProtoField.uint16("sd.o.port","Port") 

local O_TYPE_CFG        = 0x01
local O_TYPE_LB         = 0x02
local O_TYPE_IP4_EP     = 0x04
local O_TYPE_IP6_EP     = 0x06
local O_TYPE_IP4_MC     = 0x14
local O_TYPE_IP6_MC     = 0x16
local O_TYPE_IP4_SD_EP  = 0x24
local O_TYPE_IP6_SD_EP  = 0x26

local o_types = {
    [O_TYPE_CFG]        = "CONFIGURATION",      -- 0x01
    [O_TYPE_LB]         = "LOAD_BALANCING",     -- 0x02
    [O_TYPE_IP4_EP]     = "IPv4_ENDPOINT",      -- 0x04
    [O_TYPE_IP6_EP]     = "IPv6_ENDPOINT",      -- 0x06
    [O_TYPE_IP4_MC]     = "IPv4_MULTICAST",     -- 0x14
    [O_TYPE_IP6_MC]     = "IPV6_MULTICAST",     -- 0x16
    [O_TYPE_IP4_SD_EP]  = "IPv4_SD_ENDPOINT",   -- 0x24
    [O_TYPE_IP6_SD_EP]  = "IPv6_SD_ENDPOINT"    -- 0x26
}
local o_l4 = {
    [6]     = "TCP", -- 0x06
    [17]    = "UDP"  -- 0x11
}

p_sd_opts.fields = {f_o_len,f_o_type,f_o_cfg_str,f_o_prio,f_o_weight,f_o_ipv4,f_o_ipv6,f_o_l4,f_o_port}

function p_sd_opts.dissector(buf,pinfo,root)
    local offset = 0

    -- length of OptionsArray
    local o_len = buf(offset,4):uint()
    offset = offset + 4

    -- parse options (NOTE : some extra variables to easen understanding)
    local o_len_parsed = 0
    while o_len_parsed < o_len do
        local i_parse = parse_options(root,buf(offset,(o_len-o_len_parsed)))
        o_len_parsed = o_len_parsed + i_parse 
        offset = offset + i_parse
    end
end

function is_type_ipv4(type_u8)
    return((type_u8 == O_TYPE_IP4_EP) or (type_u8 == O_TYPE_IP4_MC) or (type_u8 == O_TYPE_IP4_SD_EP))
end
function is_type_ipv6(type_u8)
    return((type_u8 == O_TYPE_IP6_EP) or (type_u8 == O_TYPE_IP6_MC) or (type_u8 == O_TYPE_IP6_SD_EP))
end

function parse_options(subtree,buf)
    local offset = 0

    local o_subtree = subtree:add(p_sd_opts)

    -- Length
    o_subtree:add(f_o_len,buf(offset,2))
    local len_u16 = buf(offset,2):uint() 
    offset = offset + 2

    -- Type
    local type_tree = o_subtree:add(f_o_type,buf(offset,1))
    local type_u8 = buf(offset,1):uint()
    offset = offset + 1
    if o_types[type_u8] ~= nil then
        type_tree:append_text(" ("..o_types[type_u8]..")")
        
        -- also update "root" with entry type
        o_subtree:append_text(" : "..o_types[type_u8])
    else
        type_tree:append_text(" (type unknown)")
    end

    -- Reserved (skip), decrement len_u16 accordingly
    offset = offset + 1
    len_u16 = len_u16 - 1

    -- switch and parse correct Option
    if (type_u8 == O_TYPE_CFG) then
        -- Config string
        enge = o_subtree:add(f_o_cfg_str,buf(offset,len_u16))
        offset = offset + len_u16
    elseif (type_u8 == O_TYPE_LB) then
        -- Priority 
        o_subtree:add(f_o_prio,buf(offset,2))
        offset = offset + 2
        -- Weight
        o_subtree:add(f_o_weight,buf(offset,2))
        offset = offset + 2
    elseif is_type_ipv4(type_u8) then
        -- IPv4
        o_subtree:add(f_o_ipv4,buf(offset,4))
        offset = offset + 4
    elseif is_type_ipv6(type_u8) then
        -- IPv6
        o_subtree:add(f_o_ipv6,buf(offset,16))
        offset = offset + 16
    end

    -- IPv4, IPv6 common post-fields
    --
    if is_type_ipv4(type_u8) or is_type_ipv6(type_u8) then
        -- Reserved (skip)
        offset = offset + 1

        -- L4-Proto
        local l4_tree = o_subtree:add(f_o_l4,buf(offset,1))
        local l4_u8 = buf(offset,1):uint()
        offset = offset +1
        if o_l4[l4_u8] ~= nil then
            l4_tree:append_text(" ("..o_l4[l4_u8]..")")
        else
            l4_tree:append_text(" (L4-Proto unknown)")
        end

        -- Port
        o_subtree:add(f_o_port,buf(offset,2))
        offset = offset + 2
    end

    return(offset)
end
