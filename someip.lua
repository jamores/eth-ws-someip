-- File : someip.lua
-- Who  : Jose Amores
-- What : SOMEIP dissector

-- bitwise ops helpers
local band,bor = bit.band,bit.bor
local lshift, rshift = bit.lshift,bit.rshift
local tohex = bit.tohex

-- SOME/IP protocol
local SOMEIP_HDR_LENGTH = 16

p_someip = Proto("someip","Scalable service-Oriented MiddlewarE over IP")

local f_msg_id      = ProtoField.uint32("someip.messageid","MessageID",base.HEX)
local f_len         = ProtoField.uint32("someip.length","Length",base.HEX)
local f_req_id      = ProtoField.uint32("someip.requestid","RequestID",base.HEX)
local f_pv          = ProtoField.uint8("someip.protoversion","ProtocolVersion",base.HEX)
local f_iv          = ProtoField.uint8("someip.ifaceversion","InterfaceVersion",base.HEX)
local f_mt          = ProtoField.uint8("someip.msgtype","MessageType",base.HEX)
local f_rc          = ProtoField.uint8("someip.returncode","ReturnCode",base.HEX)

-- SOME/IP-TP
local f_offset      = ProtoField.uint32("someip.tp_offset","Offset",base.DEC,nil,0xfffffff0)
local f_reserved    = ProtoField.uint8("someip.tp_reserved","Reserved",base.HEX,nil,0x0e)
local f_more_seg    = ProtoField.uint8("someip.tp_more_segments","More Segments",base.DEC,nil,0x01)



local msg_types = {
    [0]     = "REQUEST",                -- 0x00
    [1]     = "REQUEST NO RETURN",      -- 0x01
    [2]     = "NOTIFICATION",           -- 0x02
    [64]    = "REQUEST ACK",            -- 0x40
    [65]    = "REQUEST NO RETURN ACK",  -- 0x41
    [66]    = "NOTIFICATION ACK",       -- 0x42
    [128]   = "RESPONSE",               -- 0x80
    [129]   = "ERROR",                  -- 0x81
    [192]   = "RESPONSE ACK",           -- 0xc0
    [193]   = "ERROR ACK",              -- 0xc1

    -- SOME/IP - Transport Protocol (SOME/IP-TP)
    [32]    = "REQUEST Segment",                -- 0x20
    [33]    = "REQUEST NO RETURN Segment",      -- 0x21
    [34]    = "NOTIFICATION Segment",           -- 0x22
    [96]    = "REQUEST ACK Segment",            -- 0x60
    [97]    = "REQUEST NO RETURN ACK Segment",  -- 0x61
    [98]    = "NOTIFICATION ACK Segment",       -- 0x62
    [160]   = "RESPONSE Segment",               -- 0xa0
    [161]   = "ERROR Segment",                  -- 0xa1
    [224]   = "RESPONSE ACK Segment",           -- 0xe0
    [225]   = "ERROR ACK Segment"               -- 0xe1
}
local ret_codes = {
    [0]     = "E_OK",
    [1]     = "E_NOT_OK",
    [2]     = "E_UNKNOWN_SERVICE",
    [3]     = "E_UNKNOWN_METHOD",
    [4]     = "E_NOT_READY",
    [5]     = "E_NOT_REACHABLE",
    [6]     = "E_TIMEOUT",
    [7]     = "E_WRONG_PROTOCOL_VERSION",
    [8]     = "E_WRONG_INTERFACE_VERSION",
    [9]     = "E_MALFORMED_MESSAGE",
    [10]    = "E_WRONG_MESSAGE_TYPE"
}

p_someip.fields = {f_msg_id,f_len,f_req_id,f_pv,f_iv,f_mt,f_rc, f_offset, f_reserved, f_more_seg}

p_someip.prefs["udp_port"] = Pref.uint("UDP Port",30490,"UDP Port for SOME/IP")

-- fields functions
local function field_msgid(subtree,buf)
    msg_id = subtree:add(f_msg_id,buf(0,4))
    local msg_id_uint = buf(0,4):uint()

    msg_id:append_text( " ("..tohex(buf(0,2):uint(),4)..
                        ":"..band(rshift(msg_id_uint,15),0x01)..
                        ":"..tohex(band(msg_id_uint,0x7fff),4)..")")

    msg_id:add("service_id : "..tohex(buf(0,2):uint(),4))
    if band(buf(2,1):uint(),0x80) == 0 then
        msg_id:add("method_id : "..tohex(band(msg_id_uint,0x7fff),4))
    else
        msg_id:add("event_id : "..tohex(band(msg_id_uint,0x7fff),4))
    end
end

local function field_reqid(subtree,buf)
    req_id = subtree:add(f_req_id,buf(8,4))
    local req_id_uint = buf(8,4):uint()

    req_id:append_text(" ("..buf(8,2)..":"..buf(10,2)..")")

    req_id:add("client_id : "..tohex(rshift(req_id_uint,16),4))
    req_id:add("session_id : "..tohex(req_id_uint,4))
end

local function get_someip_length(buf, pktinfo, offset)
    return buf(offset + 4,4):uint() + 8
end

-- PDU dissection function
local function someip_pdu_dissect(buf,pinfo,root)
    local m_type_num = buf(14,1):uint()
    local prev_proto = tostring(pinfo.cols.protocol)

    pinfo.cols.protocol = "SOME/IP"

    -- Delete irrelevant info from previous protocol
    if prev_proto ~= tostring(pinfo.cols.protocol) then
        pinfo.cols.info = ""
    end

    -- create subtree
    --
    subtree = root:add(p_someip,buf(0))

    -- add protocol fields to subtree
    --

    -- Message ID
    field_msgid(subtree,buf)

    -- Length
    subtree:add(f_len,buf(4,4))
    -- Requirement ID
    field_reqid(subtree,buf)
    -- Protocol Version
    subtree:add(f_pv,buf(12,1))
    -- Interface Version
    subtree:add(f_iv,buf(13,1))

    -- Message type
    local m_type = subtree:add(f_mt,buf(14,1))
    if msg_types[m_type_num] ~= nil then
        m_type:append_text(" (" .. msg_types[m_type_num] ..")")
        -- Concatenate the info of someip messages sent in same datagram
        if tostring(pinfo.cols.info) ~= "" then
            pinfo.cols.info = tostring(pinfo.cols.info) .. ", " .. msg_types[m_type_num]
        else
            pinfo.cols.info = msg_types[m_type_num]
        end
    end

    -- Return Code
    local rcode = subtree:add(f_rc,buf(15,1))
    if ret_codes[buf(15,1):uint()] ~= nil then
        rcode:append_text(" (" .. ret_codes[buf(15,1):uint()] ..")")
    end

    -- SOME/IP TP
    if band(m_type_num,0x20) ~= 0 then
        subtree:add(f_offset,buf(16,4))
        local tp_offset = band(buf(16,4):uint(), 0xfffffff0)
        pinfo.cols.info = tostring(pinfo.cols.info) .. " Offset=" .. tp_offset
        subtree:add(f_reserved,buf(19,1))
        local more_seg = subtree:add(f_more_seg,buf(19,1))
        if band(buf(19,1):uint(),0x01) == 0 then
            more_seg:append_text(" (Last Segment)")
            pinfo.cols.info = tostring(pinfo.cols.info) .. " More=False"
        else
            more_seg:append_text(" (Another segment follows)")
            pinfo.cols.info = tostring(pinfo.cols.info) .. " More=True"
        end
    end

    -- SD payload --
    --
    if (buf(0,4):uint() == 0xffff8100) and (buf:len() > SOMEIP_HDR_LENGTH)  then
        Dissector.get("sd"):call(buf(SOMEIP_HDR_LENGTH):tvb(),pinfo,root)
    elseif (buf:len() > SOMEIP_HDR_LENGTH) then
        Dissector.get("data"):call(buf(SOMEIP_HDR_LENGTH, get_someip_length(buf,pinfo,0) - SOMEIP_HDR_LENGTH):tvb(),pinfo,root)
    end

    -- Dissect next SOMEIP packet --
    local end_of_current_packet = get_someip_length(buf,pinfo,0)
    local next_packet_length = buf:len() - end_of_current_packet
    if next_packet_length > 0 then
        Dissector.get("someip"):call(buf(end_of_current_packet):tvb(),pinfo,root)
    end
end

-- main dissection function
function p_someip.dissector(buf,pinfo,root)
    -- if above TCP we need to assemble the PDU
    if pinfo.port_type == 2 then
        dissect_tcp_pdus(buf,root, SOMEIP_HDR_LENGTH, get_someip_length, someip_pdu_dissect)
    else
        someip_pdu_dissect(buf,pinfo,root)
    end
end

-- initialization routine
function p_someip.init()
    -- register protocol (some ports arount 30490, that is referenced on Specs)
    local udp_dissector_table = DissectorTable.get("udp.port")
    local tcp_dissector_table = DissectorTable.get("tcp.port")

    -- Register dissector to multiple ports
    for i,port in ipairs{30490,30491,30501,30502,30503,30504} do
        udp_dissector_table:add(port,p_someip)
        tcp_dissector_table:add(port,p_someip)
    end
end
