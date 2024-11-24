-- Define the CSMIM protocol
csmim_proto = Proto("csmim", "CSMIM Protocol")

-- Define fields for CBOR detection and decoding
local f_payload = ProtoField.bytes("csmim.payload", "MQTT Payload (CBOR)")
local f_decoded = ProtoField.string("csmim.decoded", "Decoded CBOR Data")
csmim_proto.fields = {f_payload, f_decoded}

-- Function to extract the payload offset
local function get_payload_offset(buffer)
    -- Parse the remaining length field in MQTT fixed header
    local multiplier = 1
    local value = 0
    local offset = 1 -- Start after the first byte of the fixed header
    repeat
        if offset >= buffer:len() then
            return nil, "Remaining length field out of bounds"
        end
        local byte = buffer(offset, 1):uint()
        value = value + bit32.band(byte, 0x7F) * multiplier
        multiplier = multiplier * 128
        offset = offset + 1
    until bit32.band(byte, 0x80) == 0

    -- Skip the variable header (topic length and topic string)
    if offset + 2 > buffer:len() then
        return nil, "Topic length field out of bounds"
    end
    local topic_length = buffer(offset, 2):uint()
    offset = offset + 2 + topic_length -- Skip topic length and topic string

    -- Skip the packet identifier for QoS 1/2
    if offset + 2 <= buffer:len() and buffer(0, 1):bitfield(1, 2) > 0 then
        offset = offset + 2
    end

    if offset >= buffer:len() then
        return nil, "Payload offset out of bounds"
    end

    return offset, nil
end

-- Function to decode CBOR (minimal decoding for now)
local function decode_cbor(buffer, offset, tree)
    if offset >= buffer:len() then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, "CBOR decoding error: offset out of bounds")
        return
    end

    -- For now, display raw CBOR as a placeholder
    local raw_cbor = buffer(offset):bytes():tohex()
    tree:add(buffer(offset), "Raw CBOR: " .. raw_cbor)

    -- You can replace this with actual CBOR decoding logic later
end

-- Main dissector function
function csmim_proto.dissector(buffer, pinfo, tree)
    -- Use the built-in MQTT dissector
    local mqtt_dissector = Dissector.get("mqtt")
    if mqtt_dissector then
        mqtt_dissector:call(buffer, pinfo, tree)
    else
        tree:add_expert_info(PI_PROTOCOL, PI_ERROR, "Built-in MQTT dissector not found")
        return
    end

    -- Extract the payload offset
    local payload_offset, err = get_payload_offset(buffer)
    if not payload_offset then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Failed to extract MQTT payload: " .. err)
        return
    end

    -- Add CBOR payload as a new subtree
    local csmim_tree = tree:add(csmim_proto, buffer(), "CSMIM Protocol Data")
    csmim_tree:add(f_payload, buffer(payload_offset)):append_text(" (CBOR Detected)")

    -- Decode the CBOR payload
    local cbor_decoder = require("csmim_cbor_decoder")
    cbor_decoder.decode_cbor(buffer, payload_offset, csmim_tree)

    -- Update the protocol column to CSMIM
    pinfo.cols.protocol = "CSMIM"
end

-- Register the dissector for TCP port 1883 (or other relevant port)
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(1883, csmim_proto) -- Replace 1883 with the appropriate port for CSMIM
