-- Define the CBOR decoder module
local cbor_decoder = {}

-- Recursive function to decode CBOR data dynamically
function cbor_decoder.decode_cbor(buffer, offset, tree)
    if offset >= buffer:len() then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, "CBOR decoding error: offset out of bounds")
        return buffer:len()
    end

    local initial_byte = buffer(offset, 1):uint()
    local major_type = bit32.rshift(initial_byte, 5) -- Top 3 bits for the type
    local additional_info = bit32.band(initial_byte, 0x1F) -- Bottom 5 bits
    local current_offset = offset + 1

    -- Decode based on the CBOR major type
    if major_type == 0 then
        -- Unsigned integer
        local value = additional_info
        if additional_info >= 24 then
            if additional_info == 24 then
                value = buffer(current_offset, 1):uint()
                current_offset = current_offset + 1
            elseif additional_info == 25 then
                value = buffer(current_offset, 2):uint()
                current_offset = current_offset + 2
            elseif additional_info == 26 then
                value = buffer(current_offset, 4):uint()
                current_offset = current_offset + 4
            elseif additional_info == 27 then
                value = buffer(current_offset, 8):uint64()
                current_offset = current_offset + 8
            else
                tree:add_expert_info(PI_PROTOCOL, PI_ERROR, "Unsupported unsigned integer size")
                return current_offset
            end
        end
        tree:add(buffer(offset, current_offset - offset), "Unsigned Integer: " .. value)

    elseif major_type == 1 then
        -- Negative integer
        local value = -1 - additional_info
        if additional_info >= 24 then
            if additional_info == 24 then
                value = -1 - buffer(current_offset, 1):uint()
                current_offset = current_offset + 1
            elseif additional_info == 25 then
                value = -1 - buffer(current_offset, 2):uint()
                current_offset = current_offset + 2
            elseif additional_info == 26 then
                value = -1 - buffer(current_offset, 4):uint()
                current_offset = current_offset + 4
            elseif additional_info == 27 then
                value = -1 - buffer(current_offset, 8):uint64()
                current_offset = current_offset + 8
            else
                tree:add_expert_info(PI_PROTOCOL, PI_ERROR, "Unsupported negative integer size")
                return current_offset
            end
        end
        tree:add(buffer(offset, current_offset - offset), "Negative Integer: " .. value)

    elseif major_type == 3 then
        -- UTF-8 string
        local length = additional_info
        if additional_info >= 24 then
            if additional_info == 24 then
                length = buffer(current_offset, 1):uint()
                current_offset = current_offset + 1
            elseif additional_info == 25 then
                length = buffer(current_offset, 2):uint()
                current_offset = current_offset + 2
            else
                tree:add_expert_info(PI_PROTOCOL, PI_ERROR, "Unsupported string size")
                return current_offset
            end
        end
        local utf8_string = buffer(current_offset, length):string()
        tree:add(buffer(offset, 1 + length), "UTF-8 String: " .. utf8_string)
        current_offset = current_offset + length

    elseif major_type == 4 then
        -- Array
        local length = additional_info
        if additional_info >= 24 then
            if additional_info == 24 then
                length = buffer(current_offset, 1):uint()
                current_offset = current_offset + 1
            elseif additional_info == 25 then
                length = buffer(current_offset, 2):uint()
                current_offset = current_offset + 2
            else
                tree:add_expert_info(PI_PROTOCOL, PI_ERROR, "Unsupported array size")
                return current_offset
            end
        end
        local array_tree = tree:add(buffer(offset, current_offset - offset), "CBOR Array of Length: " .. length)
        for i = 1, length do
            current_offset = cbor_decoder.decode_cbor(buffer, current_offset, array_tree)
        end

    elseif major_type == 5 then
        -- Map
        local length = additional_info
        if additional_info >= 24 then
            if additional_info == 24 then
                length = buffer(current_offset, 1):uint()
                current_offset = current_offset + 1
            elseif additional_info == 25 then
                length = buffer(current_offset, 2):uint()
                current_offset = current_offset + 2
            else
                tree:add_expert_info(PI_PROTOCOL, PI_ERROR, "Unsupported map size")
                return current_offset
            end
        end
        local map_tree = tree:add(buffer(offset, current_offset - offset), "CBOR Map of Length: " .. length)
        for i = 1, length do
            -- Decode key
            current_offset = cbor_decoder.decode_cbor(buffer, current_offset, map_tree)
            -- Decode value
            current_offset = cbor_decoder.decode_cbor(buffer, current_offset, map_tree)
        end

    else
        -- Unsupported or unknown CBOR type
        tree:add(buffer(offset, 1), "Unsupported CBOR Type: " .. major_type)
    end

    return current_offset
end

return cbor_decoder
