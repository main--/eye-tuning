import struct
from datetime import datetime
from pydaap.pydaap.parser import DmapInstruction, DmapFieldType

def len2c(l):
    if l == 1:
        return 'b'
    elif l == 2:
        return 'h'
    elif l == 4:
        return 'i'
    elif l == 8:
        return 'q'
    elif l == 16:
        return 'q'
    else:
        raise ValueError(l)

def parse(blob):
    current = [] # {}
    while len(blob) >= 8:
        tag = blob[:4]
        #print(len(blob), tag)
        size, = struct.unpack('>I', blob[4:8])
        data = blob[8:8+size]
        
        instr = DmapInstruction.get(tag.decode('ascii'))
        
        if instr:
            if instr['type'] == DmapFieldType.DMAP_DICT:
                current.append((instr['name'], parse(data)))
            elif instr['type'] == DmapFieldType.DMAP_UINT and size <= 8:
                current.append((instr['name'], struct.unpack('>' + len2c(size).upper(), data)))
            elif instr['type'] == DmapFieldType.DMAP_INT and size <= 8:
                current.append((instr['name'], struct.unpack('>' + len2c(size).lower(), data)))
            elif instr['type'] == DmapFieldType.DMAP_STR:
                current.append((instr['name'], data.decode('utf-8')))
            elif instr['type'] == DmapFieldType.DMAP_DATE:
                current.append((instr['name'], datetime.fromtimestamp(struct.unpack('>I', data)[0])))
            elif instr['type'] == DmapFieldType.DMAP_VERS:
                current.append((instr['name'], struct.unpack('>HH', data)))
            else:
                current.append((instr['name'], data))
        else:
            current.append((tag, data))

        '''
        if instr:
            if instr['type'] == DmapFieldType.DMAP_DICT:
                current[instr['name']] = parse(data)
            elif instr['type'] == DmapFieldType.DMAP_UINT and size <= 8:
                current[instr['name']], = struct.unpack('>' + len2c(size).upper(), data)
            elif instr['type'] == DmapFieldType.DMAP_INT and size <= 8:
                current[instr['name']], = struct.unpack('>' + len2c(size).lower(), data)
            elif instr['type'] == DmapFieldType.DMAP_STR:
                current[instr['name']] = data.decode('utf-8')
            elif instr['type'] == DmapFieldType.DMAP_DATE:
                current[instr['name']] = datetime.fromtimestamp(struct.unpack('>I', data)[0])
            elif instr['type'] == DmapFieldType.DMAP_VERS:
                current[instr['name']] = struct.unpack('>HH', data)
            else:
                current[instr['name']] = data
        else:
            current[tag] = data
        '''
            
        blob = blob[8+size:]
    return current
