import struct

class TlmPacket:
    def __init__(self, csp_id, csp_port, csp_payload,  sc_id=0, sc_enable=0, no_sc_id=0,amp_node_str="", uhf_node_str="", dpc_node_str=""):
        self.csp_id = csp_id
        self.csp_port = csp_port
        self.payload = csp_payload
        self.is_amp = False
        self.micron_id = None
        self.is_dpc = False
        self.sc_id = sc_id
        self.sc_enable =  sc_enable
        self.no_sc_id = no_sc_id
        amp_nodes = amp_node_str.split(',') if len(amp_node_str) > 0 else [] 
        dpc_nodes = dpc_node_str.split(',') if len(dpc_node_str) > 0 else []
        if str(csp_id) in amp_nodes:
            if (sc_enable == 1 and str(csp_id) not in no_sc_id): # sc_id (2) --> amp (2) --> tlm_id(1)
                self.tlm_id = csp_payload[4] if len(csp_payload) > 1 else b''
                self.micron_id = int.from_bytes(self.payload[2:4], byteorder='little')
                self.payload[0], self.payload[1:5] = self.payload[4], self.payload[0:4]
                self.is_amp = True
            else: # amp(2) --> tlm_id (1)
                self.tlm_id = csp_payload[2] if len(csp_payload) > 1 else b''
                self.micron_id = int.from_bytes(self.payload[0:2], byteorder='little')
                self.payload[0], self.payload[1:3] = self.payload[2], self.payload[0:2]
                self.is_amp = True
        # UHF Beacon mode packet handling
        elif str(csp_id) in dpc_nodes:
            if (sc_enable == 1 and str(csp_id) not in no_sc_id): # sc_id (2) --> tlm_id(1)
                self.tlm_id = csp_payload[2] if len(csp_payload) > 0 else b''
                self.payload[0], self.payload[1:3] = self.payload[2], self.payload[0:2]
                self.is_dpc = True
            else: # tlm_id (1)
                self.tlm_id = csp_payload[0] if len(csp_payload) > 0 else b''
                self.is_dpc = True
        elif str(csp_id) == uhf_node_str.strip(): # BEACON MIGHT NOT BE S/C COMPATIBLE, NEED TO CHECK
            if len(csp_payload) > 4 and csp_payload[4] == 136:
                if int.from_bytes(csp_payload[5:9], byteorder='little') == 0xbeefcafe:
                    self.tlm_id = csp_payload[1] if len(csp_payload) > 1 else b''
                    # Swap the TLM_ID and UHF timestamp to put TLM_ID at the start
                    self.payload[0], self.payload[1:5] = csp_payload[4], csp_payload[0:4]
        else:
            if (sc_enable == 1 and str(csp_id) not in no_sc_id): # sc_id (2) --> tlm_id(1)
                self.tlm_id = csp_payload[2] if len(csp_payload) > 0 else b''
                self.payload[0], self.payload[1:3] = self.payload[2], self.payload[0:2]
            else: # tlm_id (1)  
                self.tlm_id = csp_payload[0] if len(csp_payload) > 0 else b''
        


    def to_bytes(self):
        """ Return a bytes type object of this packet content """
        return struct.pack('BB', self.csp_id, self.csp_port) + self.payload

    def to_bytes_with_length(self):
        """ Return a bytes type object of this packet content prepended with a 4 byte UINT length.
        This format satisfies the length protocol expected by Cosmos """
        as_bytes = self.to_bytes()
        return struct.pack('<I', len(as_bytes)) + as_bytes

    def is_file_download_info_pkt(self):
        return self.csp_port == 10 and (self.tlm_id == 11 or self.tlm_id == 12)

    def is_file_download_data_pkt(self):
        return self.csp_port == 10 and self.tlm_id == 2

    def is_cancel_download_pkt(self):
        return self.csp_port == 10 and self.tlm_id == 7
