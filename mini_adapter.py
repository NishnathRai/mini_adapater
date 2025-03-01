import sys
import configparser
from queue import Queue
import websockets.sync.server
import threading
import libcsp_py3 as libcsp
import time
from tlm_packet import TlmPacket
from collections import namedtuple

# reading the config file
def read_config(path):
    config = configparser.ConfigParser()
    config.read(path)
    return config

class WebSocket:

    def __init__(self,config,send_to_target_queue,receive_from_target_queue):
        self.config = config
        self.active_client = None
        self.webSocket_server = None
        self.send_to_target_queue = send_to_target_queue 
        self.receive_from_target_queue = receive_from_target_queue

        self.websocket_thread = threading.Thread( target=self.start_server , daemon=True)
        self.websocket_thread.start()
        

    def start_server(self):
        self.webSocket_server = websockets.sync.server.serve(
            self.handle_connection ,
            self.config['TCP']['Address'] ,
            int(self.config['TCP']['Port']) 
            )
        print("web socket server started")

        try:
            self.webSocket_server.serve_forever()
        except KeyboardInterrupt:
            print(KeyboardInterrupt.__name__,"server Stopped")
        except Exception as e:
            print(f"Unexpected error: {e}")

    def handle_connection(self,websocket):
        try :
            self.active_client =  websocket.remote_address 

            self.webSocket_server = websocket
            print("client connected")

            self.thread_1 = threading.Thread(target=self.send_to_target_from_user_thread,daemon=True)
            self.thread_1.start()

            self.thread_2 = threading.Thread(target=self.send_to_user_from_target_thread,daemon=True)
            self.thread_2.start()
        except :
            self.active_client = None
            print("Thread 1 and 2 stoped ")
    
    def send_to_target_from_user_thread(self):
        try :
            while self.active_client:
                command  = self.webSocket_server.recv()
                self.send_to_target_queue.put( command )
        except websockets.exceptions.ConnectionClosed:
            print("Client disconnected")
            self.active_client = None
        except Exception as err:
            print(f"unknow error : {err}")

    def send_to_user_from_target_thread(self):
        try :
            while self.active_client:
                telemetry = self.receive_from_target_queue.get()
                if self.active_client:
                    self.webSocket_server.send( telemetry )
                else:
                    self.receive_from_target_queue.put( telemetry )
        except websockets.exceptions.ConnectionClosed:
            print("Client disconnected")
            self.active_client = None
        except Exception as err:
            print(f"unknow error : {err}")

class Csp:
    def __init__(self, config, send_to_target_queue, receive_from_target_queue, device):
        """Initialize CSP Adapter."""
        self.config = config
        self.device = device
        self.send_to_target_queue = send_to_target_queue
        self.receive_from_target_queue = receive_from_target_queue

        self.sc_enable = self.config['setup'].getint('SC_ENABLE')
        self.sc_id = self.config['setup'].getint('SC_ID')
        self.no_sc_id = self.config['setup']['NO_SC_ID'].split(',') if self.config['setup']['NO_SC_ID'] else []

        self.initialise_csp()
        
        # Start threads
        self.thread_3 = self.start_libcsp_recv_thread()
        self.thread_4 = self.start_read_tcp_send_to_csp_adapter_queue()

    def initialise_csp(self):
        """Initialize CSP parameters and interfaces."""
        libcsp.init(
            self.config['setup'].getint('CSPAddress'),
            "host", "model", "0.0.0",
            self.config['libCSP'].getint('InitBufferCount'),
            self.config['libCSP'].getint('InitBufferSize')
        )

        if self.device:
            libcsp.kiss_init(
                self.device,
                self.config['KISS'].getint('Baudrate'),
                1024,
                self.config['RTable']['Interface']
            )

            libcsp.rtable_set(
                self.config['RTable'].getint('Address'),
                self.config['RTable'].getint('Netmask'),
                self.config['RTable']['Interface'],
                self.config['RTable'].getint('Via')
            )

            libcsp.route_start_task()
        time.sleep(0.2)

    def start_libcsp_recv_thread(self):
        """Start thread to listen for incoming packets from CSP."""
        worker = threading.Thread(target=self._libcsp_recv, daemon=True)
        worker.start()
        return worker

    def _libcsp_recv(self):
        """Listen for incoming packets from the target via CSP."""
        libcsp_sock = libcsp.socket(libcsp.CSP_SO_CONN_LESS)
        libcsp.bind(libcsp_sock, libcsp.CSP_ANY)
        libcsp.listen(libcsp_sock, self.config['libCSP'].getint('ListenQueueLength'))

        while True:
            try:
                rcvdpacket = libcsp.recvfrom(libcsp_sock, self.config['libCSP'].getint('RecvfromTimeout'))
                if not rcvdpacket:
                    continue

                packet_header_info = namedtuple("header", "src dst dport sport")(*libcsp.packet_get_header(rcvdpacket))

                print(f"Packet received: source={packet_header_info.src}:{packet_header_info.sport}, "
                      f"dest={packet_header_info.dst}:{packet_header_info.dport}")

                data = bytearray(libcsp.packet_get_data(rcvdpacket))
                
                csp_packet = TlmPacket(
                    packet_header_info.src,
                    packet_header_info.dport,
                    data,
                    self.sc_id,
                    self.sc_enable,
                    self.no_sc_id,
                    self.config['setup']['AMPNodes'],
                    self.config['setup']['UHFNode'],
                    self.config['setup']['DPCNodes']
                )

                self.receive_from_target_queue.put(csp_packet)

            except libcsp.CSPError as e:
                self.logger.error(f"CSP Error: {e}")
            except Exception as e:
                self.logger.error(f"Unexpected error in _libcsp_recv: {e}")

    def start_read_tcp_send_to_csp_adapter_queue(self):
        """Start a thread to process items from the TCP queue."""
        worker = threading.Thread(target=self._read_tcp_send_to_csp_adapter_queue, daemon=True)
        worker.start()
        return worker

    def _read_tcp_send_to_csp_adapter_queue(self):
        """Process and send packets from TCP queue to CSP."""
        while True:
            try:
                item = self.send_to_target_queue.get()


                priority = item[0]  # Byte number
                dest_csp_id = item[1]  # Byte number
                dest_csp_port = item[2]  # Byte number
                packet_payload = item[3:]

                
                if self.sc_enable == 1 and str(dest_csp_id) not in self.no_sc_id:
                    packet_payload.insert(0, (self.sc_id & 0xFF))
                    packet_payload.insert(1, (self.sc_id >> 8))


                to_send = libcsp.buffer_get(self.config['libCSP'].getint('BufferGetSizeBytes'))
                packet_payload = bytearray(packet_payload)
                libcsp.packet_set_data(to_send, packet_payload)

                libcsp.sendto(
                    priority,
                    dest_csp_id,
                    dest_csp_port,  # Use destination port as source port
                    dest_csp_port,
                    libcsp.CSP_SO_CONN_LESS,
                    to_send,
                    self.config['libCSP'].getint('SendtoTimeout')
                )

            except libcsp.CSPError as e:
                self.logger.error(f"CSP Error: {e}")
            except Exception as e:
                self.logger.error(f"Unexpected error in _read_tcp_send_to_csp_adapter_queue: {e}")

if __name__ == "__main__":

    conf_path = sys.argv[1].rstrip()  # config.ini 
    device  = sys.argv[2].rstrip()    # COMX

    config = read_config( conf_path ) # got config Obj

    # creating two global Queue
    send_to_target_queue = Queue()
    receive_from_target_queue = Queue()

    # instantiate and start websocket Server 
    # And start the threads 1 and 2
    webSocket_Obj = WebSocket(config,send_to_target_queue,receive_from_target_queue)
    Csp_Obj = Csp(config,send_to_target_queue,receive_from_target_queue,device)

    # join the all threads to stop program closing immediately.
    # threads are set to daemon so will close when the main thread exits
    webSocket_Obj.websocket_thread.join()
    webSocket_Obj.thread_1.join()
    webSocket_Obj.thread_2.join()
    Csp_Obj.thread_3.join()
    Csp_Obj.thread_4.join()
    