import socket
import threading
import struct
import configparser
import warnings
import sys
import os
import logging
import csv
import time

from queue import Queue
from time import sleep
from collections import namedtuple
from pathlib import Path
from logging.handlers import RotatingFileHandler

import file_download
import file_download_micron
import adapter_statistics
from tlm_packet import TlmPacket

# IMPORTANT: This will need to change if we ever move files or directories
build_dir = Path(__file__).absolute().parent.parent / 'LIBCSP/build'
print(build_dir)
sys.path.insert(1, str(build_dir))
import libcsp_py3 as libcsp


class TCPServer:
    """ TCP server for sending and recieving COSMOS data """

    def __init__(self, host, port):

        self.host = host
        self.port = port
        self.cosmos_socket = None

        self.logger = logging.getLogger('TCP_SERVER')
        self.stat_logger = adapter_statistics.get_stat_logger()

        self.send_to_csp_adapter_queue, self.receive_from_csp_adapter_queue = Queue(), Queue()

    def start_tcp_main_thread(self):
        """ start the main tcp server thread """

        self.logger.info("Server main thread start up")
        worker = threading.Thread(target=self._tcp_main)
        worker.daemon = True
        worker.start()

    def _tcp_main(self):
        """ permanently attempt to connect/ reconnect to cosmos """

        while True:
            self._accept_cosmos_connection()
            self._process_cosmos_commands()

    def _accept_cosmos_connection(self):
        """ Open a server and allow connection from COSMOS """

        # Create a TCP/IP socket
        self.logger.info("Create TCP/IP Socket")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind the socket to the port
        server_address = (self.host, self.port)  # CMD in
        self.logger.info('Starting up on' + str(server_address))
        sock.bind(server_address)

        # Listen for incoming connections
        sock.listen(1)

        # Wait for a connection
        self.logger.info('Waiting for a connection from COSMOS')
        self.cosmos_socket, client_address = sock.accept()
        self.logger.info('Connection from COSMOS: ' + str(client_address))

    def _process_cosmos_commands(self):
        """ Listens for COSMOS commands and adds to queue """
        while True:
            try:
                recvd = self.recv_msg(self.cosmos_socket)

                if recvd:
                    self.stat_logger.increment_stat_count('tcp_recv_msg')

                    self.send_to_csp_adapter_queue.put(recvd)
                    self.stat_logger.increment_stat_count('cosmos_to_tcp_put')
                else:
                    raise ConnectionResetError

            except ConnectionResetError as e:
                self.logger.error("Restarting connection. " + str(e))
                self._close_cosmos_connection()
                break

    def _close_cosmos_connection(self):
        """ Close the connection from COSMOS """
        self.cosmos_socket.close()
        self.cosmos_socket = None

    def recv_msg(self, sock):
        """ Receives messages on the provided socket based on the length of the message """

        # Read message length and unpack it into an integer
        raw_msglen = self.recvall(sock, 4)

        if not raw_msglen:
            return None

        msglen = struct.unpack('<I', raw_msglen)[0]

        # Read the rest of the message data
        return self.recvall(sock, msglen)

    def recvall(self, sock, n):
        """ Helper function to recv n bytes or return None if EOF is hit """
        data = bytearray()
        while len(data) < n:
            packet = sock.recv(n - len(data))

            if not packet:
                return None

            data.extend(packet)

        return data

    def start_read_tcp_receive_from_csp_adapter_queue(self):
        """ start a thread to process reading items from the recieve from csp adapter queue """
        worker = threading.Thread(target=self._read_tcp_receive_from_csp_adapter_queue)
        worker.daemon = True
        worker.start()

    def _read_tcp_receive_from_csp_adapter_queue(self):
        """ read items from the recieve from csp adapter queue and call the send to COSMOS function """

        while True:
            self.logger.debug("Getting telemetry item from queue")
            item = self.receive_from_csp_adapter_queue.get()
            self.stat_logger.increment_stat_count('csp_to_tcp_get')

            try:
                self.logger.debug("Telemetry item received: " + str(item.to_bytes_with_length().hex()))

                while not self.cosmos_socket:
                    self.logger.debug("Waiting for COSMOS connection before sending telemetry back")
                    sleep(1)

                self.cosmos_socket.sendall(item.to_bytes_with_length())
                self.stat_logger.increment_stat_count('tcp_sendall')

                self.logger.debug("Telemetry item sent to COSMOS")

            except Exception as e:
                print(e)

            self.receive_from_csp_adapter_queue.task_done()


class CSPAdapter:
    """ CSP adapter for receiving, processing, and sending commands and telemetry """

    def __init__(self, config, tcp_send_to_csp_adapter_queue, tcp_receive_from_csp_adapter_queue):

        self.config = config

        self.logger = logging.getLogger('CSP_ADAPTER')
        self.stat_logger = adapter_statistics.get_stat_logger()
        self.sc_enable =  self.config['setup'].getint('SC_ENABLE')
        self.sc_id =  self.config['setup'].getint('SC_ID')  
        self.no_sc_id = self.config['setup']['NO_SC_ID'].split(',') if len(self.config['setup']['NO_SC_ID']) > 0 else [] 

        self.tcp_send_to_csp_adapter_queue = tcp_send_to_csp_adapter_queue
        self.tcp_receive_from_csp_adapter_queue = tcp_receive_from_csp_adapter_queue
        self.recvd_from_target_processing_queue = Queue()
        self.send_to_target_queue = Queue()
        self.upload_delay_queue = Queue()

        self.download_manager = None # initialised later

    def initialise_download_manager(self):
        """ initialise the file download manager class and add to self """

        self.download_manager = file_download.FileDownloadManager(
            self.tcp_receive_from_csp_adapter_queue,
            self.config['FileDownload'].getint('FileDownloadTimeoutSeconds'),
            self.config['FileDownload'].getfloat('DownloadMonitorThreadFrequencyMilliSeconds'),
            # file_download.CSPPortTransformer(self.config['FileDownload']['FileToLiveTelemPortMappingLoc'].rstrip()),
            self.config['FileDownload'].getint('LogInProgressFrequencySeconds'),
            self.config['setup'].getint('SC_ENABLE'),
            self.config['setup'].getint('SC_ID'),
            self.config['setup']['NO_SC_ID'].split(',') if len(self.config['setup']['NO_SC_ID']) > 0 else [] 
        )

        self.download_manager_micron = file_download_micron.FileDownloadManagerMicron(
            self.tcp_receive_from_csp_adapter_queue,
            self.config['FileDownload'].getint('FileDownloadTimeoutSeconds'),
            self.config['FileDownload'].getfloat('DownloadMonitorThreadFrequencyMilliSeconds'),
            # file_download.CSPPortTransformer(self.config['FileDownload']['FileToLiveTelemPortMappingLoc'].rstrip()),
            self.config['FileDownload'].getint('LogInProgressFrequencySeconds'),
            self.config['setup'].getint('SC_ENABLE'),
            self.config['setup'].getint('SC_ID'),
            self.config['setup']['NO_SC_ID'].split(',') if len(self.config['setup']['NO_SC_ID']) > 0 else [] 
        )

    def set_stat_logger_send_queue(self):
        """ set the statistics send queue so it can send telemetry back """
        self.stat_logger.set_send_queue(self.tcp_receive_from_csp_adapter_queue)

    def initialise_csp(self, device):
        """ initialise the main CSP parameters, and the interface and routing parameters """

        self.logger.info("Initialising libcsp")

        libcsp.init(
            self.config['setup'].getint('CSPAddress'),
            "host", "model", "0.0.0",
            self.config['libCSP'].getint('InitBufferCount'),
            self.config['libCSP'].getint('InitBufferSize'))

        if device:
            libcsp.kiss_init(
                device,
                self.config['KISS'].getint('Baudrate'),
                1024,
                self.config['RTable']['Interface'])

            libcsp.rtable_set(
                self.config['RTable'].getint('Address'),
                self.config['RTable'].getint('Netmask'),
                self.config['RTable']['Interface'],
                self.config['RTable'].getint('Via'))

            libcsp.route_start_task()
        sleep(0.2)  # allow router task startup

    def start_construct_and_send_csp_packet_thread(self):
        """ start a thread to process reading items from the TCP queue from COSMOS """

        worker = threading.Thread(target=self._construct_and_send_csp_packet)
        worker.daemon = True
        worker.start()

        return worker

    def _construct_and_send_csp_packet(self):
        """ construct a CSP packet from the provided command from COSMOS """

        while True:
            self.logger.debug("Waiting for next item to send to target")
            item = self.send_to_target_queue.get()
            self.stat_logger.increment_stat_count('csp_to_target_get')

            try:
                priority = item[0] # Byte number
                dest_csp_id = item[1] # Byte number
                dest_csp_port = item[2] # Byte number

                packet_payload = item[3:]

                if (self.sc_enable==1 and (str(dest_csp_id) not in self.no_sc_id)):
                    packet_payload.insert(0,(self.sc_id & 0xFF))
                    packet_payload.insert(1,(self.sc_id >> 8))  

                self.logger.debug(f"Values recieved from COSMOS- priority: {priority}, destination: {dest_csp_id}, destination port: {dest_csp_port}")

                to_send = libcsp.buffer_get(self.config['libCSP'].getint('BufferGetSizeBytes'))
                packet_payload = bytearray(packet_payload)
                libcsp.packet_set_data(to_send, packet_payload)

                # csp_sendto(prio, dest, dst_port, src_port, opts, *packet, timeout)
                libcsp.sendto(
                    priority,
                    dest_csp_id,
                    dest_csp_port, # Use destination port as source port so that responses come back on the correct ports
                    dest_csp_port,
                    libcsp.CSP_SO_CONN_LESS,
                    to_send,
                    self.config['libCSP'].getint('SendtoTimeout'))
                
                

                self.stat_logger.increment_stat_count('libcsp_sendto')

            except Exception as e:
                print(e)
            finally:
                libcsp.buffer_free(to_send)

            self.send_to_target_queue.task_done()

    def start_read_tcp_send_to_csp_adapter_queue(self):
        """ start a thread to process reading items from the TCP queue from COSMOS """

        worker = threading.Thread(target=self._read_tcp_send_to_csp_adapter_queue)
        worker.daemon = True
        worker.start()

        return worker

    def _read_tcp_send_to_csp_adapter_queue(self):
        """ read items from the TCP send queue and call the processing function """

        while True:
            self.logger.debug("Waiting for next COSMOS command")
            item = self.tcp_send_to_csp_adapter_queue.get()
            self.stat_logger.increment_stat_count('cosmos_to_tcp_get')

            try:
                self.logger.debug("COSMOS command received")

                if item[2] == 10 and item[3] == 3: # port, cmd_code
                    self.upload_delay_queue.put(item)
                    self.stat_logger.increment_stat_count('upload_delay_put')

                else:
                    self.send_to_target_queue.put(item)
                    self.stat_logger.increment_stat_count('csp_to_target_put')

            except Exception as e:
                print(e)

            self.tcp_send_to_csp_adapter_queue.task_done()

    def start_upload_delay_thread(self):
        """ start a thread to delay file upload blocks by specified delay """

        worker = threading.Thread(target=self._upload_delay)
        worker.daemon = True
        worker.start()

        return worker

    def _upload_delay(self):
        """ add items to the send_to_target_queue with a specified delay """

        while True:
            item = self.upload_delay_queue.get()
            self.stat_logger.increment_stat_count('upload_delay_get')

            self.logger.debug("Upload item received, adding to send_to_target_queue after specified delay")

            sleep(self.config['FileUpload'].getfloat('UploadDelay'))

            self.send_to_target_queue.put(item)
            self.stat_logger.increment_stat_count('csp_to_target_put')

            self.upload_delay_queue.task_done()

    def start_libcsp_recv_thread(self):
        """ start thread to listen for incoming packets from the target """

        worker = threading.Thread(target=self._libcsp_recv)
        worker.daemon = True
        worker.start()

        return worker

    def _libcsp_recv(self):
        """ start listening for incoming packets from the target """

        self.logger.debug('Listen for telemetry from target')
        libcsp_sock = libcsp.socket(libcsp.CSP_SO_CONN_LESS)
        libcsp.bind(libcsp_sock, libcsp.CSP_ANY)

        libcsp.listen(libcsp_sock, self.config['libCSP'].getint('ListenQueueLength'))

        while True:
            try:
                rcvdpacket = libcsp.recvfrom(libcsp_sock, self.config['libCSP'].getint('RecvfromTimeout'))

                if not rcvdpacket:
                    continue

                self.stat_logger.increment_stat_count('libcsp_recvfrom')
                self.logger.debug('Telemetry received from target')

                self.recvd_from_target_processing_queue.put(rcvdpacket)
                self.stat_logger.increment_stat_count('csp_from_target_put')

            except Exception as e:
                print(e)

    def start_process_libcsp_thread(self):
        """ start a thread to process packets from the target """

        worker = threading.Thread(target=self._process_libcsp_packet)
        worker.daemon = True
        worker.start()

        return worker

    def _process_libcsp_packet(self):
        """ process packets that have been placed on the processing queue """
        while True:
            rcvdpacket = self.recvd_from_target_processing_queue.get()
            self.stat_logger.increment_stat_count('csp_from_target_get')

            try:
                packet_header_info = namedtuple("header", "src dst dport sport")(*libcsp.packet_get_header(rcvdpacket))

                self.logger.debug(
                    "Packet receieved: "
                    f"source={packet_header_info.src}:{packet_header_info.sport}, "
                    f"dest={packet_header_info.dst}:{packet_header_info.dport}")

                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    data = bytearray(libcsp.packet_get_data(rcvdpacket))

                # data or file download data 
                if (self.sc_enable==1 and (str(packet_header_info.src) not in self.no_sc_id)):
                    if(int.from_bytes(data[0:2], byteorder='little') != (self.sc_id)):
                        raise Exception("Spacecraft I/D doesn't match")

                csp_packet = TlmPacket(packet_header_info.src, packet_header_info.dport, data, self.sc_id, self.sc_enable, self.no_sc_id,self.config['setup']['AMPNodes'], self.config['setup']['UHFNode'],self.config['setup']['DPCNodes'])

                self.handle_csp_packet(csp_packet)

            except Exception as e:
                print(e)

            self.recvd_from_target_processing_queue.task_done()

    def handle_csp_packet(self, csp_packet):
        """
        determine whether the packet is a special case to be dealt with by the file
        manager, or sent straight back to cosmos
        """
        selected_dl_mgr = self.download_manager
        if csp_packet.is_amp:
            selected_dl_mgr = self.download_manager_micron
            print("using micron fdownload")

        if csp_packet.is_file_download_info_pkt():
            selected_dl_mgr.init_file_download(csp_packet)
            self.tcp_receive_from_csp_adapter_queue.put(csp_packet)
            self.stat_logger.increment_stat_count('csp_to_tcp_put')

        elif csp_packet.is_file_download_data_pkt():
            selected_dl_mgr.process_csp_download_packet(csp_packet)

        elif csp_packet.is_cancel_download_pkt():  # Cancel download but also send this packet back to Cosmos
            selected_dl_mgr.cancel_download(csp_packet)
            self.tcp_receive_from_csp_adapter_queue.put(csp_packet)
            self.stat_logger.increment_stat_count('csp_to_tcp_put')

        else:
            self.tcp_receive_from_csp_adapter_queue.put(csp_packet)
            self.stat_logger.increment_stat_count('csp_to_tcp_put')


def read_config(config_path):
    """ parse the config file and return """
    config = configparser.ConfigParser()
    config.read(config_path)

    return config

def initialise_logging(config):
    """ set up logging for the adapter """

    # get log level from config and convert to numeric value
    log_level = config['logging']['LogLevel']
    numeric_log_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_log_level, int):
        raise ValueError('Invalid log level: %s' % log_level)

    # set up log file and location
    log_path = Path(config['logging']['LogLoc'].rstrip())
    log_path.mkdir(parents=True, exist_ok=True)
    timestr = time.strftime("%Y%m%d-%H%M%S")
    log_file_path = log_path.joinpath(f"adapter_{timestr}.log")

    # configure rotating logs
    rfh = RotatingFileHandler(
        filename=log_file_path,
        mode='a',
        maxBytes=config['logging'].getint('MaxBytes'),
        backupCount=config['logging'].getint('BackupCount'),
        encoding=None,
        delay=0
    )

    # set up logging to be output to both file and stdout
    logging.basicConfig(
        level=numeric_log_level,
        format="%(asctime)s %(name)s %(threadName)-25s [%(levelname)s] %(message)s",
        datefmt="%y-%m-%d %H:%M:%S",
        handlers=[
            rfh,
            logging.StreamHandler()
        ]
    )


if __name__ == "__main__":

    conf_path = sys.argv[1].rstrip()
    try:
       device = sys.argv[2].rstrip()
    except IndexError:
       device = ""

    #device = "//./COM12"
    #config = read_config("C://Users//psaripalli.AD//Documents//BW3//repos//ast-simulators//cosmos//ADAPTER//config.ini")
       
    config = read_config(conf_path)
    initialise_logging(config)
    adapter_statistics.stat_logger_config(config['statistics'].getint('Period'), config['statistics'].getboolean('ClearCounters'))

    # instantiate and start TCP Server threads
    tcp = TCPServer(config['TCP']['Address'], config['TCP'].getint('Port'))
    tcp.start_tcp_main_thread()
    tcp.start_read_tcp_receive_from_csp_adapter_queue()
    sleep(1)

    # instantiate and start csp threads
    csp = CSPAdapter(config, tcp.send_to_csp_adapter_queue, tcp.receive_from_csp_adapter_queue)
    csp.initialise_csp(device)
    csp.initialise_download_manager()
    csp.set_stat_logger_send_queue()

    libcsp_recv_worker = csp.start_libcsp_recv_thread()
    read_tcp_send_queue_worker = csp.start_read_tcp_send_to_csp_adapter_queue()
    process_libcsp_worker = csp.start_process_libcsp_thread()
    construct_and_send_csp_packet_worker = csp.start_construct_and_send_csp_packet_thread()
    upload_delay_csp_packet_worker = csp.start_upload_delay_thread()

    # join the worker threads to stop program closing immediately.
    # threads are set to daemon so will close when the main thread exits
    try:
        libcsp_recv_worker.join()
        read_tcp_send_queue_worker.join()
        process_libcsp_worker.join()
        construct_and_send_csp_packet_worker.join()
        upload_delay_csp_packet_worker.join()
    except KeyboardInterrupt:
        raise KeyboardInterrupt("Program execution interrupted. Closing down threads")
