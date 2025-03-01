import sys
import configparser
from queue import Queue
import websockets.sync.server
import threading

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
    pass

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

    # join the all threads to stop program closing immediately.
    # threads are set to daemon so will close when the main thread exits
    webSocket_Obj.websocket_thread.join()
    webSocket_Obj.thread_1.join()
    webSocket_Obj.thread_2.join()
    