import websockets.sync.server
import time

def handle_connection(websocket):
    print("client connected")

    msg  = websocket.recv()
    print("recived",msg)

    res = "this is the responce"
    websocket.send( res )

    time.sleep(3)
    websocket.send(f"2 : {res}")
    

server  = websockets.sync.server.serve( handle_connection , "localhost" , 8080 )
print("web socket server started")

try:
    server.serve_forever()
except KeyboardInterrupt:
    print(KeyboardInterrupt.__name__,"Stopped server")
except Exception as e:
    print(f"Unexpected error: {e}")