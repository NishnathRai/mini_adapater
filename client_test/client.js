
startClient();

function startClient(){
    let socket = new WebSocket("ws://localhost:8080");

    socket.onopen = function(){
        console.log("connected to web socket server")
        socket.send("hello, Server!!")
    } 

    socket.onmessage = function(event) {
        console.log("Server response:", event.data);
    };
    
    socket.onclose = function() {
        console.log("WebSocket closed");
    };

    socket.onerror = function(err){
        console.log(`WebSocket error ${err}. Retrying in 3 seconds...`);
        socket.close();
        setTimeout(startClient, 3000);
    }
}


