static const char rop_slaveData[] PROGMEM = R"==(

let my_worker = this;

self.onmessage = function (event) {
    event.ports[0].postMessage(1);
}

)==";
