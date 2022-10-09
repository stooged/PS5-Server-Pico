static const char rop_slaveData[] PROGMEM = R"==(

let my_worker = this;

self.onmessage = function (event) {
    event.ports[0].postMessage(1);
}

)==";


// https://github.com/Cryptogenic/PS5-4.03-Kernel-Exploit/blob/main/document/en/ps5/rop_slave.js