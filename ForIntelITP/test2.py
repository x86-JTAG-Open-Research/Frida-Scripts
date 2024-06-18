import frida

session = None

def on_message(message, data):
    print("%s: %s" % (message, data))

def on_detached(reason):
    print("Detached from %s: %s" % (session, reason))

def attach(pid):
    global session
    session = frida.attach(pid)
    script = session.create_script("""
        const resolver = new ApiResolver('module');
        const matches = resolver.enumerateMatches('exports:xerces-c_*_*.dll!??0MemBufInputSource@xercesc_*_*@@QAE@QBE*QBD_NQAVMemoryManager@1@@Z');

        var callCounter = 0;

        Interceptor.attach(matches[0].address, {
            onEnter: function(args) {
                send("MemBufInputSource Class Constructor Called");

                this.byteCount = ptr(args[1]).toInt32();
                this.srcDocBytes = ptr(args[0]).readAnsiString(this.byteCount);
                this.outFilePath = Process.getCurrentDir() + "\\\\MemBufInputSource_" + callCounter.toString() + "_" + ptr(args[0]).toString() + ".xml";
                
                File.writeAllText(this.outFilePath, this.srcDocBytes);

                callCounter++;
            }
        });
    """)
    script.on('message', on_message)
    session.on('detached', on_detached)
    script.load()

def detach():
    global session
    if session:
        session.detach()

def main():
    import sys
    if len(sys.argv) != 2:
        print("Usage: %s <process name or PID>" % sys.argv[0])
        sys.exit(1)

    try:
        pid = int(sys.argv[1])
    except ValueError:
        pid = sys.argv[1]
    attach(pid)
    input("Press Enter to detach...\n")
    detach()

if __name__ == '__main__':
    main()
    
