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
        var counter = 0;

        Interceptor.attach(Module.findExportByName('xerces-c_3_1.dll', '??0MemBufInputSource@xercesc_3_1@@QAE@QBEKQBD_NQAVMemoryManager@1@@Z'), {
            onEnter: function(args) {
                send("MemBufInputSource Class Constructor Called");

                this.outpath = Process.getCurrentDir() + "\\\\MemBufInputSource_" + counter.toString() + "_" + ptr(args[0]).toString() + ".xml";
                
                File.writeAllText(this.outpath, ptr(args[0]).readCString());

                counter++;
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
    
