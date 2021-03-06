from scapy.all import *

class IRC(Packet):
    name = "IRC"
    fields_desc = [ StrField("Prefix", None, fmt = "H"),
                    StrField("Command", None, fmt = "H"),
                    StrField("CommandParameters", None, fmt = "H"),
                    StrField("Trailer", None, fmt = "H"),
                    ]
             
    def do_dissect(self,s):
        elements = self.fields_desc
        cr = chr(0x0D)
        lf = chr(0x0A)
        crlf = str(cr + lf)
        space = chr(0x20)
        a = s.split(crlf)
        for x in a:
            if len(x) > 0:
                if x[0] == ':':
                    prefix = x[1: x.find(space)]
                    x = x.strip(":" + prefix + " ")
                    self.setfieldval(elements[0].name, prefix)
                command = x[:x.find(space)]
                self.setfieldval(elements[1].name, command)
                x = x.strip(command + " ")
                command_parameters = x[:x.find(" :")]
                self.setfieldval(elements[2].name, command_parameters)
                x = x.strip(command_parameters + " ")
                if x.find(" :"):
                    x = x.strip(command_parameters + " :")
                    self.setfieldval(elements[3].name, x)
               
                
        
bind_layers(TCP, IRC)
