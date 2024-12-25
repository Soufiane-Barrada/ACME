from dnslib import DNSRecord, RR, QTYPE, RDMAP, A, TXT
from dnslib.server import DNSServer, DNSHandler, BaseResolver


class MyResolverw(BaseResolver):

    def __init__(self,ipv4,doms):
        self.keyAuths=[]
        self.record=ipv4
        self.domains=doms
        self.count = len(doms)

    def add_keyAuth(self,keyAuth):
        self.keyAuths.append(keyAuth)

    def resolve(self, request, handler):
        reply = request.reply()
        print("DOING SOMETHING!")
        for i in range(self.count):
            if len(self.keyAuths)>0:
                reply.add_answer(RR(self.domains[i], QTYPE.TXT, rdata=TXT(self.keyAuths[i]), ttl=300))
            #print(f"keyauth: {self.keyAuths[i]}")
            reply.add_answer(RR(self.domains[i], QTYPE.A, rdata=A(self.record), ttl=300))
        return reply