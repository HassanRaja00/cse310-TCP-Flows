import dpkt

class Analyze_PCAP:
    def __init__(self, pcapfile):
        self.__file = pcapfile

    def readFile(self):
        f = self.__file
        tcpflows = 0;
        ports = []
        with open(self.__file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                tcpbytes = buf
                src = int.from_bytes(tcpbytes[34:36], byteorder='big')
                dst = int.from_bytes(tcpbytes[36:38], byteorder='big')
                seqnum = int.from_bytes(tcpbytes[38:42], byteorder='big')
                acknum = int.from_bytes(tcpbytes[42:46], byteorder='big')
                win = int.from_bytes(tcpbytes[48:50], byteorder='big')
                flag = tcpbytes[47]

                if flag == 2:  # if you reach a psh-ack, you are started transactions for a new flow
                    self.addtolist(src, dst, tcpbytes[73], ports)  # add the src, dst and scaling win for new flow


                for flow in ports:  # finding the corresponding flow according to sport or dport
                    if (flow[0] == src and flow[1] == dst) or (flow[1] == src and flow[0] == dst):  # we found the flow of current buffer
                        if flow[3] == 0:
                            flow[3] = ts  # initial time of flow
                        else:
                            flow[4] = ts  # hold for last time
                        flow[5] += 1  # increment packet counter for throughput

                        if flag == 16:  # counting retransmissions due to triple-acks
                            freq = flow[7] # our dict
                            if (acknum in freq):
                                freq[acknum] += 1
                            else:
                                freq[acknum] = 1
                            if freq[acknum] ==3:
                                flow[8] += 1



                        if flow[6] < 2 and flag == 16:  # print only first 2 transactions
                            flow[6] += 1

                            print("Packet " + str(flow[6]))
                            print("Source port: " + str(flow[0]))
                            print("Destination port: " + str(flow[1]))
                            print("Seq number: " + str(seqnum))
                            print("Ack number: " + str(acknum))
                            index = pow(2, flow[2]) * win
                            print("Window size: " + str(index))                # ACK= 16 SYN = 2 FIN = 1
                            print("ACK")
                            print("-------------------------------------------------------")
                        if flag == 17:  # FIN-ACK
                            tcpflows += 1
                            print("port " + str(dst) + ":")
                            print(str(flow[5]) + " packets")
                            print(str(flow[4] - flow[3]) + " is time for RTT")
                            throughput = flow[5] / (flow[4] - flow[3])  # packet num / RTT
                            print("Flow " + str(tcpflows) +  " ended with througput of: " + str(throughput) + " bps")
                            print("There were " + str(flow[8]) + " retransmissions due to triple acks in this flow" )
                            print('=================================================================================\n')






        f.close()
        print("Number of TCP flows: " + str(tcpflows))

    def addtolist(self, sport, dport, scale, list: list) -> list:
        if self.checkDuplicate(sport, dport, list):
            return list
        else:
            newlistitem = [sport, dport, scale, 0, 0, 1, 0, {}, 0]  # 0: sport, 1: dport, 2: scale, 3: ts1, 4: ts2, 5: packnum,
                                                         # 6: transaction counter, 7: dict checking for duplicate acks,
                                                         # 8: num retransmissions
            list.append(newlistitem)

    def checkDuplicate(self, sport, dport,  list: list) -> bool:  # checks if there is a duplicate flow in list
        for i in list:
            if (i[0] == sport and i[1] == dport) or (i[0] == dport and i[1] == sport):
                return True
        return False



if __name__ == "__main__":
    analysisf = Analyze_PCAP('assignment2.pcap')
    analysisf.readFile()
