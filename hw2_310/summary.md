For part 1 of this code, I obtained access to the buffer using dpkt reader.
I found the seq and ack numbers from iterating through the packet buffers and seeing their values.
I obtained the window sizes by finding the scaling factor in the buffer and 
multiplying it by the current window size. I also had a counter for all the 
packets and obtained the value of the first and last time stamps for each flow
so that I could calculate the throughput by doing numPackets / (RTT).
I obtained the retransmissions by creating a dictionary to count the num. times 
a packet is duplicated, and if it equals 3, I incremented my counter for retransmissions.
I counted the number of flows by counting the FINs that occurred