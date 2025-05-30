package org.onos.FlowParser;

import org.onlab.packet.Ethernet;
import org.onlab.packet.ICMP;
import org.onlab.packet.IPv4;
import org.onlab.packet.TCP;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.lang.Math;

import org.onos.FlowDetector.FlowKey;

/**
 * FlowData, represents the relevant features of a flow
 */
public class FlowData {

    private static final Logger log = LoggerFactory.getLogger(FlowData.class);

    /**
     * Constants
     */
    static final int IP_ICMP = 1;
    static final int IP_TCP = 6;
    static final int IP_UDP = 17;

    static final int ICMP_ECHO_REPLY = 0;
    static final int ICMP_ECHO_REQUEST = 8;
    static final int ICMP_TIME_EXCEEDED = 11;
    static final int ICMP_DEST_UNREACH = 3;
    static final int ICMP_REDIRECT = 5;

    static final int P_FORWARD = 0;
    static final int P_BACKWARD = 1;

    static final int ADD_SUCCESS = 0;
    static final int ADD_CLOSED = 1;
    static final int ADD_IDLE = 2;

    /**
     * Configurables
     */
    // NOTE: TCP flows are usually terminated upon connection teardown (by FIN
    // packet) while UDP flows are terminated by a flow timeout.
    // The flow timeout value can be assigned arbitrarily by the individual scheme
    // e.g., 600 seconds for both TCP and UDP.
    static final int FLOW_TIMEOUT = 600000; // in milliseconds
    static final int IDLE_THRESHOLD = 10000; // in milliseconds

    /**
     * Features indexes
     */

    // Byte-Based Attributes
    static final int FWD_HDR_LEN = 0; // Total forward header length
    static final int BWD_HDR_LEN = 1; // Total backward header length

    // Packet-Based Attributes
    static final int TOTAL_FWD_PKTS = 2; // Total forward packets
    static final int TOTAL_LEN_FWD_PKTS = 3; // Total forward size
    static final int TOTAL_BWD_PKTS = 4; // Total backward packets
    static final int TOTAL_LEN_BWD_PKTS = 5; // Total backward size
    static final int FWD_PKT_LEN = 6; // Forward packets length
    static final int BWD_PKT_LEN = 7; // Backward packets length
    static final int PKT_LEN = 8; // Total packets length
    static final int PKT_SIZE_AVG = 9; // Average packet size

    // Interarrival Times Attributes
    static final int FLOW_IAT = 10; // Flow interarrival time
    static final int FWD_IAT = 11; // Forward interarrival time
    static final int BWD_IAT = 12; // Backward interarrival time
    static final int DURATION = 13; // Duration of the flow

    // Flow Timers Attributes
    static final int ACTIVE = 14; // Active time before coming idle
    static final int IDLE = 15; // Idle time before coming active

    // Flag-Based Attributes
    static final int FWD_PSH_FLAGS = 16; // Forward PSH count
    static final int BWD_PSH_FLAGS = 17; // Backward PSH count
    static final int FWD_URG_FLAGS = 18; // Forward URG count
    static final int BWD_URG_FLAGS = 19; // Backward URG count
    static final int FIN_FLAG_CNT = 20; // Number of packets with FIN
    static final int SYN_FLAG_CNT = 21; // Number of packets with SYN
    static final int RST_FLAG_CNT = 22; // Number of packets with RST
    static final int PSH_FLAG_CNT = 23; // Number of packets with PSH
    static final int ACK_FLAG_CNT = 24; // Number of packets with ACK
    static final int URG_FLAG_CNT = 25; // Number of packets with URG
    static final int CWE_FLAG_CNT = 26; // Number of packets with CWE
    static final int ECE_FLAG_CNT = 27; // Number of packets with ECE

    // Flow-Based Attributes
    static final int DOWNUP_RATIO = 28; // Download and upload ratio
    static final int FWD_SEG_SIZE_AVG = 29; // Average size observed in the forward direction
    static final int BWD_SEG_SIZE_AVG = 30; // Average size observed in the backward direction
    static final int FWD_BYTES_BULK_AVG = 31; // Average number of bytes bulk rate in the forward direction
    static final int FWD_PKTS_BULK_AVG = 32; // Average number of packets bulk rate in the forward direction
    static final int FWD_BULK_RATE_AVG = 33; // Average number of bulk rate in the forward direction
    static final int BWD_BYTES_BULK_AVG = 33; // Average number of bytes bulk rate in the backward direction
    static final int BWD_PKTS_BULK_AVG = 34; // Average number of packets bulk rate in the backward direction
    static final int BWD_BULK_RATE_AVG = 35; // Average number of bulk rate in the backward direction
    static final int INIT_FWD_WIN_BYTES = 36; // Total number of bytes sent in initial window in forward direction
    static final int INIT_BWD_WIN_BYTES = 37; // Total number of bytes sent in initial window in backward direction
    static final int FWD_ACT_DATA_PKTS = 38; // Count of packets with at least 1 byte of TCP data payload in forward
                                             // direction
    static final int FWD_SEG_SIZE_MIN = 39; // Minimum segment size observed in the forward direction
    static final int FLOW_BYTES_SEC = 40; // Number of flow bytes per second
    static final int FLOW_PKTS_SEC = 41; // Number of flow packets per second
    static final int FWD_PKTS_SEC = 42; // Number of packets sent per second in the forward direction
    static final int BWD_PKTS_SEC = 43; // Number of packets sent per second in the backward direction

    // Subflow-Based Attributes
    static final int SUBFLOW_FWD_PKTS = 44; // Average Sub-flow forward packets
    static final int SUBFLOW_FWD_BYTES = 45; // Average Sub-flow forward bytes
    static final int SUBFLOW_BWD_PKTS = 46; // Average Sub-flow backward packets
    static final int SUBFLOW_BWD_BYTES = 47; // Average Sub-flow backward bytes

    // Number of features
    static final int NUM_FEATURES = 48; // Number of features (there are more including Distributed flow features which
                                        // includes (min,max,avg,std..))

    /**
     * Properties
     */

    // Network-Identifiers Attributes
    public String flowId; // Flow ID
    public int srcIP; // IP address of the source (client)
    public int srcPort; // Port number of the source connection
    public int dstIP; // IP address of the destination (server)
    public int dstPort; // Port number of the destination connection.
    public byte proto; // The IP protocol being used for the connection.
    public long timestamp; // Timestamp of flow
    public String label; // Type of traffic

    public IFlowFeature[] f; // A map of the features to be exported

    public boolean valid; // Has the flow met the requirements of a bi-directional flow
    public long activeStart; // The starting time of the latest activity
    public long firstTime; // The time of the first packet in the flow
    public long fwdLastTime; // The time of the last packet in the forward direction
    public long bwdLastTime; // The time of the last packet in the backward direction

    public TcpState clientTcpState; // Connection state of the client
    public TcpState serverTcpState; // Connection state of the server
    public int icmpState;
    public int udpState;
    public boolean flowTimeout;

    public boolean hasData; // Whether the connection has had any data transmitted.
    public boolean isBidir; // Is the flow bi-directional?
    public short pktDirection; // Direction of the current packet
    public byte dscp; // The first set DSCP field for the flow.

    public FlowKey forwardKey;
    public FlowKey backwardKey;

    // Initialize all features
    public void initParameters() {

        // Byte-Based Attributes
        this.f[FWD_HDR_LEN] = new ValueFlowFeature(0);
        this.f[BWD_HDR_LEN] = new ValueFlowFeature(0);

        // Packet-Based Attributes
        this.f[TOTAL_FWD_PKTS] = new ValueFlowFeature(0);
        this.f[TOTAL_LEN_FWD_PKTS] = new ValueFlowFeature(0);
        this.f[TOTAL_BWD_PKTS] = new ValueFlowFeature(0);
        this.f[TOTAL_LEN_BWD_PKTS] = new ValueFlowFeature(0);
        this.f[FWD_PKT_LEN] = new DistributionFlowFeature(0);
        this.f[BWD_PKT_LEN] = new DistributionFlowFeature(0);
        this.f[PKT_LEN] = new DistributionFlowFeature(0);
        this.f[PKT_SIZE_AVG] = new ValueFlowFeature(0);

        // Interarrival Times Attributes
        this.f[FLOW_IAT] = new DistributionFlowFeature(0);
        this.f[FWD_IAT] = new DistributionFlowFeature(0);
        this.f[BWD_IAT] = new DistributionFlowFeature(0);
        this.f[DURATION] = new ValueFlowFeature(0);

        // Flow Timers Attributes
        this.f[ACTIVE] = new DistributionFlowFeature(0);
        this.f[IDLE] = new DistributionFlowFeature(0);

        // Flag-based Attributes
        this.f[FWD_PSH_FLAGS] = new ValueFlowFeature(0);
        this.f[BWD_PSH_FLAGS] = new ValueFlowFeature(0);
        this.f[FWD_URG_FLAGS] = new ValueFlowFeature(0);
        this.f[BWD_URG_FLAGS] = new ValueFlowFeature(0);
        this.f[FIN_FLAG_CNT] = new ValueFlowFeature(0);
        this.f[SYN_FLAG_CNT] = new ValueFlowFeature(0);
        this.f[RST_FLAG_CNT] = new ValueFlowFeature(0);
        this.f[PSH_FLAG_CNT] = new ValueFlowFeature(0);
        this.f[ACK_FLAG_CNT] = new ValueFlowFeature(0);
        this.f[URG_FLAG_CNT] = new ValueFlowFeature(0);
        this.f[CWE_FLAG_CNT] = new ValueFlowFeature(0);
        this.f[ECE_FLAG_CNT] = new ValueFlowFeature(0);

        // Flow-Based Attributes
        this.f[DOWNUP_RATIO] = new ValueFlowFeature(0);
        this.f[FWD_SEG_SIZE_AVG] = new ValueFlowFeature(0);
        this.f[BWD_SEG_SIZE_AVG] = new ValueFlowFeature(0);
        this.f[FWD_BYTES_BULK_AVG] = new ValueFlowFeature(0);
        this.f[FWD_PKTS_BULK_AVG] = new ValueFlowFeature(0);
        this.f[FWD_BULK_RATE_AVG] = new ValueFlowFeature(0);
        this.f[BWD_BYTES_BULK_AVG] = new ValueFlowFeature(0);
        this.f[BWD_PKTS_BULK_AVG] = new ValueFlowFeature(0);
        this.f[BWD_BULK_RATE_AVG] = new ValueFlowFeature(0);
        this.f[INIT_FWD_WIN_BYTES] = new ValueFlowFeature(0);
        this.f[INIT_BWD_WIN_BYTES] = new ValueFlowFeature(0);
        this.f[FWD_ACT_DATA_PKTS] = new ValueFlowFeature(0);
        this.f[FWD_SEG_SIZE_MIN] = new ValueFlowFeature(0);
        this.f[FLOW_BYTES_SEC] = new ValueFlowFeature(0);
        this.f[FLOW_PKTS_SEC] = new ValueFlowFeature(0);
        this.f[FWD_PKTS_SEC] = new ValueFlowFeature(0);
        this.f[BWD_PKTS_SEC] = new ValueFlowFeature(0);

        // Subflow-based Attributes
        this.f[SUBFLOW_FWD_PKTS] = new ValueFlowFeature(0);
        this.f[SUBFLOW_FWD_BYTES] = new ValueFlowFeature(0);
        this.f[SUBFLOW_BWD_PKTS] = new ValueFlowFeature(0);
        this.f[SUBFLOW_BWD_BYTES] = new ValueFlowFeature(0);

        // Traffic type
        this.label = "0";
    }

    // Records the first packet of the flow and save its fwd and bwd key to identify
    // it
    public FlowData(int srcIP, int srcPort, int dstIP, int dstPort, byte proto, Ethernet packet) {

        // ---------------------------------------- First packet in the flow
        // ------------------------------------------//
        IPv4 ipv4 = (IPv4) packet.getPayload();

        // Set forward and backward keys
        this.forwardKey = new FlowKey(srcIP, srcPort, dstIP, dstPort, proto);
        this.backwardKey = new FlowKey(dstIP, dstPort, srcIP, srcPort, proto);

        // Initialize flow data
        // Network-Based Attributes
        this.flowId = this.forwardKey.toString();
        this.srcIP = srcIP;
        this.srcPort = srcPort;
        this.dstIP = dstIP;
        this.dstPort = dstPort;
        this.proto = proto;
        this.dscp = ipv4.getDscp();
        this.timestamp = System.currentTimeMillis();
        this.f = new IFlowFeature[NUM_FEATURES];
        initParameters();

        // Set the packet direction
        this.valid = false;
        this.hasData = false;
        this.pktDirection = P_FORWARD; // Set direction to Forward

        // Initialize hdr and pkt length values in bytes.
        long headerLength = ipv4.getHeaderLength() * 32 / 8;
        long length = ipv4.getTotalLength();

        // Set the packet lengths
        this.f[TOTAL_FWD_PKTS].Add(1);
        this.f[FWD_HDR_LEN].Add(headerLength);
        this.f[TOTAL_LEN_FWD_PKTS].Add(length);
        this.f[FWD_PKT_LEN].Add(length);
        this.f[PKT_LEN].Add(length);

        // Set the packet timestamps
        this.firstTime = this.timestamp;
        this.fwdLastTime = this.timestamp;
        this.activeStart = this.timestamp;

        // Check if packet is TCP and set STATE and initial flags.
        if (this.proto == IPv4.PROTOCOL_TCP) {
            this.clientTcpState = new TcpState(TcpState.State.START);
            this.serverTcpState = new TcpState(TcpState.State.START);

            TCP tcp = (TCP) ipv4.getPayload();
            short flags = tcp.getFlags();
            setTcpFlags(flags, pktDirection);

        }
        // Check if packet is ICMP and set ICMP Type
        else if (this.proto == IPv4.PROTOCOL_ICMP) {
            ICMP icmp = (ICMP) ipv4.getPayload();
            this.icmpState = icmp.getIcmpType();
        }
        // Check if the flow met the requirements of a bi-directional flow
        updateStatus(packet);
    }

    public void setLabelValue(String label_value) {
        this.label = label_value;
    }

    // Records the next packets of the flow
    public int Add(Ethernet packet, int srcIP) {

        // ---------------------------------------- New packet in the flow
        // ------------------------------------------//
        IPv4 ipv4 = (IPv4) packet.getPayload();

        // Set the packet direction
        if (this.srcIP == srcIP) {
            pktDirection = P_FORWARD;
        } else {
            pktDirection = P_BACKWARD;
        }

        // Get hdr and pkt length values in bytes
        long hlen = ipv4.getHeaderLength() * 32 / 8;
        long length = ipv4.getTotalLength();

        // Add the total length of the packet
        f[PKT_LEN].Add(length);

        // Check the protocol
        if (this.proto == IPv4.PROTOCOL_ICMP) {
            ICMP icmp = (ICMP) ipv4.getPayload();
            this.icmpState = icmp.getIcmpType();
        } else if (this.proto == IPv4.PROTOCOL_TCP) {
            TCP tcp = (TCP) ipv4.getPayload();
            short flags = tcp.getFlags();
            addTcpFlags(flags, pktDirection);
        }

        // Get timestamp packet
        long now = System.currentTimeMillis(); // obtain actual time
        long last = getLastTime(); // obtain last time seen packet
        long diff = now - last; // obtain difference between first and last packet

        if (diff > FLOW_TIMEOUT) { // if difference is greater than timeout
            return ADD_IDLE; // return idle (packet set inactive)
        }
        if (now < last) { // if now is less than last
            // log.info("Flow: ignoring reordered packet. {} < {}\n", now, last); //
            return ADD_SUCCESS; // return success
        }
        if (now < firstTime) { // if now is less than first time
            log.error("Current packet is before start of flow. {} < {}\n", now, firstTime); // log error
        }
        if (diff > IDLE_THRESHOLD) {
            f[IDLE].Add(diff);
            // Active time stats - calculated by looking at the previous packet
            // time and the packet time for when the last idle time ended.
            diff = last - activeStart;
            f[ACTIVE].Add(diff);

            fwdLastTime = 0;
            bwdLastTime = 0;
            activeStart = now;
        }

        // Packet is travelling in the forward direction
        if (pktDirection == P_FORWARD) {
            // Packet length
            f[FWD_PKT_LEN].Add(length);
            f[TOTAL_LEN_FWD_PKTS].Add(length);
            f[TOTAL_FWD_PKTS].Add(1);
            f[FWD_HDR_LEN].Add(hlen);

            // Inter-arrival time
            if (fwdLastTime > 0) {
                diff = now - fwdLastTime;
                f[FWD_IAT].Add(diff);

                long diff2 = now - getLastTime();
                f[FLOW_IAT].Add(diff2);
            }

            // Update the last forward packet timestamp
            fwdLastTime = now;

            // Packet is travelling in the backward direction
        } else if (pktDirection == P_BACKWARD) {

            isBidir = true;
            if (dscp == 0) {
                dscp = ipv4.getDscp();
            }
            // Packet lengths
            f[BWD_PKT_LEN].Add(length);
            f[TOTAL_LEN_BWD_PKTS].Add(length);
            f[TOTAL_BWD_PKTS].Add(1);
            f[BWD_HDR_LEN].Add(hlen);

            // Inter-arrival time
            if (bwdLastTime > 0) {
                diff = now - bwdLastTime;
                f[BWD_IAT].Add(diff);

                long diff2 = now - getLastTime();
                f[FLOW_IAT].Add(diff2);
            }
            // Update the last backward packet timestamp
            bwdLastTime = now;
        }

        // Update the status (validity, TCP connection state) of the flow.
        updateStatus(packet);

        if (proto == IP_TCP &&
                clientTcpState.getState() == TcpState.State.CLOSED &&
                serverTcpState.getState() == TcpState.State.CLOSED) {
            return ADD_CLOSED;
        } else if (proto == IP_ICMP && icmpState == ICMP_ECHO_REPLY) {
            return ADD_CLOSED;
        }

        return ADD_SUCCESS;
    }

    public boolean IsClosed() {

        // Close if reached timeout
        if ((this.timestamp - this.getLastTime()) > FLOW_TIMEOUT) {
            return true;
        }
        // Close if ICMP did full connection
        else if (proto == IP_ICMP) {
            return (icmpState == ICMP_ECHO_REPLY || icmpState == ICMP_DEST_UNREACH || icmpState == ICMP_TIME_EXCEEDED);
        } else if (proto == IP_UDP) {
            return true;
        }
        // Close depending on TCP state
        else if (proto == IP_TCP) {
            return clientTcpState.getState() == TcpState.State.CLOSED
                    && serverTcpState.getState() == TcpState.State.CLOSED;
        }
        return false;
    }

    private void updateTcpState(Ethernet packet) {
        IPv4 ipv4 = (IPv4) packet.getPayload();
        TCP tcp = (TCP) ipv4.getPayload();
        short flags = tcp.getFlags();
        clientTcpState.setState(flags, P_FORWARD, pktDirection);
        serverTcpState.setState(flags, P_BACKWARD, pktDirection);
    }

    private void updateStatus(Ethernet packet) {

        IPv4 ipv4 = (IPv4) packet.getPayload();
        long length = ipv4.getTotalLength();

        if (proto == IP_UDP || proto == IP_ICMP) {
            if (valid) {// Has the flow met the requirements of a bi-directional flow
                return;
            }
            if (length > 8) { // Have data inside the packet
                hasData = true;
            }
            if (hasData && isBidir) {
                valid = true;
            }
        } else if (proto == IP_TCP) {
            if (!valid) {
                if (clientTcpState.getState() == TcpState.State.ESTABLISHED) {
                    if (length > ipv4.getHeaderLength()) {
                        valid = true;
                    }
                }
            }
            updateTcpState(packet);
        }
    }

    private long getLastTime() {
        if (bwdLastTime == 0) {
            return fwdLastTime;
        }
        if (fwdLastTime == 0) {
            return bwdLastTime;
        }
        return Math.max(fwdLastTime, bwdLastTime);
    }

    // Get DownUp Ratio
    public long getDownUpRatio() {
        if (this.f[TOTAL_LEN_FWD_PKTS].Get() > 0) {
            return (this.f[TOTAL_LEN_BWD_PKTS].Get() / this.f[TOTAL_LEN_FWD_PKTS].Get());
        }
        return 0;
    }

    // Get Forward Average Segment Size
    public long fAvgSegmentSize() {
        if (this.f[FWD_PKT_LEN].Get() != 0) {
            return (this.f[FWD_PKT_LEN].ToArrayList().get(4) / this.f[FWD_PKT_LEN].Get());
        }
        return 0;
    }

    // Get Backward Average Segment Size
    public long bAvgSegmentSize() {
        if (this.f[BWD_PKT_LEN].Get() != 0) {
            return (this.f[BWD_PKT_LEN].ToArrayList().get(4) / this.f[BWD_PKT_LEN].Get());
        }
        return 0;
    }

    // Get flow bytes per second
    public long getflowBytesPerSecond() {
        long totalFlowBytes = f[TOTAL_LEN_FWD_PKTS].Get() + f[TOTAL_LEN_BWD_PKTS].Get();
        double duration = this.getLastTime() - this.firstTime;
        if (duration > 0) {
            return (long) ((double) totalFlowBytes / (duration / 1000));
        } else
            return 0;
    }

    // Get flow packets per second
    public long getflowPktsPerSecond() {
        long totalFlowPackets = f[TOTAL_FWD_PKTS].Get() + f[TOTAL_BWD_PKTS].Get();
        double duration = this.getLastTime() - this.firstTime;
        if (duration > 0) {
            return (long) ((double) totalFlowPackets / (duration / 1000));
        } else
            return 0;
    }

    // Get forward packets per second
    public long getfwdPktsPerSecond() {
        double duration = this.getLastTime() - this.firstTime;
        if (duration > 0) {
            return (long) ((double) this.f[TOTAL_FWD_PKTS].Get() / (duration / 1000));
        } else
            return 0;
    }

    // Get backward packets per second
    public long getbwdPktsPerSecond() {
        double duration = this.getLastTime() - this.firstTime;
        if (duration > 0) {
            return (long) ((double) this.f[TOTAL_BWD_PKTS].Get() / (duration / 1000));
        } else
            return 0;
    }

    // Se comprueba con una operacion de & si tiene el state concreto
    public void setTcpFlags(short flags, int pktDirection) {

        if (pktDirection == P_FORWARD) {
            if (TcpState.tcpSet(TcpState.TCP_PUSH, flags)) {
                f[FWD_PSH_FLAGS].Set(1);
            }
            if (TcpState.tcpSet(TcpState.TCP_URG, flags)) {
                f[FWD_URG_FLAGS].Set(1);
            }
        } else if (pktDirection == P_BACKWARD) {
            if (TcpState.tcpSet(TcpState.TCP_PUSH, flags)) {
                f[BWD_PSH_FLAGS].Set(1);
            }
            if (TcpState.tcpSet(TcpState.TCP_URG, flags)) {
                f[BWD_URG_FLAGS].Set(1);
            }
        }
        if (TcpState.tcpSet(TcpState.TCP_FIN, flags)) {
            this.f[FIN_FLAG_CNT].Set(1);
        }
        if (TcpState.tcpSet(TcpState.TCP_SYN, flags)) {
            this.f[SYN_FLAG_CNT].Set(1);
        }
        if (TcpState.tcpSet(TcpState.TCP_RST, flags)) {
            this.f[RST_FLAG_CNT].Set(1);
        }
        if (TcpState.tcpSet(TcpState.TCP_PUSH, flags)) {
            this.f[PSH_FLAG_CNT].Set(1);
        }
        if (TcpState.tcpSet(TcpState.TCP_ACK, flags)) {
            this.f[ACK_FLAG_CNT].Set(1);
        }
        if (TcpState.tcpSet(TcpState.TCP_URG, flags)) {
            this.f[URG_FLAG_CNT].Set(1);
        }
        if (TcpState.tcpSet(TcpState.TCP_CWE, flags)) {
            this.f[CWE_FLAG_CNT].Set(1);
        }
        if (TcpState.tcpSet(TcpState.TCP_ECE, flags)) {
            this.f[ECE_FLAG_CNT].Set(1);
        }
    }

    public void addTcpFlags(short flags, int pktDirection) {

        if (pktDirection == P_FORWARD) {
            if (TcpState.tcpSet(TcpState.TCP_PUSH, flags)) {
                f[FWD_PSH_FLAGS].Add(1);
            }
            if (TcpState.tcpSet(TcpState.TCP_URG, flags)) {
                f[FWD_URG_FLAGS].Add(1);
            }
        } else if (pktDirection == P_BACKWARD) {
            if (TcpState.tcpSet(TcpState.TCP_PUSH, flags)) {
                f[BWD_PSH_FLAGS].Add(1);
            }
            if (TcpState.tcpSet(TcpState.TCP_URG, flags)) {
                f[BWD_URG_FLAGS].Add(1);
            }
        }
        if (TcpState.tcpSet(TcpState.TCP_FIN, flags)) {
            f[FIN_FLAG_CNT].Add(1);
        }
        if (TcpState.tcpSet(TcpState.TCP_SYN, flags)) {
            f[SYN_FLAG_CNT].Add(1);
        }
        if (TcpState.tcpSet(TcpState.TCP_RST, flags)) {
            f[RST_FLAG_CNT].Add(1);
        }
        if (TcpState.tcpSet(TcpState.TCP_PUSH, flags)) {
            f[PSH_FLAG_CNT].Add(1);
        }
        if (TcpState.tcpSet(TcpState.TCP_ACK, flags)) {
            f[ACK_FLAG_CNT].Add(1);
        }
        if (TcpState.tcpSet(TcpState.TCP_URG, flags)) {
            f[URG_FLAG_CNT].Add(1);
        }
        if (TcpState.tcpSet(TcpState.TCP_CWE, flags)) {
            f[CWE_FLAG_CNT].Add(1);
        }
        if (TcpState.tcpSet(TcpState.TCP_ECE, flags)) {
            f[ECE_FLAG_CNT].Add(1);
        }
    }

    public String getParameterPredict_RFECV(Logger log) {
    	    	
    	//@ATTRIBUTE Src-Port NUMERIC
        int src_port = this.srcPort;
    	//@ATTRIBUTE Dst-Port NUMERIC
        int dst_port = this.dstPort;
        //@ATTRIBUTE Total-Len-Fwd-Pkts NUMERIC
        long tot_len_fwd_pkts = f[TOTAL_LEN_FWD_PKTS].Get();
    	//@ATTRIBUTE Total-Len-Bwd-Pkts NUMERIC
        long tot_len_bwd_pkts = f[TOTAL_LEN_BWD_PKTS].Get();
        
        
    	//@ATTRIBUTE Fwd-Pkt-Len-Mean NUMERIC
        long fwd_pkt_len_mean = this.f[FWD_PKT_LEN].ToArrayList().get(1);
    	//@ATTRIBUTE Fwd-Pkt-Len-std NUMERIC
        long fwd_pkt_len_std = this.f[FWD_PKT_LEN].ToArrayList().get(3);
        //@ATTRIBUTE Pkt-Len-Mean NUMERIC
        long pkt_len_mean = f[PKT_LEN].ToArrayList().get(1);
        //@ATTRIBUTE Pkt-Len-Max NUMERIC
        long pkt_len_max = f[PKT_LEN].ToArrayList().get(2);
        
        
        //@ATTRIBUTE Flow-IAT-Min NUMERIC
        long flow_IAT_min = f[FLOW_IAT].ToArrayList().get(0);
    	//@ATTRIBUTE Fwd-IAT-Min NUMERIC
        long fwd_IAT_min = f[FWD_IAT].ToArrayList().get(0);       
    	//@ATTRIBUTE Bwd-IAT-Min NUMERIC
        long bwd_IAT_min = f[BWD_IAT].ToArrayList().get(0);
        
        
    	//@ATTRIBUTE FIN-Flag-Cnt NUMERIC
        long fin_flag_cnt = this.f[FIN_FLAG_CNT].Get();
    	//@ATTRIBUTE Flow-Byts/s NUMERIC
        long flow_bytes_sec = this.f[FLOW_BYTES_SEC].Get();

    	

        String data = 
        		src_port + "," + dst_port + "," + tot_len_fwd_pkts + "," + tot_len_bwd_pkts + ","
                + fwd_pkt_len_mean + "," + fwd_pkt_len_std + "," + pkt_len_mean + "," + pkt_len_max + ","
                + flow_IAT_min + "," + fwd_IAT_min + "," + bwd_IAT_min + "," 
                + fin_flag_cnt + "," + flow_bytes_sec; 

        return data;
    }

 public String getParameterPredict(Logger log) {
    	
    	//@ATTRIBUTE Src-Port NUMERIC
        int src_port = this.srcPort;
    	//@ATTRIBUTE Dst-Port NUMERIC
        int dst_port = this.dstPort;
        //@ATTRIBUTE Total-Len-Fwd-Pkts NUMERIC
        long tot_len_fwd_pkts = f[TOTAL_LEN_FWD_PKTS].Get();
    	//@ATTRIBUTE Total-Len-Bwd-Pkts NUMERIC
        long tot_len_bwd_pkts = f[TOTAL_LEN_BWD_PKTS].Get();
        
        
    	//@ATTRIBUTE Fwd-Pkt-Len-Min NUMERIC
        long fwd_pkt_len_min = this.f[FWD_PKT_LEN].ToArrayList().get(0);
    	//@ATTRIBUTE Pkt-Len-Mean NUMERIC
        long pkt_len_mean = f[PKT_LEN].ToArrayList().get(1);
    	//@ATTRIBUTE Flow-IAT-Min NUMERIC
        long flow_IAT_min = f[FLOW_IAT].ToArrayList().get(0);
    	//@ATTRIBUTE Fwd-IAT-Min NUMERIC
        long fwd_IAT_min = f[FWD_IAT].ToArrayList().get(0);
        
        
    	//@ATTRIBUTE Bwd-IAT-Mean NUMERIC
        long bwd_IAT_mean = f[BWD_IAT].ToArrayList().get(1);
    	//@ATTRIBUTE Fwd-PSH-Flags NUMERIC
        long fwd_psh_flags = this.f[FWD_PSH_FLAGS].Get();
    	//@ATTRIBUTE PSH-Flag-Cnt NUMERIC
        long psh_flag_cnt = this.f[PSH_FLAG_CNT].Get();
    	//@ATTRIBUTE ACK-Flag-Cnt NUMERIC
        long ack_flag_cnt = this.f[ACK_FLAG_CNT].Get();

    	

        String data = 
        		src_port + "," + dst_port + "," + tot_len_fwd_pkts + "," + tot_len_bwd_pkts + ","
                + fwd_pkt_len_min + "," + pkt_len_mean + "," + flow_IAT_min + "," + fwd_IAT_min + ","
                + bwd_IAT_mean + "," + fwd_psh_flags + "," + psh_flag_cnt + "," + ack_flag_cnt; 

        return data;
    }
    
    public String getParameterPredict_ONOS1(Logger log) {
    	
    	//@attribute 'Flow-id' string
        //String flow_id = this.flowId;
    	//@attribute 'Src-Port' numeric
        int src_port = this.srcPort;
    	//@attribute 'Timestamp' numeric
        long timestamp = this.timestamp;        
    	//@attribute 'Total-Len-Fwd-Pkts' numeric
        long tot_len_fwd_pkts = f[TOTAL_LEN_FWD_PKTS].Get();
    	//@attribute 'Fwd-Pkt-Len-Mean' numeric
        long fwd_pkt_len_mean = this.f[FWD_PKT_LEN].ToArrayList().get(1);
    	//@attribute 'Fwd-Pkt-Len-Max' numeric
        long fwd_pkt_len_max = this.f[FWD_PKT_LEN].ToArrayList().get(2);
    	//@attribute 'Pkt-Len-Mean' numeric
        long pkt_len_mean = f[PKT_LEN].ToArrayList().get(1);
    	//@attribute 'Pkt-Len-Max' numeric
        long pkt_len_max = f[PKT_LEN].ToArrayList().get(2);
    	//@attribute 'Pkt-Size-Avg' numeric
        long pkt_len_avg = (long) Math.sqrt(f[PKT_LEN].ToArrayList().get(3));
    	//@attribute 'RST-Flag-Cnt' numeric
        long rst_flag_cnt = this.f[RST_FLAG_CNT].Get();
    	//@attribute 'ACK-Flag-Cnt' numeric
        long ack_flag_cnt = this.f[ACK_FLAG_CNT].Get();
    	//@attribute 'Fwd-Seg-Size-Avg' numeric
        long flow_seg_avg = f[FWD_SEG_SIZE_AVG].Get();
    	//@attribute 'Subflow-Fwd-Bytes' numeric
        long subflow_fwd_bytes = f[SUBFLOW_FWD_BYTES].Get();
    	

        String data = 
        		src_port + "," + timestamp + "," + tot_len_fwd_pkts + "," + fwd_pkt_len_mean + ","
                + fwd_pkt_len_max + "," + pkt_len_mean + "," + pkt_len_max + "," + pkt_len_avg + ","
                + rst_flag_cnt + "," + ack_flag_cnt + "," + flow_seg_avg + "," + subflow_fwd_bytes; 

        return data;
    }

    public String getParameterPredict_Oscar(Logger log) {
        // @attribute 'Dst Port' numeric
        int dst_port = this.dstPort;
        // @attribute 'TotLen Bwd Pkts' numeric
        long tot_len_bwd_pkts = f[TOTAL_LEN_BWD_PKTS].Get();
        // @attribute 'Fwd Pkt Len Max' numeric
        long fwd_pkt_len_max = this.f[FWD_PKT_LEN].ToArrayList().get(2);
        // @attribute 'Fwd Pkt Len Min' numeric
        long fwd_pkt_len_min = this.f[FWD_PKT_LEN].ToArrayList().get(2);
        // @attribute 'Flow IAT Mean' numeric
        long flow_IAT_Mean = f[FLOW_IAT].ToArrayList().get(1);
        // @attribute 'Flow IAT Min' numeric
        long flow_IAT_Min = f[FLOW_IAT].ToArrayList().get(0);
        // @attribute 'Bwd IAT Min' numeric
        long bwd_IAT_min = f[BWD_IAT].ToArrayList().get(0);
        // @attribute 'Fwd Pkts/s' numeric
        long fwd_pakts_per_second = getfwdPktsPerSecond();
        // @attribute 'Bwd Pkts/s' numeric
        long bwd_pakts_per_second = getbwdPktsPerSecond();
        // @attribute 'Pkt Len Max' numeric
        long pkt_len_max = f[PKT_LEN].ToArrayList().get(2);
        // @attribute 'Pkt Len Var' numeric
        long pkt_len_var = (long) Math.sqrt(f[PKT_LEN].ToArrayList().get(3));
        // @attribute 'FIN Flag Cnt' numeric
        long fin_flag_cnt = this.f[FIN_FLAG_CNT].Get();
        // @attribute 'ACK Flag Cnt' numeric
        long ack_flag_cnt = this.f[ACK_FLAG_CNT].Get();
        // @attribute 'Init Bwd Win Byts' numeric
        long init_bwd_win_byts = f[INIT_BWD_WIN_BYTES].Get();
        // @attribute 'Active Std' numeric
        long active_std = f[ACTIVE].ToArrayList().get(3);
        // @attribute 'Dst 192.168.3.' {0,1}
        int dst_192_168_3 = 0;
        // @attribute 'Dst 200.175.2.' {0,1}
        int dst_200_175_2 = 0;
        // @attribute 'Dst 192.168.20.' {0,1}
        int dst_192_168_20 = 0;
        // @attribute 'Src 192.168.3.' {0,1}
        int src_192_168_3 = 0;
        // @attribute 'Src 200.175.2.' {0,1}
        int src_200_175_2 = 0;
        // @attribute 'Src 192.168.20.' {0,1}
        int src_192_168_20 = 0;
        String[] src_IP_split = IPv4.fromIPv4Address(srcIP).split("\\.");
        String[] dst_IP_split = IPv4.fromIPv4Address(dstIP).split("\\.");
        
        

        switch (src_IP_split[0] + "." + src_IP_split[1] + "." + src_IP_split[2]) {
            case "192.168.3":
                src_192_168_3 = 1;
                break;
            case "192.168.20":
                src_192_168_20 = 1;
                break;
            case "200.175.2":
                src_200_175_2 = 1;
                break;
            default:
        }

        switch (dst_IP_split[0] + "." + dst_IP_split[1] + "." + dst_IP_split[2]) {
            case "192.168.3":
                dst_192_168_3 = 1;
                break;
            case "192.168.20":
                dst_192_168_20 = 1;
                break;
            case "200.175.2":
                dst_200_175_2 = 1;
                break;
            default:
        }

        String data = dst_port + "," + tot_len_bwd_pkts + "," + fwd_pkt_len_max + "," + fwd_pkt_len_min + ","
                + flow_IAT_Mean + "," + flow_IAT_Min + "," + bwd_IAT_min + "," + fwd_pakts_per_second + ","
                + bwd_pakts_per_second + "," + pkt_len_max + "," + pkt_len_var + "," + fin_flag_cnt + "," + ack_flag_cnt
                + "," + init_bwd_win_byts + "," + active_std + "," + dst_192_168_3 + "," + dst_200_175_2 + ","
                + dst_192_168_20 + "," + src_192_168_3 + "," + src_200_175_2 + "," + src_192_168_20;

        return data;
    }

    
    public String Export() {
        if (!valid) {
        }

        // -----------------------------------
        // First, lets consider the last active time in the calculations in case
        // this changes something.
        // -----------------------------------
        long diff = getLastTime() - activeStart;
        f[ACTIVE].Add(diff);

        // ---------------------------------
        // Update Flow stats which require counters or other final calculations
        // ---------------------------------

        // More sub-flow calculations
        if (f[ACTIVE].Get() > 0) {
            f[SUBFLOW_FWD_PKTS].Set(f[TOTAL_FWD_PKTS].Get() / f[ACTIVE].Get());
            f[SUBFLOW_FWD_BYTES].Set(f[TOTAL_LEN_FWD_PKTS].Get() / f[ACTIVE].Get());
            f[SUBFLOW_BWD_PKTS].Set(f[TOTAL_BWD_PKTS].Get() / f[ACTIVE].Get());
            f[SUBFLOW_BWD_BYTES].Set(f[TOTAL_LEN_BWD_PKTS].Get() / f[ACTIVE].Get());
        }
        f[DURATION].Set(getLastTime() - firstTime);
        if (f[DURATION].Get() < 0) {
            log.error("Duration ({}) < 0", f[DURATION]);
        }

        // Flow Based calculations
        f[DOWNUP_RATIO].Set(getDownUpRatio());
        f[FWD_SEG_SIZE_AVG].Set(fAvgSegmentSize());
        f[BWD_SEG_SIZE_AVG].Set(bAvgSegmentSize());
        f[FLOW_BYTES_SEC].Set(getflowBytesPerSecond());
        f[FLOW_PKTS_SEC].Set(getflowPktsPerSecond());
        f[FWD_PKTS_SEC].Set(getfwdPktsPerSecond());
        f[BWD_PKTS_SEC].Set(getbwdPktsPerSecond());

        // Calculate PKT-SIZE-AVG
        f[PKT_SIZE_AVG].Set((f[TOTAL_LEN_FWD_PKTS].Get() + f[TOTAL_LEN_BWD_PKTS].Get())
                / (f[TOTAL_FWD_PKTS].Get() + f[TOTAL_BWD_PKTS].Get()));
        Date date = new Date(timestamp);
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

        String exported = String.format("\n--Network-Based Attributes--\n" +
                "Flow-id: %s\n" +
                "Src-IP: %s\n" +
                "Src-Port: %d\n" +
                "Dst-IP: %s\n" +
                "Dst-Port: %d\n" +
                "Protocol-Type: %d\n" +
                "Timestamp: %s\n", flowId, IPv4.fromIPv4Address(srcIP), srcPort,
                IPv4.fromIPv4Address(dstIP), dstPort, proto, df.format(date))
                + String.format("\n--Byte-Based Attributes--\n" +
                        "Fwd-Header-Len: %d\n" +
                        "Bwd-Header-Len: %d\n", f[FWD_HDR_LEN].Get(), f[BWD_HDR_LEN].Get())
                +
                String.format("\n--Packet-Based Attributes--\n" +
                        "Total-Fwd-Pkts: %d\n" +
                        "Total-Bwd-Pkts: %d\n" +
                        "Total-Len-Fwd-Pkts: %d\n" +
                        "Total-Len-Bwd-Pkts: %d\n" +
                        "Fwd-Pkt-Len-Min: %s\n" +
                        "Fwd-Pkt-Len-Mean: %s\n" +
                        "Fwd-Pkt-Len-Max: %s\n" +
                        "Fwd-Pkt-Len-Std: %s\n" +
                        "Bwd-Pkt-Len-Min: %s\n" +
                        "Bwd-Pkt-Len-Mean: %s\n" +
                        "Bwd-Pkt-Len-Max: %s\n" +
                        "Bwd-Pkt-Len-Std: %s\n" +
                        "Pkt-Len-Min: %s\n" +
                        "Pkt-Len-Mean: %s\n" +
                        "Pkt-Len-Max: %s\n" +
                        "Pkt-Len-Std: %s\n" +
                        "Pkt-Size-Avg: %s\n", f[TOTAL_FWD_PKTS].Get(), f[TOTAL_BWD_PKTS].Get(),
                        f[TOTAL_LEN_FWD_PKTS].Get(), f[TOTAL_LEN_BWD_PKTS].Get(), f[FWD_PKT_LEN].ToArrayList().get(0),
                        f[FWD_PKT_LEN].ToArrayList().get(1), f[FWD_PKT_LEN].ToArrayList().get(2),
                        f[FWD_PKT_LEN].ToArrayList().get(3),
                        f[BWD_PKT_LEN].ToArrayList().get(0), f[BWD_PKT_LEN].ToArrayList().get(1),
                        f[BWD_PKT_LEN].ToArrayList().get(2),
                        f[BWD_PKT_LEN].ToArrayList().get(3), f[PKT_LEN].ToArrayList().get(0),
                        f[PKT_LEN].ToArrayList().get(1),
                        f[PKT_LEN].ToArrayList().get(2), f[PKT_LEN].ToArrayList().get(3), f[PKT_SIZE_AVG].Get())
                +
                String.format("\n--Interarrival Times Attributes--\n" +
                        "Duration: %s\n" +
                        "Flow-IAT-Min: %s\n" +
                        "Flow-IAT-Mean: %s\n" +
                        "Flow-IAT-Max: %s\n" +
                        "Flow-IAT-Std: %s\n" +
                        "Fwd-IAT-Tot: %s\n" +
                        "Fwd-IAT-Min: %s\n" +
                        "Fwd-IAT-Mean: %s\n" +
                        "Fwd-IAT-Max: %s\n" +
                        "Fwd-IAT-Std: %s\n" +
                        "Bwd-IAT-Tot: %s\n" +
                        "Bwd-IAT-Min: %s\n" +
                        "Bwd-IAT-Mean: %s\n" +
                        "Bwd-IAT-Max: %s\n" +
                        "Bwd-IAT-Std: %s\n", f[DURATION].Get(), f[FLOW_IAT].ToArrayList().get(0),
                        f[FLOW_IAT].ToArrayList().get(1), f[FLOW_IAT].ToArrayList().get(2),
                        f[FLOW_IAT].ToArrayList().get(3),
                        f[FWD_IAT].Get(), f[FWD_IAT].ToArrayList().get(0), f[FWD_IAT].ToArrayList().get(1),
                        f[FWD_IAT].ToArrayList().get(2), f[FWD_IAT].ToArrayList().get(3), f[BWD_IAT].Get(),
                        f[BWD_IAT].ToArrayList().get(0), f[BWD_IAT].ToArrayList().get(1),
                        f[BWD_IAT].ToArrayList().get(2),
                        f[BWD_IAT].ToArrayList().get(3))
                +
                String.format("\n--Flow Timers Attributes--\n" +
                        "Active-Time-Min: %s\n" +
                        "Active-Time-Mean: %s\n" +
                        "Active-Time-Max: %s\n" +
                        "Active-Time-Std: %s\n" +
                        "Idle-Time-Min: %s\n" +
                        "Idle-Time-Mean: %s\n" +
                        "Idle-Time-Max: %s\n" +
                        "Idle-Time-Std: %s\n", f[ACTIVE].ToArrayList().get(0), f[ACTIVE].ToArrayList().get(1),
                        f[ACTIVE].ToArrayList().get(2), f[ACTIVE].ToArrayList().get(3), f[IDLE].ToArrayList().get(0),
                        f[IDLE].ToArrayList().get(1), f[IDLE].ToArrayList().get(2), f[IDLE].ToArrayList().get(3))
                +
                String.format("\n--Flag-based Attributes--\n" +
                        "Fwd-PSH-Flags: %d\n" +
                        "Bwd-PSH-Flags: %d\n" +
                        "Fwd-URG-Flags: %d\n" +
                        "Bwd-URG-Flags: %d\n" +
                        "FIN-Flag-Cnt: %d\n" +
                        "SYN-Flag-Cnt: %d\n" +
                        "RST-Flag-Cnt: %d\n" +
                        "PSH-Flag-Cnt: %d\n" +
                        "ACK-Flag-Cnt: %d\n" +
                        "URG-Flag-Cnt: %d\n" +
                        "CWE-Flag-Cnt: %d\n" +
                        "ECE-Flag-Cnt: %d\n", f[FWD_PSH_FLAGS].Get(), f[BWD_PSH_FLAGS].Get(), f[FWD_URG_FLAGS].Get(),
                        f[BWD_URG_FLAGS].Get(), f[FIN_FLAG_CNT].Get(), f[SYN_FLAG_CNT].Get(), f[RST_FLAG_CNT].Get(),
                        f[PSH_FLAG_CNT].Get(), f[ACK_FLAG_CNT].Get(), f[URG_FLAG_CNT].Get(), f[CWE_FLAG_CNT].Get(),
                        f[ECE_FLAG_CNT].Get())
                +
                String.format("\n--Flow-Based Attributes--\n" +
                        "Down/Up-Ratio: %s\n" +
                        "Fwd-Seg-Size-Avg: %s\n" +
                        "Bwd-Seg-Size-Avg: %s\n" +
                        "Fwd-Byts/b-Avg: %s\n" +
                        "Fwd-Pkts/b-Avg: %s\n" +
                        "Fwd-Blk-Rate-Avg: %s\n" +
                        "Bwd-Byts/b-Avg: %s\n" +
                        "Bwd-Pkts/b-Avg: %s\n" +
                        "Bwd-Blk-Rate-Avg: %s\n" +
                        "Init-Fwd-Win-Byts: %s\n" +
                        "Init-Bwd-Win-Byts: %s\n" +
                        "Fwd-Act-Data-Pkts: %s\n" +
                        "Fwd-Seg-Size-Min: %s\n" +
                        "Flow-Byts/s: %s\n" +
                        "Flow-Pkts/s: %s\n" +
                        "Fwd-Pkts/s: %s\n" +
                        "Bwd-Pkts/s: %s\n", f[DOWNUP_RATIO].Get(), f[FWD_SEG_SIZE_AVG].Get(), f[BWD_SEG_SIZE_AVG].Get(),
                        f[FWD_BYTES_BULK_AVG].Get(), f[FWD_PKTS_BULK_AVG].Get(), f[FWD_BULK_RATE_AVG].Get(),
                        f[BWD_BYTES_BULK_AVG].Get(),
                        f[BWD_PKTS_BULK_AVG].Get(), f[BWD_BULK_RATE_AVG].Get(), f[INIT_FWD_WIN_BYTES].Get(),
                        f[INIT_BWD_WIN_BYTES].Get(), f[FWD_ACT_DATA_PKTS].Get(), f[FWD_SEG_SIZE_MIN].Get(),
                        f[FLOW_BYTES_SEC].Get(),
                        f[FLOW_PKTS_SEC].Get(), f[FWD_PKTS_SEC].Get(), f[BWD_PKTS_SEC].Get())
                +
                String.format("\n--Subflow-based Attributes--\n" +
                        "Subflow-Fwd-Pkts: %s\n" +
                        "Subflow-Fwd-Bytes: %s\n" +
                        "Subflow-Bwd-Pkts: %s\n" +
                        "Subflow-Bwd-Bytes: %s\n", f[SUBFLOW_FWD_PKTS].Get(), f[SUBFLOW_FWD_BYTES].Get(),
                        f[SUBFLOW_BWD_PKTS].Get(),
                        f[SUBFLOW_BWD_BYTES].Get())
                +
                String.format("\n--Traffic Type--\n" +
                        "Label: %s\n", label);

        // log.info(exported);

        String data = 
        		flowId + "," 
        		+ IPv4.fromIPv4Address(srcIP) + "," 
        		+ srcPort + "," 
        		+ IPv4.fromIPv4Address(dstIP)
                + "," 
        		+ dstPort + "," 
                + proto + "," 
        		+ df.format(date) + "," 
                + f[FWD_HDR_LEN].Get() + "," 
        		+ f[BWD_HDR_LEN].Get() + ","
                + f[TOTAL_FWD_PKTS].Get() + "," 
        		+ f[TOTAL_BWD_PKTS].Get() + "," 
                + f[TOTAL_LEN_FWD_PKTS].Get() + "," 
        		+ f[TOTAL_LEN_BWD_PKTS].Get() + ","
                + f[FWD_PKT_LEN].ToArrayList().get(0) + "," 
        		+ f[FWD_PKT_LEN].ToArrayList().get(1) + "," 
                + f[FWD_PKT_LEN].ToArrayList().get(2) + ","
                + f[FWD_PKT_LEN].ToArrayList().get(3) + "," 
                + f[BWD_PKT_LEN].ToArrayList().get(0) + "," 
                + f[BWD_PKT_LEN].ToArrayList().get(1) + ","
                + f[BWD_PKT_LEN].ToArrayList().get(2) + "," 
                + f[BWD_PKT_LEN].ToArrayList().get(3) + "," 
                + f[PKT_LEN].ToArrayList().get(0) + ","
                + f[PKT_LEN].ToArrayList().get(1) + "," 
                + f[PKT_LEN].ToArrayList().get(2) + "," 
                + f[PKT_LEN].ToArrayList().get(3) + "," 
                + f[PKT_SIZE_AVG].Get()
                + "," 
                + f[DURATION].Get() + "," 
                + f[FLOW_IAT].ToArrayList().get(0) + "," 
                + f[FLOW_IAT].ToArrayList().get(1) + "," 
                + f[FLOW_IAT].ToArrayList().get(2) + ","
                + f[FLOW_IAT].ToArrayList().get(3) + "," 
                + f[FWD_IAT].Get() + "," 
                + f[FWD_IAT].ToArrayList().get(0) + "," 
                + f[FWD_IAT].ToArrayList().get(1) + "," 
                + f[FWD_IAT].ToArrayList().get(2) + "," 
                + f[FWD_IAT].ToArrayList().get(3) + "," 
                + f[BWD_IAT].Get() + "," 
                + f[BWD_IAT].ToArrayList().get(0) + "," 
                + f[BWD_IAT].ToArrayList().get(1) + ","
                + f[BWD_IAT].ToArrayList().get(2) + "," 
                + f[BWD_IAT].ToArrayList().get(3) + "," 
                + f[ACTIVE].ToArrayList().get(0) + ","
                + f[ACTIVE].ToArrayList().get(1) + "," 
                + f[ACTIVE].ToArrayList().get(2) + "," 
                + f[ACTIVE].ToArrayList().get(3) + ","
                + f[IDLE].ToArrayList().get(0) + "," 
                + f[IDLE].ToArrayList().get(1) + "," 
                + f[IDLE].ToArrayList().get(2) + "," 
                + f[IDLE].ToArrayList().get(3)
                + "," 
                + f[FWD_PSH_FLAGS].Get() + "," 
                + f[BWD_PSH_FLAGS].Get() + "," 
                + f[FWD_URG_FLAGS].Get() + "," 
                + f[BWD_URG_FLAGS].Get() + "," 
                + f[FIN_FLAG_CNT].Get() + "," 
                + f[SYN_FLAG_CNT].Get() + ","
                + f[RST_FLAG_CNT].Get() + "," 
                + f[PSH_FLAG_CNT].Get() + "," 
                + f[ACK_FLAG_CNT].Get() + "," 
                + f[URG_FLAG_CNT].Get() + ","
                + f[CWE_FLAG_CNT].Get() + "," 
                + f[ECE_FLAG_CNT].Get() + "," 
                + f[DOWNUP_RATIO].Get() + "," 
                + f[FWD_SEG_SIZE_AVG].Get() + ","
                + f[BWD_SEG_SIZE_AVG].Get() + "," 
                + f[FWD_BYTES_BULK_AVG].Get() + "," 
                + f[FWD_PKTS_BULK_AVG].Get() + "," 
                + f[FWD_BULK_RATE_AVG].Get() + ","
                + f[BWD_BYTES_BULK_AVG].Get() + "," 
                + f[BWD_PKTS_BULK_AVG].Get() + "," 
                + f[BWD_BULK_RATE_AVG].Get() + "," 
                + f[INIT_FWD_WIN_BYTES].Get() + ","
                + f[INIT_BWD_WIN_BYTES].Get() + "," 
                + f[FWD_ACT_DATA_PKTS].Get() + "," 
                + f[FWD_SEG_SIZE_MIN].Get() + ","
                + f[FLOW_BYTES_SEC].Get() + "," 
                + f[FLOW_PKTS_SEC].Get() + "," 
                + f[FWD_PKTS_SEC].Get() + "," 
                + f[BWD_PKTS_SEC].Get() + ","
                + f[SUBFLOW_FWD_PKTS].Get() + "," 
                + f[SUBFLOW_FWD_BYTES].Get() + "," 
                + f[SUBFLOW_BWD_PKTS].Get() + "," 
                + f[SUBFLOW_BWD_BYTES].Get() + "," 
                + label;

        return data;

    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof FlowData))
            return false;
        FlowData ref = (FlowData) obj;
        return this.forwardKey.equals(ref.forwardKey) && this.backwardKey.equals(ref.backwardKey);
    }

    @Override
    public int hashCode() {
        return forwardKey.hashCode() + backwardKey.hashCode();
    }

}