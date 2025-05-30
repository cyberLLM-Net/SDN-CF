package org.onos.FlowParser;

/**
 * TcpState
 */
public class TcpState {
    public enum State {
        START,
        SYN,
        SYNACK,
        ESTABLISHED,
        FIN,
        CLOSED;
    }

    static final long TCP_FIN = 0x01;
    static final long TCP_SYN = 0x02;
    static final long TCP_RST = 0x04;
    static final long TCP_PUSH = 0x08;
    static final long TCP_ACK = 0x10;
    static final long TCP_URG = 0x20;
    static final long TCP_CWE = 0x80;
    static final long TCP_ECE = 0x40;

    private State state;

    public TcpState(State state) {
        this.state = state;
    }

    public State getState(){
        return state;
    }

    public void setState(short flags, int dir, short pktDirection){
        if (tcpSet(TCP_RST, flags)) {
            state = State.CLOSED;
        } else if (tcpSet(TCP_FIN, flags) && (dir == pktDirection)) {
            state = State.FIN;
        } else if (state == State.FIN) {
            if (tcpSet(TCP_ACK, flags) && (dir != pktDirection)) {
                state = State.CLOSED;
            }
        } else if (state == State.START) {
            if (tcpSet(TCP_SYN, flags) && (dir == pktDirection)) {
                state = State.SYN;
            }
        } else if (state == State.SYN) {
            if (tcpSet(TCP_SYN, flags) && tcpSet(TCP_ACK, flags) && (dir != pktDirection)) {
                state = State.SYNACK;
            }
        } else if (state == State.SYNACK) {
            if (tcpSet(TCP_ACK, flags) && (dir == pktDirection)) {
                state = State.ESTABLISHED;
            }
        }
    }

    static boolean tcpSet(long find, short flags) {
        return ((find & flags) == find);
    }
}