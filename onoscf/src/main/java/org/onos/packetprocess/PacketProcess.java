package org.onos.packetprocess;

import org.onlab.packet.*;
import org.onos.FlowDetector.FlowKey;
import org.onos.Classifier.RandomForestClassifier;
import org.onos.FlowParser.CsvExporter;
import org.onos.FlowParser.FlowData;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.*;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.*;

@SuppressWarnings("ALL")
@Component(immediate = true)
public class PacketProcess {

    private static Logger log = LoggerFactory.getLogger(PacketProcess.class);

    private static final int PRIORITY = 2;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    private ApplicationId appId;
    private final PacketProcessor packetProcessor = new sdnPacketProcessor();
    // Record of active data streams
    private HashMap<FlowKey, FlowData> flows = new HashMap<FlowKey, FlowData>();
    private RandomForestClassifier random_forest;

    // Activate the application
    @Activate
    public void activate() throws Exception {
        // Register application and add the process to be launched
        appId = coreService.registerApplication("org.onosproject.packetprocess",
                () -> log.info("Register APP Packet Processor"));

        log.info("RandomForest init");
        random_forest = new RandomForestClassifier(log);
        log.info("RandomForest started");
 
        packetService.addProcessor(packetProcessor, PRIORITY);
        log.info(appId.toString());
        log.info("Started APP Packet Processor with IA");
    }

    // Deactivate the application
    @Deactivate
    public void deactivate() {
        packetService.removeProcessor(packetProcessor);
        flows.clear();
        flowRuleService.removeFlowRulesById(appId);
        log.info("Stopped APP Packet Processor");
    }

    // Process an incoming TCP packet
    private void processTCP(PacketContext context, Ethernet packet) throws Exception {
        // Get characteristics of the packet
        // log.info("[TCP]");
        String predict = "0";
        DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
        IPv4 ipv4 = (IPv4) packet.getPayload();
        int srcIP = ipv4.getSourceAddress();
        int dstIP = ipv4.getDestinationAddress();
        byte proto = ipv4.getProtocol();
        TCP tcp = (TCP) ipv4.getPayload();
        int srcPort = tcp.getSourcePort();
        int dstPort = tcp.getDestinationPort();

        FlowKey forwardKey = new FlowKey(srcIP, srcPort, dstIP, dstPort, proto);
        FlowKey backwardKey = new FlowKey(dstIP, dstPort, srcIP, srcPort, proto);
        FlowData f;
        log.info("Processing TCP packet received from device: {}", deviceId);
        log.info("[TCP] - SrcIP {}, SrcPort {}, DstIP {}, DstPort {}",
                 IPv4.fromIPv4Address(srcIP), srcPort, IPv4.fromIPv4Address(dstIP), dstPort);
                 

        // Check if flow is stored and update it
        if (flows.containsKey(forwardKey) || flows.containsKey(backwardKey)) {
            if (flows.containsKey(forwardKey)) {
                f = flows.get(forwardKey);
            } else {
                f = flows.get(backwardKey);
            }
           // log.info("[TCP] Flow stored");
            f.Add(packet, srcIP);
            //log.info(
            //        "[TCP] FLOW UPDATED: DeviceID {} -- SrcIP {}, SrcPort {}, DstIP {}, DstPort {}, Proto {}, TCPFlags {}",
            //        deviceId, IPv4.fromIPv4Address(srcIP),
            //        srcPort, IPv4.fromIPv4Address(dstIP), dstPort, proto, tcp.getFlags());

            String predict_atributes = f.getParameterPredict(log);
            //log.info("[TCP] Prediction parameters {} ", predict_atributes);

            predict = random_forest.predict(predict_atributes, log);
            //log.info("[TCP] Prediction value {} ", predict);

            if (predict.equals("1")) {
               log.info("[TCP] ANOMALOUS traffic (Flow Stored)");
                // context.block();
            } else {
                log.info("[TCP] NORMAL traffic (Flow Stored)");
            }

        } else {
            f = new FlowData(srcIP, srcPort, dstIP, dstPort, proto, packet);
            //log.info("[TCP] NEW FLOW: DeviceID {} -- SrcIP {}, SrcPort {}, DstIP {}, DstPort {}, Proto {}, TCPFlags {}",
            //        deviceId, IPv4.fromIPv4Address(srcIP),
            //        srcPort, IPv4.fromIPv4Address(dstIP), dstPort, proto, tcp.getFlags());

            String predict_atributes = f.getParameterPredict(log);
            //log.info("[TCP] Prediction parameters {}", predict_atributes);

            predict = random_forest.predict(predict_atributes, log);
            //log.info("[TCP] Prediction value {} ", predict);

            if (predict.equals("1")) {
                log.info("[TCP] ANOMALOUS traffic");
                // context.block();

            } else {
                log.info("[TCP] NORMAL traffic");
            }
            
            flows.put(forwardKey, f);
            flows.put(backwardKey, f);
        }
        // If flow closes, add it to csv "registry" file and same data as logs
        // if (f.IsClosed() || predict.equals("1")) {
        if (f.IsClosed()) {
            f.setLabelValue(predict);
            //log.info(
            //        "[TCP] FLOW CLOSED: DeviceID {} -- SrcIP {}, SrcPort {}, DstIP {}, DstPort {}, Proto {}, TCPFlags {}",
            //        deviceId, IPv4.fromIPv4Address(srcIP),
            //        srcPort, IPv4.fromIPv4Address(dstIP), dstPort, proto, tcp.getFlags());
            flows.remove(forwardKey);
            flows.remove(backwardKey);
            CsvExporter.writeCsv("registry", f.Export());
        }
        //log.info("");
    }

    // Proccess any incoming ICMP packet
    private void processICMP(PacketContext context, Ethernet packet) throws Exception {
        // Get characteristics of the packet
        // log.info("[ICMP]");
        String predict = "0";
        DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
        IPv4 ipv4 = (IPv4) packet.getPayload();
        int srcIP = ipv4.getSourceAddress();
        int dstIP = ipv4.getDestinationAddress();
        byte proto = ipv4.getProtocol();
        int srcPort = 0;
        int dstPort = 0;
        ICMP icmp = (ICMP) ipv4.getPayload();

        FlowKey forwardKey = new FlowKey(srcIP, srcPort, dstIP, dstPort, proto);
        FlowKey backwardKey = new FlowKey(dstIP, dstPort, srcIP, srcPort, proto);
        FlowData f;

        log.info("Processing ICMP packet received from device: {}", deviceId);
        log.info("[ICMP] - SrcIP {}, SrcPort {}, DstIP {}, DstPort {}",
                IPv4.fromIPv4Address(srcIP), srcPort, IPv4.fromIPv4Address(dstIP), dstPort);

        if (flows.containsKey(forwardKey) || flows.containsKey(backwardKey)) {
            if (flows.containsKey(forwardKey)) {
                f = flows.get(forwardKey);
            } else {
                f = flows.get(backwardKey);
            }

            //log.info("[ICMP] Flow stored");
            f.Add(packet, srcIP);

            //log.info(
            //        "[ICMP] FLOW UPDATED: DeviceID {} -- SrcIP {}, SrcPort {}, DstIP {}, DstPort {}, Proto {}, ICMPtype {}",
            //        deviceId, IPv4.fromIPv4Address(srcIP),
            //        srcPort, IPv4.fromIPv4Address(dstIP), dstPort, proto, icmp.getIcmpType());

            String predict_atributes = f.getParameterPredict(log);
            //log.info("[ICMP] Prediction parameters {}", predict_atributes);

            predict = random_forest.predict(predict_atributes, log);
            //log.info("[ICMP] Prediction value {}  ", predict);

            if (predict.equals("1")) {
                log.info("[ICMP] ANOMALOUS traffic (Flow Stored)");
                // context.block();
            } else {
                log.info("[ICMP] NORMAL traffic (Flow Stored)");
            }

        } else {
            f = new FlowData(srcIP, srcPort, dstIP, dstPort, proto, packet);
            //log.info(
            //        "[ICMP] NEW FLOW: DeviceID {} -- SrcIP {}, SrcPort {}, DstIP {}, DstPort {}, Proto {}, ICMPtype {}",
            //        deviceId, IPv4.fromIPv4Address(srcIP),
            //        srcPort, IPv4.fromIPv4Address(dstIP), dstPort, proto, icmp.getIcmpType());

            String predict_atributes = f.getParameterPredict(log);
            // log.info("[ICMP] Prediction parameters {}", predict_atributes);

            predict = random_forest.predict(predict_atributes, log);
            // log.info("[ICMP] Prediction value {} ", predict);

            if (predict.equals("1")) {
               log.info("[ICMP] ANOMALOUS traffic");
                // context.block();
            } else {
                log.info("[ICMP] NORMAL traffic");
            }
            flows.put(forwardKey, f);
            flows.put(backwardKey, f);
        }
        // If flow closes, add it to csv "registry" file and same data as logs
        // if (f.IsClosed() || predict.equals("1")) {
        if (f.IsClosed()) {
            f.setLabelValue(predict);
            //log.info(
            //        "[ICMP] FLOW CLOSED: DeviceID {} -- SrcIP {}, SrcPort {}, DstIP {}, DstPort {}, Proto {}, ICMPtype {}",
            //        deviceId, IPv4.fromIPv4Address(srcIP),
            //        srcPort, IPv4.fromIPv4Address(dstIP), dstPort, proto, icmp.getIcmpType());
            flows.remove(forwardKey);
            flows.remove(backwardKey);
            CsvExporter.writeCsv("registry", f.Export());
        }
        //log.info("");
    }

    // Process any incoming UDP packet
    private void processUDP(PacketContext context, Ethernet packet) throws Exception {
        // Get characteristics of the packet
        //log.info("[UDP]");
        String predict = "0";
        DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
        IPv4 ipv4 = (IPv4) packet.getPayload();
        int srcIP = ipv4.getSourceAddress();
        int dstIP = ipv4.getDestinationAddress();
        byte proto = ipv4.getProtocol();
        UDP udp = (UDP) ipv4.getPayload();
        int srcPort = udp.getSourcePort();
        int dstPort = udp.getDestinationPort();
        
        // Not registry DNS traffic
        if ( (srcPort == 53) || (dstPort == 53)) return;

        FlowKey forwardKey = new FlowKey(srcIP, srcPort, dstIP, dstPort, proto);
        FlowKey backwardKey = new FlowKey(dstIP, dstPort, srcIP, srcPort, proto);
        FlowData f;

        log.info("Processing UDP packet received from device: {}", deviceId);
        log.info("[UDP] - SrcIP {}, SrcPort {}, DstIP {}, DstPort {}",
                IPv4.fromIPv4Address(srcIP), srcPort, IPv4.fromIPv4Address(dstIP), dstPort);

        // Check if flow is stored and update it
        if (flows.containsKey(forwardKey) || flows.containsKey(backwardKey)) {
            if (flows.containsKey(forwardKey)) {
                f = flows.get(forwardKey);
            } else {
                f = flows.get(backwardKey);
            }
            //log.info("[UDP] Flow stored");
            f.Add(packet, srcIP);
            //log.info("[UDP] FLOW UPDATED: DeviceID {} -- SrcIP {}, SrcPort {}, DstIP {}, DstPort {}, Proto {}",
            //        deviceId, IPv4.fromIPv4Address(srcIP),
            //        srcPort, IPv4.fromIPv4Address(dstIP), dstPort, proto);

            String predict_atributes = f.getParameterPredict(log);
            //log.info("[UDP] Prediction parameters {}", predict_atributes);

            predict = random_forest.predict(predict_atributes, log);
            //log.info("[UDP] Prediction value {} ", predict);

            if (predict.equals("1")) {
                log.info("[UDP] ANOMALOUS traffic (Flow Stored)");
                // context.block();
            } else {
                log.info("[UDP] NORMAL traffic (Flow Stored)");
            }

        } else {
            f = new FlowData(srcIP, srcPort, dstIP, dstPort, proto, packet);
            //log.info("[UDP] NEW FLOW: DeviceID {} -- SrcIP {}, SrcPort {}, DstIP {}, DstPort {}, Proto {}", deviceId,
            //        IPv4.fromIPv4Address(srcIP),
            //        srcPort, IPv4.fromIPv4Address(dstIP), dstPort, proto);

            String predict_atributes = f.getParameterPredict(log);
            //log.info("[UDP] Prediction parameters {} ", predict_atributes);

            predict = random_forest.predict(predict_atributes, log);
            //log.info("[UDP] Prediction value {}  ", predict);

            if (predict.equals("1")) {
                log.info("[UDP] ANOMALOUS traffic");
                // context.block();
            } else {
                log.info("[UDP] NORMAL traffic");
            }
            flows.put(forwardKey, f);
            flows.put(backwardKey, f);

        }
        // If flow closes, add it to csv "registry" file and same data as logs
        // if (f.IsClosed() || predict.equals("1")) {
        if (f.IsClosed()) {
            f.setLabelValue(predict);
            //log.info("[UDP] FLOW CLOSED: DeviceID {} -- SrcIP {}, SrcPort {}, DstIP {}, DstPort {}, Proto {}", deviceId,
            //        IPv4.fromIPv4Address(srcIP),
            //        srcPort, IPv4.fromIPv4Address(dstIP), dstPort, proto);
            flows.remove(forwardKey);
            flows.remove(backwardKey);
            CsvExporter.writeCsv("registry", f.Export());
        }
        //log.info("");
    }

    // Indicates whether the specified packet corresponds to ICMP.
    private boolean isICMP(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV4 &&
                ((IPv4) eth.getPayload()).getProtocol() == IPv4.PROTOCOL_ICMP;
    }

    // Indicates whether the specified packet corresponds to TCP.
    private boolean isTCP(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV4 &&
                ((IPv4) eth.getPayload()).getProtocol() == IPv4.PROTOCOL_TCP;
    }

    // Indicates whether the specified packet corresponds to TCP.
    private boolean isUDP(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV4 &&
                ((IPv4) eth.getPayload()).getProtocol() == IPv4.PROTOCOL_UDP;
    }

    // Intercepts packets
    private class sdnPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            // Get Ethernet header
            //log.info("New packet");
            Ethernet packet = context.inPacket().parsed();
            //log.info(context.toString());
            if (isUDP(packet)) {
                try {
                    //log.info("UDP packet");
                    processUDP(context, packet);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } else if (isICMP(packet)) {
                try {
                    //log.info("ICMP packet");
                    processICMP(context, packet);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } else if (isTCP(packet)) {
                try {
                    //log.info("TCP packet");
                    processTCP(context, packet);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }

}