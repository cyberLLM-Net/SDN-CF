package org.onos.FlowParser;

import org.onos.packetprocess.PacketProcess;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** */
public class CsvExporter {

    private static Logger log = LoggerFactory.getLogger(PacketProcess.class);

    public static void writeCsv(String fileName, String data) {
        try {
            // create a list of objects
            List<List<String>> records = List.of(
                    List.of(data));

            String filename = "csv/" + fileName + ".csv";
            Path pathToFile = Paths.get(filename);
            //log.info("pathToFile: " + pathToFile.toAbsolutePath());

            if (!Files.exists(pathToFile) || (Files.exists(pathToFile) && (Files.size(pathToFile) == 0))) {
                log.info("File does not exist or is empty, lets create it");

                // create a writer
                BufferedWriter writer = Files.newBufferedWriter(pathToFile.toAbsolutePath());

                // write header record
                ArrayList<String> columns = new ArrayList<String>();
                columns.add("Flow-id");
                columns.add("Src-IP");
                columns.add("Src-Port");
                columns.add("Dst-IP");
                columns.add("Dst-Port");
                columns.add("Protocol-Type");
                columns.add("Timestamp");
                columns.add("Fwd-Header-Len");
                columns.add("Bwd-Header-Len");
                columns.add("Total-Fwd-Pkts");
                columns.add("Total-Bwd-Pkts");
                columns.add("Total-Len-Fwd-Pkts");
                columns.add("Total-Len-Bwd-Pkts");
                columns.add("Fwd-Pkt-Len-Min");
                columns.add("Fwd-Pkt-Len-Mean");
                columns.add("Fwd-Pkt-Len-Max");
                columns.add("Fwd-Pkt-Len-Std");
                columns.add("Bwd-Pkt-Len-Min");
                columns.add("Bwd-Pkt-Len-Mean");
                columns.add("Bwd-Pkt-Len-Max");
                columns.add("Bwd-Pkt-Len-Std");
                columns.add("Pkt-Len-Min");
                columns.add("Pkt-Len-Mean");
                columns.add("Pkt-Len-Max");
                columns.add("Pkt-Len-Std");
                columns.add("Pkt-Size-Avg");
                columns.add("Duration");
                columns.add("Flow-IAT-Min");
                columns.add("Flow-IAT-Mean");
                columns.add("Flow-IAT-Max");
                columns.add("Flow-IAT-Std");
                columns.add("Fwd-IAT-Tot");
                columns.add("Fwd-IAT-Min");
                columns.add("Fwd-IAT-Mean");
                columns.add("Fwd-IAT-Max");
                columns.add("Fwd-IAT-Std");
                columns.add("Bwd-IAT-Tot");
                columns.add("Bwd-IAT-Min");
                columns.add("Bwd-IAT-Mean");
                columns.add("Bwd-IAT-Max");
                columns.add("Bwd-IAT-Std");
                columns.add("Active-Time-Min");
                columns.add("Active-Time-Mean");
                columns.add("Active-Time-Max");
                columns.add("Active-Time-Std");
                columns.add("Idle-Time-Min");
                columns.add("Idle-Time-Mean");
                columns.add("Idle-Time-Max");
                columns.add("Idle-Time-Std");
                columns.add("Fwd-PSH-Flags");
                columns.add("Bwd-PSH-Flags");
                columns.add("Fwd-URG-Flags");
                columns.add("Bwd-URG-Flags");
                columns.add("FIN-Flag-Cnt");
                columns.add("SYN-Flag-Cnt");
                columns.add("RST-Flag-Cnt");
                columns.add("PSH-Flag-Cnt");
                columns.add("ACK-Flag-Cnt");
                columns.add("URG-Flag-Cnt");
                columns.add("CWE-Flag-Cnt");
                columns.add("ECE-Flag-Cnt");
                columns.add("Down/Up-Ratio");
                columns.add("Fwd-Seg-Size-Avg");
                columns.add("Bwd-Seg-Size-Avg");
                columns.add("Fwd-Byts/b-Avg");
                columns.add("Fwd-Pkts/b-Avg");
                columns.add("Fwd-Blk-Rate-Avg");
                columns.add("Bwd-Byts/b-Avg");
                columns.add("Bwd-Pkts/b-Avg");
                columns.add("Bwd-Blk-Rate-Avg");
                columns.add("Init-Fwd-Win-Byts");
                columns.add("Init-Bwd-Win-Byts");
                columns.add("Fwd-Act-Data-Pkts");
                columns.add("Fwd-Seg-Size-Min");
                columns.add("Flow-Byts/s");
                columns.add("Flow-Pkts/s");
                columns.add("Fwd-Pkts/s");
                columns.add("Bwd-Pkts/s");
                columns.add("Subflow-Fwd-Pkts");
                columns.add("Subflow-Fwd-Bytes");
                columns.add("Subflow-Bwd-Pkts");
                columns.add("Subflow-Bwd-Bytes");
                columns.add("Label");

                writer.write(columns.get(0));
                for (int i = 1; i < columns.size(); i++) {
                    writer.write("," + columns.get(i));
                }
                writer.newLine();

                // write all records
                for (List<String> record : records) {
                    writer.write(String.join(",", record));
                    writer.newLine();
                }
                // close the writer
                writer.close();

            } else if (Files.exists(pathToFile)) {
                //log.info("File exists");
                // create a reader
                BufferedReader br = Files.newBufferedReader(pathToFile.toAbsolutePath());

                if (br.readLine() == null) {
                    log.info("File is empty, remove it");

                } else {
                    //log.info("File is not empty, write next lines");
                    // create filewriter
                    FileWriter fileWriter = new FileWriter(filename, true);
                    BufferedWriter writer = new BufferedWriter(fileWriter);
                    // write all records
                    for (List<String> record : records) {
                        writer.write(String.join(",", record));
                        writer.newLine();
                    }
                    // close the writer
                    writer.close();
                }
            }

        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }
}