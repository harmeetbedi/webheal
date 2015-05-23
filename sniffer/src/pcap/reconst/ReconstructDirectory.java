package pcap.reconst;

import org.apache.log4j.Logger;

import pcap.reconst.reconstructor.JpcapReconstructor;
import pcap.reconst.reconstructor.StreamReassembler;
import pcap.reconst.reconstructor.Reconstructor;

import java.io.File;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ReconstructDirectory {
    private static Logger logger = Logger.getLogger(ReconstructDirectory.class);
    private String inputDirectory;
    private Reconstructor reconstructor;

    public ReconstructDirectory(String inputDirectory, Reconstructor reconstructor) {
        this.reconstructor = reconstructor;
        setInputDirectory(inputDirectory);
    }

    public void setInputDirectory(String inputDirectory) {
        this.inputDirectory = inputDirectory;
    }

    public void listFiles(File dir, List<File> filteredFiles) throws Exception {
        File[] files = dir.listFiles();
        for (File file : files) {
            if (file.getName().endsWith(".reconst")) {
                filteredFiles.add(file);
            }
            if (file.isDirectory()) {
                listFiles(file, filteredFiles);
            }
        }
    }


    public void reconstruct() throws Exception {
        logger.debug("in reconstruct()....");
        File rootDirectory = new File(inputDirectory);
        List<File> filteredFiles = new ArrayList<File>();
        listFiles(rootDirectory, filteredFiles);
        for (File inputFile : filteredFiles) {
            System.out.println(String.format("processing %s", inputFile.getAbsolutePath()));
            logger.debug(String.format("processing %s", inputFile.getAbsolutePath()));
            FileDataReconstructor fileDataReconstructor = new FileDataReconstructor();
            fileDataReconstructor.reconstruct(inputFile, reconstructor);
        }
    }

    public static void main(String[] args) {
        try {
            Set<Integer> set = new HashSet<Integer>();
            set.add(80);
            ReconstructDirectory reconstructDirectory = new ReconstructDirectory(args[0], new JpcapReconstructor(new StreamReassembler(set,false),true));
            reconstructDirectory.reconstruct();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
    }
}