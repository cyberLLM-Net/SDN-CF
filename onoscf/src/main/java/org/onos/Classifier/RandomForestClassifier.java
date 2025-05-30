package org.onos.Classifier;

// ---------- Java IO ---------
import java.io.IOException;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Arrays;
import java.io.File;
//----------- Weka ---------
import weka.core.Instances;
import weka.classifiers.Evaluation;
import weka.classifiers.trees.RandomForest;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.converters.ArffLoader;
import weka.filters.Filter;
import weka.filters.supervised.instance.StratifiedRemoveFolds;
import org.slf4j.Logger;

public class RandomForestClassifier {
    public static String filename = "//root//onos//apache-karaf-4.2.8//csv//dataset.arff";
    public static RandomForest random_forest_classifier;
    private static Instances training_data;
    private static Instances test_data;
    private static int num_atributes;

    public RandomForestClassifier(Logger log) throws Exception {
        Instances all_data = get_training_data();
        splitDataset(all_data);
        randomForestCreation();
        testEvaluation(log);
    }

    private void testEvaluation(Logger log) throws Exception {
        Evaluation eval = new Evaluation(test_data);
        eval.evaluateModel(random_forest_classifier, test_data);

        // Confusion matrix
        log.info(eval.toMatrixString());

        // Precision
        BigDecimal bd_0 = new BigDecimal(String.valueOf(eval.precision(0)));
        BigDecimal rounded = bd_0.setScale(6, RoundingMode.FLOOR);
        log.info("Precision 0: " + rounded);

        BigDecimal bd_1 = new BigDecimal(String.valueOf(eval.precision(1)));
        BigDecimal rounded_1 = bd_1.setScale(6, RoundingMode.FLOOR);
        log.info("Precision 1: " + rounded_1);

        BigDecimal bd_weighted = new BigDecimal(String.valueOf(eval.weightedPrecision()));
        BigDecimal rounded_2 = bd_weighted.setScale(6, RoundingMode.FLOOR);
        log.info("Precision weighted: " + rounded_2);
        log.info("");

        // Recall
        bd_0 = new BigDecimal(String.valueOf(eval.recall(0)));
        rounded = bd_0.setScale(6, RoundingMode.FLOOR);
        log.info("Recall 0: " + rounded);

        bd_1 = new BigDecimal(String.valueOf(eval.recall(1)));
        rounded_1 = bd_1.setScale(6, RoundingMode.FLOOR);
        log.info("Recall 1: " + rounded_1);

        bd_weighted = new BigDecimal(String.valueOf(eval.weightedRecall()));
        rounded_2 = bd_weighted.setScale(6, RoundingMode.FLOOR);
        log.info("Recall weighted: " + rounded_2);
        log.info("");

        // F measure
        bd_0 = new BigDecimal(String.valueOf(eval.fMeasure(0)));
        rounded = bd_0.setScale(6, RoundingMode.FLOOR);
        log.info("F 0: " + rounded);

        bd_1 = new BigDecimal(String.valueOf(eval.fMeasure(1)));
        rounded_1 = bd_1.setScale(6, RoundingMode.FLOOR);
        log.info("F 1: " + rounded_1);

        bd_weighted = new BigDecimal(String.valueOf(eval.weightedFMeasure()));
        rounded_2 = bd_weighted.setScale(6, RoundingMode.FLOOR);
        log.info("F weighted: " + rounded_2);
        log.info("");

        // ROC Area
        bd_0 = new BigDecimal(String.valueOf(eval.areaUnderROC(0)));
        rounded = bd_0.setScale(6, RoundingMode.FLOOR);
        log.info("ROC Area 0: " + rounded);

        bd_1 = new BigDecimal(String.valueOf(eval.areaUnderROC(1)));
        rounded_1 = bd_1.setScale(6, RoundingMode.FLOOR);
        log.info("ROC Area 1: " + rounded_1);

        bd_weighted = new BigDecimal(String.valueOf(eval.weightedAreaUnderROC()));
        rounded_2 = bd_weighted.setScale(6, RoundingMode.FLOOR);
        log.info("ROC Area weighted: " + rounded_2);
        log.info("");

        // PRC Area
        bd_0 = new BigDecimal(String.valueOf(eval.areaUnderPRC(0)));
        rounded = bd_0.setScale(6, RoundingMode.FLOOR);
        log.info("PRC Area 0: " + rounded);

        bd_1 = new BigDecimal(String.valueOf(eval.areaUnderPRC(1)));
        rounded_1 = bd_1.setScale(6, RoundingMode.FLOOR);
        log.info("PRC Area 1: " + rounded_1);

        bd_weighted = new BigDecimal(String.valueOf(eval.weightedAreaUnderPRC()));
        rounded_2 = bd_weighted.setScale(6, RoundingMode.FLOOR);
        log.info("PRC Area weighted: " + rounded_2);
        log.info("");

        // Kappa.
        bd_0 = new BigDecimal(String.valueOf(eval.kappa()));
        rounded = bd_0.setScale(6, RoundingMode.FLOOR);
        log.info("Kappa: " + rounded);
        log.info("");

    }

    public String predict(String parameters_string, Logger log) throws Exception {
        Instances new_input = training_data;
        new_input.delete(); // Clean dataset

        // Create a void instance
        Instance unlabeled = new DenseInstance(num_atributes);

        String[] parameters = parameters_string.split(",");
        int counter = 0;

        for (String parameter : parameters) {
            if (!parameter.isEmpty()) {
                unlabeled.setValue(counter, Long.parseLong(parameter));
            }
            counter = counter + 1;
        }
        new_input.add(unlabeled);
        //log.info("Analizing instance: {}", new_input.lastInstance());
        new_input.setClassIndex(new_input.numAttributes() - 1);

        // label instances
        double prediction = random_forest_classifier.classifyInstance(new_input.lastInstance());

        // get the name of the class value
        String prediction_name = new_input.classAttribute().value((int) prediction);

        double dist[] = random_forest_classifier.distributionForInstance(new_input.lastInstance());

        //log.info("Distribution for instance:");
        int j = 0;
        for (double d : dist) {
            Attribute att = new_input.attribute(new_input.classIndex());
            String classification = att.value(j);
            log.info(d + "  " + classification);
            j++;
        }

        return prediction_name;
    }

    private void randomForestCreation() throws Exception {
        random_forest_classifier = new RandomForest();
        // Train the model
        random_forest_classifier.buildClassifier(training_data);
    }

    private static void splitDataset(Instances data) throws Exception {
        Instances dataset_total = new Instances(data);

        int numFolds = 10;
        StratifiedRemoveFolds stratifiedFilter = new StratifiedRemoveFolds();
        stratifiedFilter.setNumFolds(numFolds);
        stratifiedFilter.setInputFormat(dataset_total);

        // set options for creating the subset of data
        String[] options = new String[2];
        Instances[] folds = new Instances[numFolds];

        for (int i = 0; i < numFolds; i++) {
            options[0] = "-F"; // indicate we want to select a specific fold
            options[1] = Integer.toString(i + 1); // select the fold
            stratifiedFilter.setOptions(options); // set the filter options
            folds[i] = Filter.useFilter(dataset_total, stratifiedFilter);
        }

        test_data = new Instances(folds[0]);
        test_data.addAll(folds[1]);
        test_data.addAll(folds[2]);

        training_data = new Instances(folds[3]);
        training_data.addAll(folds[4]);
        training_data.addAll(folds[5]);
        training_data.addAll(folds[6]);
        training_data.addAll(folds[7]);
        training_data.addAll(folds[8]);
        training_data.addAll(folds[9]);

    }

    private static Instances get_training_data() throws IOException {
        ArffLoader loader = new ArffLoader();
        loader.setFile(new File(filename));
        Instances dataset = loader.getDataSet();

        num_atributes = dataset.numAttributes();
        /* Select last atribute to predict, the label */
        dataset.setClassIndex(num_atributes - 1);
        return dataset;
    }

}
