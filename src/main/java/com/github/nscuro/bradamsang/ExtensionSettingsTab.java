package com.github.nscuro.bradamsang;

import burp.ITab;
import com.github.nscuro.bradamsang.io.ExecutionResult;
import com.github.nscuro.bradamsang.io.NativeCommandExecutor;
import com.github.nscuro.bradamsang.io.WslCommandExecutor;
import com.github.nscuro.bradamsang.util.BurpLogger;
import com.github.nscuro.bradamsang.util.WslUtils;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.swing.BorderFactory;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.event.ChangeEvent;

public final class ExtensionSettingsTab implements ITab, ExtensionSettingsProvider {

    private final NativeCommandExecutor nativeCommandExecutor;
    private final WslUtils wslUtils;
    private final BurpLogger burpLogger;

    private WslCommandExecutor wslCommandExecutor;

    private String radamsaExecutablePath;
    private int payloadCount;
    private final List<String> samplePaths = new ArrayList<>();
    private List<String> installedWslDistributions;
    private String selectedWslDistribution;
    private boolean wslModeEnabled;

    // UI Components
    private JPanel wrapperPanel;
    private JPanel mainPanel;
    private JButton redetectRadamsaExecutableButton;
    private JList samplesList;
    private JButton addSamplesButton;
    private JButton removeSamplesButton;
    private JButton clearSamplesButton;
    private JTextField radamsaExecutablePathTextField;
    private JSpinner payloadCountSpinner;
    private JComboBox wslDistributionComboBox;
    private JCheckBox enableWslModeCheckBox;
    private JButton redetectWslDistributionsButton;

    public ExtensionSettingsTab(final NativeCommandExecutor nativeCommandExecutor,
                                final BurpLogger burpLogger) {
        this.nativeCommandExecutor = nativeCommandExecutor;
        this.wslUtils = new WslUtils(nativeCommandExecutor);
        this.burpLogger = burpLogger;
    }

    @Override
    public String getTabCaption() {
        return BurpExtension.EXTENSION_NAME;
    }

    @Override
    public Component getUiComponent() {
        // Attempt to auto-configure WSL when available
        try {
            if (wslUtils.isWslAvailable()) {
                installedWslDistributions = wslUtils.getInstalledDistributions();

                if (!installedWslDistributions.isEmpty()) {
                    burpLogger.info("WSL is available and the following distributions have been found: " + installedWslDistributions);

                    enableWslModeCheckBox.setEnabled(true);
                    enableWslModeCheckBox.setSelected(true);

                    wslDistributionComboBox.setEnabled(true);
                    redetectRadamsaExecutableButton.setEnabled(true);

                    wslDistributionComboBox.setModel(new DefaultComboBoxModel(wslUtils.getInstalledDistributions().toArray(new String[0])));
                    selectedWslDistribution = installedWslDistributions.get(0);

                    wslModeEnabled = true;
                    wslCommandExecutor = new WslCommandExecutor(nativeCommandExecutor, selectedWslDistribution);
                    burpLogger.info("WSL mode enabled with distribution " + selectedWslDistribution);
                } else {
                    burpLogger.warn("WSL is available, but no distributions are installed");
                }
            } else {
                burpLogger.info("WSL is not available");
            }
        } catch (IOException e) {
            burpLogger.error(e);
        }

        // General
        redetectRadamsaExecutableButton.addActionListener(action -> redetectRadamsaExecutablePath());

        // Payload generator
        payloadCountSpinner.setModel(new SpinnerNumberModel(1, 0, Integer.MAX_VALUE, 1));
        payloadCountSpinner.addChangeListener(this::onPayloadCountSpinnerStateChanged);
        addSamplesButton.addActionListener(this::onAddSamplesButtonPressed);
        removeSamplesButton.addActionListener(this::onRemoveSamplesButtonPressed);
        clearSamplesButton.addActionListener(this::onClearSamplesButtonPressed);

        // WSL
        redetectWslDistributionsButton.addActionListener(this::onRedetectWslDistributionsButtonClicked);

        redetectRadamsaExecutablePath();

        return $$$getRootComponent$$$();
    }

    @Override
    public Optional<String> getRadamsaExecutablePath() {
        return Optional.ofNullable(radamsaExecutablePath);
    }

    @Override
    public int getPayloadCount() {
        return payloadCount;
    }

    @Override
    public List<String> getSamplePaths() {
        if (wslModeEnabled) {
            return samplePaths.stream()
                    .map(wslUtils::convertToWslPath)
                    .collect(Collectors.toList());
        }

        return samplePaths;
    }

    @Override
    public boolean isWslModeEnabled() {
        return wslModeEnabled;
    }

    @Override
    public Optional<String> getWslDistributionName() {
        return Optional.ofNullable(selectedWslDistribution);
    }

    private void redetectRadamsaExecutablePath() {
        burpLogger.info("searching for Radamsa executable");

        final Optional<String> radamsaPathOptional;

        try {
            radamsaPathOptional = locateRadamsaExecutable();
        } catch (IOException e) {
            radamsaExecutablePath = null;
            burpLogger.error("detecting Radamsa executable path failed", e);

            SwingUtilities.invokeLater(() -> radamsaExecutablePathTextField.setText(null));
            return;
        }

        if (radamsaPathOptional.isPresent()) {
            radamsaExecutablePath = radamsaPathOptional.get();
            burpLogger.info("Radamsa executable found at " + radamsaExecutablePath);

            SwingUtilities.invokeLater(() -> radamsaExecutablePathTextField.setText(radamsaExecutablePath));
        } else {
            radamsaExecutablePath = null;
            burpLogger.warn("could not detect Radamsa executable path");

            SwingUtilities.invokeLater(() -> radamsaExecutablePathTextField.setText(null));
        }
    }

    private Optional<String> locateRadamsaExecutable() throws IOException {
        if (wslUtils.isWslAvailable() && wslModeEnabled) {
            if (wslCommandExecutor == null) {
                burpLogger.error("no wsl command executor set");
                return Optional.empty();
            }

            final ExecutionResult executionResult = wslCommandExecutor.execute(Arrays.asList("which", "radamsa"));

            if (executionResult.getExitCode() != 0) {
                burpLogger.warn("unable to locate Radamsa executable in $PATH of " + selectedWslDistribution);
                return Optional.empty();
            }

            return executionResult.getStdoutOutput().map(String::trim);
        } else {
            return Arrays.stream(System.getenv("PATH").split(Pattern.quote(File.pathSeparator)))
                    .map(Paths::get)
                    .map(path -> path.resolve("radamsa"))
                    .map(Path::toFile)
                    .filter(File::exists)
                    .map(File::toString)
                    .findFirst();
        }
    }

    private void onPayloadCountSpinnerStateChanged(final ChangeEvent changeEvent) {
        payloadCount = ((Number) payloadCountSpinner.getValue()).intValue();
    }

    private void onAddSamplesButtonPressed(final ActionEvent actionEvent) {
        final JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
        fileChooser.setMultiSelectionEnabled(true);
        fileChooser.setFileHidingEnabled(false);

        if (fileChooser.showOpenDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
            Arrays.stream(fileChooser.getSelectedFiles())
                    .map(File::getPath)
                    .filter(path -> !samplePaths.contains(path))
                    .forEach(samplePaths::add);

            SwingUtilities.invokeLater(() -> samplesList.setModel(new DefaultComboBoxModel(samplePaths.toArray(new String[0]))));
        }
    }

    private void onRemoveSamplesButtonPressed(final ActionEvent actionEvent) {
        Arrays.stream(samplesList.getSelectedIndices())
                .forEach(samplePaths::remove);

        SwingUtilities.invokeLater(() -> samplesList.setModel(new DefaultComboBoxModel(samplePaths.toArray(new String[0]))));
    }

    private void onClearSamplesButtonPressed(final ActionEvent actionEvent) {
        samplePaths.clear();

        SwingUtilities.invokeLater(() -> samplesList.setModel(new DefaultComboBoxModel(samplePaths.toArray(new String[0]))));
    }

    private void onRedetectWslDistributionsButtonClicked(final ActionEvent actionEvent) {
        try {
            installedWslDistributions = wslUtils.getInstalledDistributions();
        } catch (IOException e) {
            burpLogger.error("failed to detect available wsl distributions", e);
        }
    }

    {
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        wrapperPanel = new JPanel();
        wrapperPanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel = new JPanel();
        mainPanel.setLayout(new GridLayoutManager(4, 1, new Insets(0, 0, 0, 0), -1, -1));
        wrapperPanel.add(mainPanel, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(1, 3, new Insets(3, 3, 3, 3), -1, -1));
        mainPanel.add(panel1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel1.setBorder(BorderFactory.createTitledBorder("General"));
        final JLabel label1 = new JLabel();
        label1.setText("Radamsa Executable:");
        panel1.add(label1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        radamsaExecutablePathTextField = new JTextField();
        radamsaExecutablePathTextField.setEditable(false);
        panel1.add(radamsaExecutablePathTextField, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        redetectRadamsaExecutableButton = new JButton();
        redetectRadamsaExecutableButton.setText("Redetect");
        panel1.add(redetectRadamsaExecutableButton, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, 1, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        mainPanel.add(spacer1, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(2, 2, new Insets(3, 3, 3, 3), -1, -1));
        mainPanel.add(panel2, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel2.setBorder(BorderFactory.createTitledBorder("Intruder Payload Generator"));
        final JLabel label2 = new JLabel();
        label2.setText("Payload Count:");
        panel2.add(label2, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        payloadCountSpinner = new JSpinner();
        panel2.add(payloadCountSpinner, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        panel2.add(panel3, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JScrollPane scrollPane1 = new JScrollPane();
        scrollPane1.setVerticalScrollBarPolicy(22);
        panel3.add(scrollPane1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        samplesList = new JList();
        scrollPane1.setViewportView(samplesList);
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new GridLayoutManager(4, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel3.add(panel4, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        addSamplesButton = new JButton();
        addSamplesButton.setText("Add ...");
        panel4.add(addSamplesButton, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, 1, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        removeSamplesButton = new JButton();
        removeSamplesButton.setText("Remove");
        panel4.add(removeSamplesButton, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, 1, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        clearSamplesButton = new JButton();
        clearSamplesButton.setText("Clear");
        panel4.add(clearSamplesButton, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, 1, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer2 = new Spacer();
        panel4.add(spacer2, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final JLabel label3 = new JLabel();
        label3.setText("Samples:");
        panel2.add(label3, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel5 = new JPanel();
        panel5.setLayout(new GridLayoutManager(2, 3, new Insets(3, 3, 3, 3), -1, -1));
        mainPanel.add(panel5, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel5.setBorder(BorderFactory.createTitledBorder("WSL"));
        final JLabel label4 = new JLabel();
        label4.setText("Distribution:");
        panel5.add(label4, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        wslDistributionComboBox = new JComboBox();
        wslDistributionComboBox.setEnabled(false);
        panel5.add(wslDistributionComboBox, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        enableWslModeCheckBox = new JCheckBox();
        enableWslModeCheckBox.setEnabled(false);
        enableWslModeCheckBox.setText("Enable WSL mode");
        panel5.add(enableWslModeCheckBox, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        redetectWslDistributionsButton = new JButton();
        redetectWslDistributionsButton.setEnabled(false);
        redetectWslDistributionsButton.setText("Redetect");
        panel5.add(redetectWslDistributionsButton, new GridConstraints(1, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, 1, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer3 = new Spacer();
        wrapperPanel.add(spacer3, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return wrapperPanel;
    }

}
