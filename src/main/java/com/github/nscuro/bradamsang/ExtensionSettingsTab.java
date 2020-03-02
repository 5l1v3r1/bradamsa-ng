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
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ItemEvent;
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
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JSeparator;
import javax.swing.JSpinner;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.event.ChangeEvent;


import static java.lang.String.format;

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
    private JPanel mainPanel;
    private JTextField radamsaExecutablePathTextField;
    private JButton refreshRadamsaExecutablePathButton;
    private JSpinner payloadCountSpinner;
    private JLabel payloadCountWarningLabel;
    private JComboBox wslDistributionComboBox;
    private JCheckBox enableWslModeCheckBox;
    private JButton refreshWslDistributionsButton;
    private JList samplePathsList;
    private JButton addSamplePathsButton;
    private JButton removeSamplePathButton;
    private JButton clearSamplePathsButton;

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
        try {
            if (wslUtils.isWslAvailable()) {
                installedWslDistributions = wslUtils.getInstalledDistributions();
                if (!installedWslDistributions.isEmpty()) {
                    burpLogger.info("WSL is available and the following distributions have been found: " + installedWslDistributions);

                    enableWslModeCheckBox.setEnabled(true);
                    enableWslModeCheckBox.setSelected(true);

                    wslDistributionComboBox.setEnabled(true);
                    refreshWslDistributionsButton.setEnabled(true);

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

        payloadCountSpinner.setModel(new SpinnerNumberModel(1, 0, Integer.MAX_VALUE, 1));
        payloadCountWarningLabel.setVisible(false);

        refreshRadamsaExecutablePathButton.addActionListener(this::onRefreshRadamsaExecutablePathButtonPressed);
        payloadCountSpinner.addChangeListener(this::onPayloadCountSpinnerStateChanged);

        addSamplePathsButton.addActionListener(this::onAddSamplePathsButtonPressed);
        removeSamplePathButton.addActionListener(this::onRemoveSamplePathButtonPressed);
        clearSamplePathsButton.addActionListener(this::onClearSamplePathsButtonPressed);

        enableWslModeCheckBox.addItemListener(this::onEnableWslModeCheckBoxItemStateChanged);
        wslDistributionComboBox.addItemListener(this::onWslDistributionComboBoxItemStateChanged);
        refreshWslDistributionsButton.addActionListener(this::onRefreshWslDistributionsButtonPressed);

        refreshRadamsaExecutablePath();

        return $$$getRootComponent$$$();
    }

    private void onRefreshRadamsaExecutablePathButtonPressed(final ActionEvent actionEvent) {
        refreshRadamsaExecutablePath();
    }

    private void onPayloadCountSpinnerStateChanged(final ChangeEvent changeEvent) {
        payloadCount = ((Number) payloadCountSpinner.getValue()).intValue();

        SwingUtilities.invokeLater(() -> payloadCountWarningLabel.setVisible(payloadCount <= 0));
    }

    private void onAddSamplePathsButtonPressed(final ActionEvent actionEvent) {
        final JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
        fileChooser.setMultiSelectionEnabled(true);
        fileChooser.setFileHidingEnabled(false);

        if (fileChooser.showOpenDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
            Arrays.stream(fileChooser.getSelectedFiles())
                    .map(File::getPath)
                    .filter(path -> !samplePaths.contains(path))
                    .forEach(samplePaths::add);

            SwingUtilities.invokeLater(() -> samplePathsList.setModel(new DefaultComboBoxModel(samplePaths.toArray(new String[0]))));
        }
    }

    private void onRemoveSamplePathButtonPressed(final ActionEvent actionEvent) {
        Arrays.stream(samplePathsList.getSelectedIndices())
                .forEach(samplePaths::remove);

        SwingUtilities.invokeLater(() -> samplePathsList.setModel(new DefaultComboBoxModel(samplePaths.toArray(new String[0]))));
    }

    private void onClearSamplePathsButtonPressed(final ActionEvent actionEvent) {
        samplePaths.clear();

        SwingUtilities.invokeLater(() -> samplePathsList.setModel(new DefaultComboBoxModel(samplePaths.toArray(new String[0]))));
    }

    private void onEnableWslModeCheckBoxItemStateChanged(final ItemEvent itemEvent) {
        wslModeEnabled = itemEvent.getStateChange() == ItemEvent.SELECTED;

        if (wslModeEnabled) {
            wslCommandExecutor = new WslCommandExecutor(nativeCommandExecutor, selectedWslDistribution);
            burpLogger.info("WSL mode enabled with distribution " + selectedWslDistribution);
        } else {
            wslCommandExecutor = null;
            burpLogger.info("WSL mode disabled");
        }

        refreshRadamsaExecutablePath();
    }

    private void onWslDistributionComboBoxItemStateChanged(final ItemEvent itemEvent) {
        final int selectedDistroIndex = wslDistributionComboBox.getSelectedIndex();

        if (selectedDistroIndex >= installedWslDistributions.size()) {
            burpLogger.error("sdfasdfsdfgsdfg");
            return;
        }

        selectedWslDistribution = installedWslDistributions.get(selectedDistroIndex);
        wslCommandExecutor = new WslCommandExecutor(nativeCommandExecutor, selectedWslDistribution);

        refreshRadamsaExecutablePath();
    }

    private void onRefreshWslDistributionsButtonPressed(final ActionEvent actionEvent) {
        burpLogger.info("Refreshing installed WSL distributions");

        try {
            wslCommandExecutor = null;
            installedWslDistributions = wslUtils.getInstalledDistributions();
            burpLogger.info("Found WSL distributions: " + installedWslDistributions);

            SwingUtilities.invokeLater(() -> {
                wslDistributionComboBox.setModel(new DefaultComboBoxModel(installedWslDistributions.toArray(new String[0])));
            });
        } catch (IOException e) {
            burpLogger.error("Refreshing installed WSL distributions failed", e);
        }
    }

    private void refreshRadamsaExecutablePath() {
        burpLogger.info("Searching for Radamsa executable");

        final Optional<String> radamsaPathOptional;

        try {
            radamsaPathOptional = locateRadamsaExecutable();
        } catch (IOException e) {
            radamsaExecutablePath = null;
            burpLogger.error("Refreshing Radamsa executable path failed", e);

            SwingUtilities.invokeLater(() -> radamsaExecutablePathTextField.setText(null));
            return;
        }

        if (radamsaPathOptional.isPresent()) {
            radamsaExecutablePath = radamsaPathOptional.get();
            burpLogger.info("Radamsa exexutable found at " + radamsaExecutablePath);

            SwingUtilities.invokeLater(() -> radamsaExecutablePathTextField.setText(radamsaExecutablePath));
        } else {
            radamsaExecutablePath = null;
            burpLogger.warn("Could not locate Radamsa executable in $PATH");

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
                burpLogger.warn(format("Unable to locate Radamsa executable in $PATH of %s", selectedWslDistribution));
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
        mainPanel = new JPanel();
        mainPanel.setLayout(new GridLayoutManager(4, 1, new Insets(0, 0, 0, 0), -1, -1));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(1, 3, new Insets(0, 5, 0, 5), -1, -1));
        mainPanel.add(panel1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel1.setBorder(BorderFactory.createTitledBorder("General"));
        final JLabel label1 = new JLabel();
        label1.setText("Radamsa Path:");
        panel1.add(label1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        radamsaExecutablePathTextField = new JTextField();
        radamsaExecutablePathTextField.setEditable(false);
        panel1.add(radamsaExecutablePathTextField, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        refreshRadamsaExecutablePathButton = new JButton();
        refreshRadamsaExecutablePathButton.setText("Redetect");
        panel1.add(refreshRadamsaExecutablePathButton, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        mainPanel.add(spacer1, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(4, 3, new Insets(0, 5, 0, 5), -1, -1));
        mainPanel.add(panel2, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel2.setBorder(BorderFactory.createTitledBorder("Intruder Payload Generator"));
        final JLabel label2 = new JLabel();
        label2.setText("Payload Count:");
        panel2.add(label2, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        payloadCountSpinner = new JSpinner();
        panel2.add(payloadCountSpinner, new GridConstraints(0, 1, 1, 2, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        payloadCountWarningLabel = new JLabel();
        payloadCountWarningLabel.setEnabled(true);
        payloadCountWarningLabel.setForeground(new Color(-39373));
        payloadCountWarningLabel.setText("Values <= 0 are being interpreted as \"infinite\". Be aware that Intruder attacks started with setting must be aborted manually.");
        panel2.add(payloadCountWarningLabel, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label3 = new JLabel();
        label3.setText("Samples:");
        panel2.add(label3, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        samplePathsList = new JList();
        final DefaultListModel defaultListModel1 = new DefaultListModel();
        samplePathsList.setModel(defaultListModel1);
        panel2.add(samplePathsList, new GridConstraints(3, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_WANT_GROW, null, new Dimension(150, 50), null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new GridLayoutManager(3, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel2.add(panel3, new GridConstraints(3, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        addSamplePathsButton = new JButton();
        addSamplePathsButton.setText("Add ...");
        panel3.add(addSamplePathsButton, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        removeSamplePathButton = new JButton();
        removeSamplePathButton.setText("Remove");
        panel3.add(removeSamplePathButton, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        clearSamplePathsButton = new JButton();
        clearSamplePathsButton.setText("Clear");
        panel3.add(clearSamplePathsButton, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JSeparator separator1 = new JSeparator();
        separator1.setForeground(new Color(-4473925));
        panel2.add(separator1, new GridConstraints(2, 0, 1, 3, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new GridLayoutManager(2, 3, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel.add(panel4, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel4.setBorder(BorderFactory.createTitledBorder("Windows Subsystem for Linux"));
        final JLabel label4 = new JLabel();
        label4.setText("Distribution:");
        panel4.add(label4, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        wslDistributionComboBox = new JComboBox();
        wslDistributionComboBox.setEnabled(false);
        panel4.add(wslDistributionComboBox, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        enableWslModeCheckBox = new JCheckBox();
        enableWslModeCheckBox.setEnabled(false);
        enableWslModeCheckBox.setText("Enable WSL mode");
        panel4.add(enableWslModeCheckBox, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        refreshWslDistributionsButton = new JButton();
        refreshWslDistributionsButton.setEnabled(false);
        refreshWslDistributionsButton.setText("Refresh");
        panel4.add(refreshWslDistributionsButton, new GridConstraints(1, 2, 1, 1, GridConstraints.ANCHOR_EAST, GridConstraints.FILL_NONE, 1, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return mainPanel;
    }

}
