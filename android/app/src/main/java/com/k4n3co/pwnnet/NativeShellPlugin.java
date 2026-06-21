package com.k4n3co.pwnnet;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

@CapacitorPlugin(name = "NativeShell")
public class NativeShellPlugin extends Plugin {

    @PluginMethod
    public void execute(PluginCall call) {
        String command = call.getString("command");
        if (command == null) {
            call.reject("Command is required");
            return;
        }

        try {
            String binaryName = command.split(" ")[0];
            Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
            
            final StringBuilder output = new StringBuilder();
            final StringBuilder errorOutput = new StringBuilder();

            Thread outThread = new Thread(() -> readStream(process.getInputStream(), output));
            Thread errThread = new Thread(() -> readStream(process.getErrorStream(), errorOutput));

            outThread.start();
            errThread.start();

            int exitCode = process.waitFor();
            outThread.join(1000);
            errThread.join(1000);

            JSObject ret = new JSObject();
            if (exitCode == 127 || (errorOutput.toString().contains("not found") && output.length() == 0)) {
                ret.put("output", "");
                ret.put("error", "BINARY_NOT_FOUND: The command '" + binaryName + "' was not found. Install Termux then run: pkg install nmap gobuster");
                ret.put("exitCode", 127);
            } else {
                ret.put("output", output.toString());
                ret.put("error", errorOutput.toString());
                ret.put("exitCode", exitCode);
            }
            call.resolve(ret);
        } catch (Exception e) {
            call.reject("Execution failed: " + e.getMessage());
        }
    }

    private void readStream(InputStream is, StringBuilder sb) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
        } catch (Exception e) {
            // ignore
        }
    }
}
