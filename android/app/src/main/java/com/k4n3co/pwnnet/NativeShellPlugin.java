package com.k4n3co.pwnnet;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.BufferedReader;
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
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            StringBuilder errorOutput = new StringBuilder();
            while ((line = errorReader.readLine()) != null) {
                errorOutput.append(line).append("\n");
            }

            int exitCode = process.waitFor();
            
            JSObject ret = new JSObject();
            if (exitCode == 127) {
                ret.put("output", "");
                ret.put("error", "BINARY_NOT_FOUND: The command '" + command.split(" ")[0] + "' was not found on this device. Native tools require root or a pre-installed environment like Termux.");
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
}
