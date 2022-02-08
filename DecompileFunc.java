//TODO write a description for this script
//@author 
//@category FunctionID
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.decompiler.*;
import ghidra.program.model.pcode.*;
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.service.FidService;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.framework.options.SaveState;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import java.io.File;
import java.io.FileReader; 
import java.io.FileWriter; 
import java.io.FileOutputStream;
import java.io.*;
 
import java.io.Serializable;

public class DecompileFunc extends GhidraScript {

    FidService service;
    public void run() throws Exception {
//TODO Add User Code Here
    service = new FidService();

		DomainFolder folder =
			askProjectFolder("Please select a project folder to RECURSIVELY look for a named function:");

		ArrayList<DomainFile> programs = new ArrayList<DomainFile>();
		findPrograms(programs, folder);
		findFunction(programs);
	}

	private void findFunction(ArrayList<DomainFile> programs) {
        String path="F:\\binary_decompile\\ghidra\\openssl_ghidra_json\\";
		for (DomainFile domainFile : programs) {
            if (monitor.isCancelled()) {
                return;
            }
            Map<String, String> dictionary = new HashMap<String, String>();
            DecompInterface ifc = new DecompInterface();
            SaveState ss = new SaveState("foo");
            // println("\n\n"); 
            // println(domainFile.getName());
            Program program = null;
            try {
                program = (Program) domainFile.getDomainObject(this, false, false, monitor);
                FunctionManager functionManager = program.getFunctionManager();
                                ifc.openProgram(program);
                FunctionIterator functions = functionManager.getFunctions(true);
                for (Function function : functions) {
                    if (monitor.isCancelled()) {
                        return;
                    }
                    String funName=function.getName();
                    if(funName.startsWith("_"))
                        continue;
                    DecompileResults res = ifc.decompileFunction(function,0,monitor);
                    ClangTokenGroup tokgroup = res.getCCodeMarkup();
                    String Pcode=tokgroup.toString(); 
                    dictionary.put(funName,Pcode);
                    ss.putString(funName,Pcode);
                    // }
                }
            }
            catch (Exception e) {
                Msg.warn(this, "problem looking at " + domainFile.getName(), e);
            }
            finally {
                if (program != null) {
                    program.release(this);
                }
            }
            String filePath=path+ domainFile.getName() + ".json"; 
             
            try {
                File file = new File(filePath); 
                ss.saveToJsonFile(file);
            } catch (IOException e) {
                e.printStackTrace();
            }
            String data=dictionary.toString();  
		}
	}

	private void findPrograms(ArrayList<DomainFile> programs, DomainFolder folder)
			throws VersionException, CancelledException, IOException {
		DomainFile[] files = folder.getFiles();
		for (DomainFile domainFile : files) {
			if (monitor.isCancelled()) {
				return;
			}
			if (domainFile.getContentType().equals(ProgramContentHandler.PROGRAM_CONTENT_TYPE)) {
				programs.add(domainFile);
			}
		}
		DomainFolder[] folders = folder.getFolders();
		for (DomainFolder domainFolder : folders) {
			if (monitor.isCancelled()) {
				return;
			}
			findPrograms(programs, domainFolder);
		}
	}

}
