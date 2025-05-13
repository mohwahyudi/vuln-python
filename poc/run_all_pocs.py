#!/usr/bin/env python3

import sys
import os
import importlib.util
import time

def load_module(file_path):
    module_name = os.path.basename(file_path).replace('.py', '')
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def run_all_pocs(base_url):
    print("\n" + "=" * 80)
    print("Running All Proof of Concept Exploits".center(80))
    print("=" * 80)
    print(f"Target: {base_url}\n")
    
    # Get all PoC files
    current_dir = os.path.dirname(os.path.abspath(__file__))
    poc_files = [f for f in os.listdir(current_dir) if f.endswith('.py') and f != 'run_all_pocs.py' and f != '__init__.py']
    poc_files.sort()  # Sort to run in numerical order
    
    for poc_file in poc_files:
        print("\n" + "=" * 80)
        print(f"Running: {poc_file}".center(80))
        print("=" * 80 + "\n")
        
        try:
            # Load and run the PoC module
            module = load_module(os.path.join(current_dir, poc_file))
            
            # Find the main function (usually named after the vulnerability)
            main_func = None
            for attr_name in dir(module):
                if attr_name.endswith('_poc') and callable(getattr(module, attr_name)):
                    main_func = getattr(module, attr_name)
                    break
            
            if main_func:
                main_func(base_url)
            else:
                print(f"[-] Could not find PoC function in {poc_file}")
        except Exception as e:
            print(f"[-] Error running {poc_file}: {str(e)}")
        
        # Pause between PoCs to avoid overwhelming the server
        time.sleep(1)
    
    print("\n" + "=" * 80)
    print("All PoCs Completed".center(80))
    print("=" * 80)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <base_url>")
        print(f"Example: {sys.argv[0]} http://localhost:5000")
        sys.exit(1)
        
    base_url = sys.argv[1].rstrip('/')
    run_all_pocs(base_url)