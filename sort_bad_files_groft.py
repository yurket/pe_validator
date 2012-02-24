r"""usage: <script> [log_file.txt dir_for_sorted_files]

    if no log_file was specified, using log.txt in current dir, 
    if no dir_for_sorted_files was specified, using current dir.
"""
import os 
import shutil
import sys

log_name = "log.txt"
argc = len(sys.argv)
dir_path = ""
if (argc == 2):
    log_name = sys.argv[1]
elif (argc == 3):
    dir_path = sys.argv[2]
elif (argc > 3):
    print "usage: <script> [log_file.txt dir_for_sorted_files]"
    raw_input()

class_names = ["bad", "not_mz", "ok", "pe_16", "pe_64", "unknown"]
dir_names = []
for x in class_names:
    dir_names.append(os.path.join(dir_path, x))

for Dir in dir_names:
    if not os.path.exists(Dir):
        os.mkdir(Dir, 777)

with open(log_name, 'r') as f:
    for line in f:
        for name, Dir in zip(class_names, dir_names):
            if (line.find((" : "+name)) != -1):
                file_name_end = line.find(" : " + name)
                file_name = line[ : file_name_end]
                shutil.copy(file_name, Dir)
        print '.',

for Dir in dir_names:
    if (len(os.listdir(Dir)) == 0):
        os.rmdir(Dir)