#!/usr/bin/env python

import sys, urllib2, os, tarfile, subprocess, platform, multiprocessing

botanmajor = "1.10"
botanminor = "9"
botanname = "Botan-" + botanmajor + "." + botanminor
botanfile = botanname + ".tgz"
botanurl = "http://botan.randombit.net/releases/" + botanfile
botaninstalldir = "../botan"

def extractTar(file):
    index = file.rfind(".") + 1
    if (index > 0):
        type = file[index:]
        if (type == "tgz"):
            type = "gz"
        print("Extracting " + file + "... as " + type)
        file = tarfile.open(file, "r:" + type)
        file.extractall()
        file.close()
    else:
        print("Unable to extract file: " + file)

def downloadFile(url):
    file_name = url.split('/')[-1]
    u = urllib2.urlopen(url)
    f = open(file_name, 'wb')
    meta = u.info()
    file_size = int(meta.getheaders("Content-Length")[0])
    print "Downloading: %s Bytes: %s" % (file_name, file_size)

    file_size_dl = 0
    block_sz = 8192
    while True:
        buffer = u.read(block_sz)
        if not buffer:
            break

        file_size_dl += len(buffer)
        f.write(buffer)
        status = r"%10d  [%3.2f%%]" % (file_size_dl, file_size_dl * 100. / file_size)
        status = status + chr(8)*(len(status)+1)
        print status,

    f.close()

def runCmd(cmd):
    print("Issue command: " +  " ".join(cmd))
    subprocess.call(cmd)

def configureBotan():
    configCmd = ["./configure.py", "--disable-shared", "--prefix=" + botaninstalldir]
    if (platform.system() == "Windows"):
        configCmd.append("--cc=msvc")
        configCmd.append("--cpu=i386")
    else:
        configCmd.append("--disable-asm")
    runCmd(configCmd)

def buildBotan():
    if (os.path.exists(botaninstalldir) == True):
        shutil.rmtree(botaninstalldir)

    buildCmd = []
    if (platform.system() == "Windows"):
        buildCmd.extend(["nmake"])
    else:
        buildCmd.extend(["make", "-j" + str(multiprocessing.cpu_count() + 1)])
    buildCmd.extend(["clean", "install"])
    runCmd(buildCmd)

def fixupFile(src, dest):
    if (os.path.exists(dest) == True):
        os.unlink(dest)
    os.symlink(src, dest)

def fixupInstall():
    if (platform.system() == "Windows"):
        pass
    else:
        fixupFile("libbotan-" + botanmajor + ".a", "lib/libbotan.a")
        fixupFile("botan-" + botanmajor + "/botan", "include/botan")

def main(argv):
    if (os.path.exists(botanfile) == False):
        downloadFile(botanurl)
    else:
        print("Skip download of Botan archive because the " + botanfile + " already exists")

    if (os.path.exists(botanname) == False):
        extractTar(botanfile)
    else:
        print("Skip extraction of Botan archive because the " + botanname + " directory already exists")
    
    os.chdir(botanname)
    configureBotan()
    buildBotan()
    os.chdir(botaninstalldir)
    fixupInstall()

if __name__ == "__main__":
    main(sys.argv[1:])
