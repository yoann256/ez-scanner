# EZ Scanner
<center>Powered by <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/b/b7/VirusTotal_logo.svg/2560px-VirusTotal_logo.svg.png"></center>

> [!NOTE]
> This program uses a free VirusTotal API key, you may get errors beacause the API key has been used too much, to prevent that, you can use **your own VirusTotal API key**.

## Instructions
```bash
./EZ_Scanner <path_to_file>
```

## Downloads

### Linux (just to run)
You can go on the releases page to download the file, you might need to install ''libcurl'' and ''libssl-dev'' by doing:
```bash
sudo apt install libssl-dev
```

### Linux (Compiling)
> [!NOTE]
> You need to make a VirusTotal account to get an API key.

> Step 1 - Changing the code
> You need to change line 13 of scanner.cpp: ```#define VIRUSTOTAL_API_KEY "YOUR_API_KEY"```
> YOUR_API_KEY needs to be changed to your VirusTotal API key. [Dont kow how to get it?]()

> Step 2 - Compiling
> Just run the following commands:
> ```bash
> cd build
> cmake ..
> make
> ```

And you successfully compiled EZ Scanner!

## Problem compiling?

### Linux
Make sure that CMake is installed by running: ``cmake -v``, if it isn't run: ``sudo apt install cmake``.\
You also need a C/C++ compiler, this project used gcc and g++.

## How to get your VirusTotal API key?
You need to go to [the VirusTotal website](https://www.virustotal.com/gui/), then you need to go on your profile (on the top right) and you'll see a dropdown menu, click API key and the blurred out text is your API key!
