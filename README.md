# EZ Scanner
<center>Powered by <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/b/b7/VirusTotal_logo.svg/2560px-VirusTotal_logo.svg.png"></center>

## Instructions
'''bash
./EZ_Scanner <path_to_file>
'''

## Downloads

### Linux (just to run)
You can go on the releases page to download the file, you might need to install ''libcurl'' and ''libssl-dev'' by doing:
'''bash
sudo apt install libssl-dev
'''

### Linux (Compiling)
> [!NOTE]
> You need to make a VirusTotal account to get an API key.

> Step 1 - Changing the code
> You need to change line 13 of scanner.cpp: '''cpp #define VIRUSTOTAL_API_KEY "YOUR_API_KEY"'''