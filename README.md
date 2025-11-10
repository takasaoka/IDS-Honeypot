# IDS and HoneyPot with DoS For Testing
Below is how to run the code. Ideally you should be running this using two separate linux machines on the same network but it can also be done on the same machine.
<br>
<br>

# MACHINE 1 - Honeypot and Detector
```bash
pip install numpy scikit-learn scapy
```
## open the port (linux specific)
```
sudo ufw allow 8080/tcp
sudo ufw allow 80/tcp
sudo ufw allow 21/tcp
sudo ufw allow 22/tcp
```
## Terminal 1 (Machine 1): start the honeypot
```
sudo python3 honeypot.py
```

The honeypot will listen on ports 21, 22, 80 and 443 but will not activate until the trigger by the detect.py is set off

## Terminal 2 (Machine 1): start detector
```
python3 detect.py --isoforest --baseline <baseline> --contamination <contamination>
```

<br>
<br>

# MACHINE 2 - Attacker (DoS) on a single terminal
## First to trigger the detection to fork out the honeypot:
```
python3 dos.py --target <target IP Address> --ports 8080 --requestsPerSecond <requests per second> --concurrency <concurrency> --duration <seconds>
```

## Once you see the honeypot is listening on the ports 21, 22, 80, and 443 run:
```
python3 dos.py --target <target IP Address> --ports 21,22,80,443 --requestsPerSecond <requests per second> --concurrency <concurrency> --duration <seconds>
```

All logs will be collected into the honeypot_logs folder in the current directory