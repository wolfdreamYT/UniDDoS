# UniDDoS
A DDoS script that can take down low to medium scale WiFi networks and some websites. This was made to prank my mom when she uses her TV, but i turned it into a proper DDoSer.

# Setup

First, install the requirements:
  - Python 3.13+
  - pip 3.13+
  - node.js (for server testing)

Then, install the libraries required:
  - `pip install -r requirements.txt`
You should see the shell installing all the required libs.

# How to Use
First, you need to find an IP or a URL, pick your choice. Lets say the IP is 12.43.55.812, this is just an example but you can use your own target. Then, while in the same terminal set to your folder, enter `python happyday.py`. You should see a UI pop up on the screen, and that is your centre of command.

You can set the target to a URL or IP, your choice.
then you can set the amount of requests, if you want to flood (infinite requests), then just remove any numbers and leave it empty.
You can adjust the threads to how many threads you want, can be from 5 to 100, your choice, but your computors limits. 
Set the delay to whatever you want the delay to be inbetween each ping, i set it by default to rapidly send. 
Click "Start" to start the program once you setup everything, and then you can see traffic waves below. 
Press "Stop" if you want to end the attack.
