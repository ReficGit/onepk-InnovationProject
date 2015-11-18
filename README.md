#Introduction

The purpose of this project is to demonstrate some of the One Platform Kit (onePK) abilities through an implementation a data path service set (dpss) functionality. In order to bring this project to life, both C programming skills on Unix like platforms and networking skills are required.
The program is able to track TCP packets and show some information out of them, for example, L4 protocol, source and destination addresses with ports, and other data like packet flow number. What is more, the program can track how many packets had already went through a device under test, which is router in our case, drop as many packets as configured in the program (drop rate) and saves the dropped packets information to a file called «dropped_packets_log.txt». The third implemented feature is an ability to change a port that is listened by the program on the router (those are, for example, fa0/1 or se0/0/0 interface). What is more, there is a counter that tracks a time difference between packets and shows mean, maximum and minimum times.

#Other documentation can be found from the onepk.pdf
