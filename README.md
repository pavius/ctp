CTP is a Linux user space application which lets you pass hundreds of megabits of ethernet traffic through an off the shelf PC. Frames can be manipulated, filtered and generated with a flexible and configurable processing pipeline. CTP was tested in 2012 to process 350 Mbp/s with 0% drop and ms-level jitter. The drops occured at the capture level, so with off the shelf capture NICs one could probably achieve full wirespeed. 

It achieves this through the following:

* It uses PF_RING rather than PF_PACKET
* The processing pipeline is explicitly spread out across cores, where each core runs a single RT priority thread processing thread which busy waits on a queue
* Inter-thread (effectively, inter-core) communication is done through bespoke queues based on spin locks so no kernel interaction is required when processing a frame

This project is for reference only, and has examples of modules which simulate a 3G access network.

