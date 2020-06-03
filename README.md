# Offensive Mamba

Offensive Mamba is an automated penetration testing that uses publicly available softwares, CVE Databases and Exploit Databases to test the security of a network just like a Penetration Tester does but without invloving human biases and shortcomings of a human actor.

## Main Interfaces
This project has 3 main interfaces or parts:

* **Dashboard**<br/>
  Frontend for the Users where they can view reports and other information related to their network.

* **API and Master Control**<br/>
  It the core of the project. It contains database and API backend along with the part which controls the Users Network to get vulnerability information from the local systems users has registered.

* **Local Agent**<br/>
  This part should be deployed inside the user's network. It will recieve commands from the Master and act accordingly to provide information that master requires about the local systems. It will assist Master to genrate and store reports into the main system database.
