# Network Security Plan
# By Pramath Joshi
# Student at Coder Academy


1.	***Identify threats to network security by creating a threat model for the network described in the Problem Scenario. You must:***

-	Outline the common and emerging vulnerabilities for the client (150 – 200 words)

-	Profile TWO potential attackers, and describe: (200 – 300 words for each profile) 

•	The attacker’s motivations in attacking the network and the relationship the attacker may have with the client

•	A scenario or threat the attacker could pose

•	The technical expertise required for them to carry out the attack

•	The possible severity/seriousness of the attack and the damage it could cause


**OUTLINING COMMON AND EMERGING VULNERABILITIES:**

The common and emerging vulnerabilities for the client that I could identify are that, firstly, the router that they have decided to use for accessing the Internet, which is TP-LINK AC750 uses a broken encryption protocol called WEP for the wireless security. WEP stands for Wired Equivalent Privacy, the router uses a key to manage your passwords for the router, this is not mentioned in the WEP standard. 

This therefore introduces weaknesses in the router because without key management, these keys will be present forever and it will be of poor quality. Outcome is that when recognising which packets are encrypted with the poor-quality keys can be easily sniffed because the first three bytes of the key is sent unencrypted in each packet when sending information to the Internet.

Another emerging vulnerability that I can see is that their home is attached to a park, this can pose a threat because they have an extended antenna which is attached to the router so the Wi-Fi signals can be sent to the front street and the park. These signals which are transmitted can be vulnerable to a Man in the Middle attack. 

The person can intercept the communication between the router and the smart devices they have in the household. The outcome of this is that they can spy on their private conversations and target all the information in their devices. 

Due to the family having smart mobile devices and computers they will be using that to send confidential data like login credentials or accessing financial information, this traffic that is sent between the members and the browser can be hijacked and stolen.

Another vulnerability that I can see is that they have 2 HP standard laptops which are running on Windows 8.1. These laptops are vulnerable to remote code execution. This is a high-risk vulnerability and it was discovered in June 12, 2018. 

Remote Code execution is where an attacker can exploit the issue to run arbitrary code when the user is runs the affected application. The attacker can then modify files in their computer’s since they have full access. After they gain access, the attacker can try to block the user’s permissions where only the attacker can have access. 



**PROFILING ONE OF THE TWO POTENTIAL ATTACKERS AND THEIR DESCRIPTION:**

An attacker can be a teenager who practices hacking in a real environment rather than a test environment without understanding the consequences.

The attacker’s motivations in attacking the network can just be that they want to test their skills of what they have learnt through online resources in a real-world situation. 

The client’s weak network could be an easy target for the teenager. The motivation may also be that they have an idea of publicising this information if they do end up finding vulnerabilities in the client’s network. The consequence of this is that everyone in the public will know about the weak network and may also know more about the status of the client. 

The relationship that the attacker can have with the client can be nothing. The teenager can be living a couple of houses down the road and may have come across the Wi-Fi signal that the client’s router is emitting.

A scenario or threat that the teenager could pose is if he is sitting on the park behind the client’s home, he can potentially be monitoring traffic via Wireshark. If he decides to go further, he can also sniff the packets that the client is sending to the router. 

This is a threat because the router is using poor encryption methods and only the first few bytes of the packet is encrypted meaning that the client may transfer credit card details or even login to their organisation which can all be seen and manipulated by the teenager. 
The technical expertise needed for the teenager to carry out the attack is deep knowledge about Linux and its commands. 

Linux is the Operating System to know if anyone wants to carry out any type of attack. The teenager would also need to know how to use Wireshark and the basic theory concepts like OSI and TCP/IP model and the components of each layer. This is necessary if they want to follow the TCP stream in Wireshark. 


The severity and seriousness of the attack Is large, this is because the teenager can be seeing un encrypted traffic. He can be a man in the middle and perform this attack because he can be intercepting online communications. When the client accesses their work email or is surfing the website the teenager can eavesdrop into these sessions and target all devices. This is serious and can cause damaging effects because the teenager may be able to read vital information regarding his financial organisation matters which must be kept within the organisation.


The more damaging effects is if the teenager controls the router somehow he can spoof the DNS server and the teen can make all the connections go to him. 


**PROFILING TWO OF THE TWO POTENTIAL ATTACKERS AND THEIR DESCRIPTION:**


A second potential attacker can be a person trying to achieve data theft, i.e.: stealing. Since it is mentioned that the household is labelled as rich, anyone would want to have a peek into their valuables.

The attacker’s motivations in attacking the network would be to aim at compromising their data as they can be a data theft thief. The owners, although rich, may not have enough knowledge about securing their devices. If this is the case,then there is a high probability that they will be storing sensitive information like username’s and passwords on their devices, it may not be locked, and it maybe not be stored in a deep file structure. There is a chance that it maybe stored on the desktop of the two laptops and the two MACBOOK’s leaving it exposed.

The attacker may have a relationship with the client because normally the thieves of data theft are people who may want revenge or are initialising it intentionally because they want to bring the victims status down. The attacker may be their neighbour who can seem to be friendly and approachable, but the owners would not have any idea of their underlying intention. 

A scenario or threat these types of attackers could pose is since they have two Windows 8.1 laptops running with weak encryption methods in their router, it can be vulnerable to remote code execution as mentioned above. The threat comes when they gain access into one of the computers and find confidential data which they can extract. This is when it is a critical emergency and needs to be resolved as soon as possible before it causes more damage.


The technical expertise the attacker needs to carry out this type of attack is basic computer skills like using the command line in windows. They would also need to know how IPv4 addresses or Ipv6 addresses work and need to gain knowledge about covering up what they do. Knowing Linux is a vital skill to develop because all the tools that a hacker uses is developed for and by Linux. 

Before launching such attacks, an attacker needs to practice their hacking in a test environment by using a Virtual Machine workstation before implementing it in the real world. They would also need to know basic security concepts like public key infrastructures and intrusion detection systems.


Since the household is using both wireless and wired networks, an attacker needs to know how this works. For wireless they need to know encryption algorithms like WEP and understand the protocol for connection. For ethernet connections attackers need to know more about the modem and if it has security flaws. 


Knowledge about wire shark which is a packet sniffing tool is necessary for basic packet monitoring especially if their aim is to modify the data in between the transmission. 


Possible severity or seriousness of the attack is high because attackers’ main goal in this case is to extract confidential data and this is usually related to money. The damage it could cause is the household can lose all their well earnt money in a matter of seconds before even finding out themselves or by a bank. 

•	***Categorise the threats or issues you have identified and provide a statement which gives them an overall qualitative assessment of their security posture.***

**HIGH:** Poor encryption algorithm: TP-LINK AC750 uses WIRED Equivalent Privacy, it is old and broken in terms of its architecture so it sends packets that are unencrypted which can cause packets to be exposed to the Internet world. 
HIGH: Windows 8.1 Laptops: vulnerable to remote code execution, allowing hackers to take complete control of their two devices, with the possibility of stealing private data.


**MEDIUM:** Remote access to camera: potential for a hacker to gain root privileges as the Wi-Fi signal is transmitted outside the house which can allow the hackers to take remote control of devices to manipulate what is being seen and heard or even turn it off. It also is a door to inserting a malicious botnet that can be hidden and perform malicious activity when they turn on the camera.


**MEDIUM:** Google Home: this device has the potential to be listening to conversations that the members of the household have. There is the potential for the device to be controlled remotely through an unsecured app interface that was found in Chromecasts. This can cause breaches to alarm systems that the household has in place and hackers may disable the alarm systems as a first step. 


**LOW:** Apple Time Machine: Has a vulnerability that allows remote attackers to cause a denial of service attack via modified DHCP replies. This also poses a threat to their MAC laptops. Attackers can send scam emails noting that a virus has been discovered and a phone number that seems to be like Apple’s but, it is not. It can cause browsers to freeze and mails to be scanned.


**MEDIUM:** Samsung S8 Vulnerability: with a risk rating of 6.8 according to the Common Vulnerabilities Emerging website these phones compromise confidentiality because it allows exterior attackers to execute some code on vulnerable installations of the mobile version S8. Although user interaction is needed to exploit this issue the client’s mobile will always have cellular radios enabled when they are in call with someone. This allows the hacker to gain admin control.

**HIGH:** Grand stream Products: GXP1600 VoIP can be vulnerable to identity theft. 


**Quantitative Feedback:**
As an overall feedback, the household is vulnerable to many attacks because of the scale of devices they have. Everything from the wireless router posing a threat due to old encryption methods to the laptops using old operating systems. The household at high risk of unwanted people spying on their household due to cameras being exposed in the front door. They may also be having a passcode to enter their home; security cameras can capture all of this if they were to be accessed remotely by hackers. An extremely high-risk vulnerability is when thieves can extract confidential data from their devices and this household is vulnerable to this attack vector. In conclusion, the household needs a lot of patch work to be done to their devices and the physical house itself. 

2.	**Analyse the security risks and outline the process of risk management, you must:**
-	Outline the risk management process you will undertake to assess risks in plain-English. 
Firstly, risk analysis is a planned study of unknown findings and risks that pose a threat to a network. I would ask questions about the threats that their devices are facing and what the overall consequences are if these threats are to be exploited. 

The risk management process I would take to answer these questions to assess the risks is mapping out the total assets and their values which is based on costs and the impact of the threats. I would start by creating a list of all the devices the owners are using like the Apple time machine, 2 android phones, iPhones, 2 HP laptops, MAC’s, alarm systems, Grand stream products like basic IP phones – GXP1600 and HD IP Cameras – the CXV3600 model and the IOT devices. 

Once I collect all this information, I would create a table based on the vulnerabilities that each device poses and their impacts on confidentiality, integrity and availability ranging from limited to severe and I would simultaneously rate the costs of each product from low to high. 

The next step I would take to answer the two questions above is to examine the various threats, their level of impact and the chances of occurrence deeply by using online resources. One popular website I am aware of is the Common Vulnerabilities and Exposure website which gives a reference point for openly known information security vulnerabilities along with scores for each vulnerability ranging from low, medium and high risk finding. 

From all this information I would conclude with calculating a risk matrix by scoring the assets and the threat which allows the client to see their assets, threats posed, vulnerabilities and the features of the risks in a bigger picture. 




-	**Identify and categorise THREE potentially valuable assets on the network, you must:**
1)	Identify the type of asset and state why it is valuable
2)	Determine and record the value of each asset to:
-	The client
-	The attacker
-	In monetary terms
-	Indicate whether this asset requires protection from attack

The first asset I would immediately consider valuable are the 2 Windows laptops and the 2 MAC laptops. These devices are important because the client works in the financial sector and I know there is a great chance that they will be saving their private information on all the laptops. As a senior executive working in the financial sector, the client’s laptop will be a high valuable target because of their job role and their work commitments. I am sure that they would be logging onto each of their computers every single day to either login to access their systems remotely and, they will be using it as a communication device either for online meetings and conferences where sensitive information will be exchanged. 

Hence if I were to measure the level of importance of how valuable these laptops are to the client on a scale of 1-10 with 1 being least valuable and 10 being most valuable, I would go for 10. There are vulnerabilities associated especially with the Windows laptops and the only way the client can perform their duties safely is to ensure maximum security for these devices. 

In terms of the attacker, these laptops are extremely vital targets for them to attack. The client’s job profile clearly indicates the word financial sector, and this automatically converts into money. If the client was to use their windows computers for daily work, they will be accessing the Internet, since their router has weak encryption protocols in place and the range extending to the park it will be an easy target for them to steal, modify or destroy information by installing malware or holding the laptop ransom. 

The attacker can do multiple hacks if the client uses windows laptops as MAC’s often are difficult to attack because they are less vulnerable to viruses or exploits, although easy to hack because of safari. The hacker can also cause money to be stolen on the windows laptops especially if they are using net banking, they can send a phishing email by executing a social engineering attack that can replicate a bank’s login page and redirect all traffic to the attacker. 

In monetary terms, if the client was to have credentials and other personal information that shapes the identity of the individual, I would say that laptop would be worth more than their life. Otherwise, looking at the current market value of the HP Laptops running on Windows 8.1 would be ranging around $900-$1200 with the 2014 model. 
Windows 8.1 laptops do need protection because they are extremely vulnerable to remote code execution. 



A second asset that will be valuable is the GXP1600 Grand-stream product called Voice over Internet Protocol. 
This asset is valuable because it is vulnerable to extreme vulnerabilities like stealing a person’s identity through service thefts and eavesdropping. Identity will be the most critical aspect for any person in this world. With a high-profile status and being a senior executive in the financial sector, exposing the client’s identity will have a negative impact on the individual. 

Consequences of exposing the client would be that they may lose their relationship with the family because an attacker can cause the victim to be psychologically affected leading to depression and anxiety with a loss of confidence of not knowing what to do next. 

This is also an asset because if an attacker tries to compromise the service from a service provider or utilise the service while forwarding the cost to another individual then there is no encryption. The attacker can manipulate what the client is attempting to convey by misleading the victim on the other end. 

This will cause a damaging impact on the client’s work aspect if they were to be having a conversation with their colleagues discussing details regarding the environment of their organisation as an example.
 
The relation of the GXP1600 VoIP to the client is that this phone is crucial because an attacker can grab their credentials to invoke calls that lead to extracting business data. If the client were to be engaging in a call with their manager inside their home, someone can potentially be listening to their conversations in the middle and can note down critical information that can reveal hidden facts about their organisation. The projects that need to be carried out, how much customers in their database, their budget and so on will all be essential information for an attacker. 

The relation of the GXP1600 VoIP to the attacker is that they can fluently initiate a variety of attacks because the client has these systems in place already. The attacker will want to intercept the conversations, make fake calls and extract sensitive information from this device because their aim is to gain benefit either in monetary value or by becoming popular because they have taken the identity or peeked into the conversation of a senior executive. 
They can also hold the device to ransom because this software is vulnerable to worms, viruses and malware because the device runs on end systems like computers that are open to malicious code injections in voice apps. The attacker may not want any benefit but rather cause a Denial of Service attack for their enjoyment purposes. This can be achieved by inputting too many packers into the connectivity by creating a tsunami of messages hence causing the systems to breakdown. 

In monetary terms due to the Voice over Internet Protocol being susceptible to many attacks like above, it can be worth thousands and thousands of dollars because its not about the product, but it is the conversations and extracting personal information that can cause the real damage to the client and their organisation. 
This asset needs extreme protection from viruses and malware attacks to identity theft. It is recommended to be patched or approach a professional cyber security consultant who can guide the client to install the right products and the vendors that ship patches as soon as a vulnerability Is discovered. 


The third potential asset that is valuable will be the grand-stream CXV3600 IP Camera that the client has in their household, monitoring the activities in their home. This asset is valuable to the client because an attacker can take remote control of the camera and use it a monitoring tool to listen to any private conversations or watch any live video stream of the client’s personal life. 

The IP Camera can also be a tool to shoulder surf any passwords or sensitive data that the client initiates onto their devices.
The relation of the CXV3600 IP Camera to the client will be vital. This is because personal safety is important for the well being of the client and this device will allow the client to remotely view what is happening internally and externally around their household. 

The IP cameras can also enable the client to record any malicious activity that can take place in and around the house and can report the incident to the police to take the appropriate action. The main benefit is that there is evidence and suspects can immediately be identified and their identity exposed.



The relation of the CXV3600 IP Camera to the attacker because although these devices ensure maximum safety by giving a live coverage of the activities that take place, they can also be susceptible to attacks within the network. It has been noted that there are more than 400 models of these IP cameras that are vulnerable to attacks that enable hackers to step in and take remote control of these devices. All they need is an IP address, so it bypasses additional security by overtaking credentials. The attacker can then control motion detection and they are able to listen to audio being initiated by the members of the house. 

In monetary terms the IP cameras may not cause substantial damage if a hacker was to gain root privileges other than intercepting private conversations inside the home and learn about the members and what they do. It becomes serious when they are shoulder surfing the members for private information that can spill out bank account details, company login details and more. If this was to happen it can cause a large amount of money to be lost. 

This asset needs high protection and the only way is for it to be patched up by the vendor. The cameras may need their firmware updated. 



3.	**Create a risk management plan and security controls based on your threat model and assets on the network, you must:**

•	**Design two policies which outline security controls and requirements to mitigate TWO of the most serious threats in your threat model. (300 – 400 words per policy)**

**WEP Poor Encryption Danger:**
Since the client has decided to use the TP-Link AC750 wireless router for Internet communications which has the poor and outdated encryption algorithm, Wired Equivalent Privacy, this can be easily cracked in hours’ time.
A wireless policy should be implemented to mitigate the threat of an attacker intercepting the client’s online activities. I would start by including a risk assessment into their wireless policy. 

**Risk Assessment:**
Is a section I would provide a control for security and cater to the clients needs to protect against attacks on the router because it can help identify threats and vulnerabilities in their home network. So, it is essential for the client to understand the risks associated prior to using the Internet because the assessment will provide a defensive strategy, that could be applied to protect against future threats, and it will cut down on costs of having to face data loss if an attacker intercepts and modifies the traffic going to the Internet. 

This assessment will also enable enough security components to be put into action. Since the client works in the financial sector, they may use their home network for transmitting sensitive information related to their organisation and the consequences of this will be huge if they were to be spied on. 

The risk assessment needs to be conducted immediately to ensure that the wide scope of security measures is enough to cater for the identified risks in the network. 

**Network Segregation:**
Network segregation will also be implemented in the wireless policy, allowing the client to distinguish between wireless and wired network since they have a wired network included in their home. If a security breach was to occur on the wireless part of their network, then it won’t affect the wired network. It can do this because it makes way for the client to establish untrusted LANs from the trusted ones and this is usually an ethernet connection. 
This part of the policy also allows to implement a firewall to be placed in the middle of the wired and wireless networks to take control and survey the traffic between the wired and wireless portions.

**Confidentiality:**
Confidentiality part of the policy ensures that there are substantial encryption algorithms in place which can allow a secure communication pathway for wireless transmissions to take place, avoiding the danger of eavesdropping. An Advanced Encryption Standard should be followed as part of the wireless policy because the key sizes are 128 – 256-bit blocks and can resist attack since the security is strengthened. 

**Windows 8.1 Vulnerability:**
The client needs a policy for securing their windows laptops as they are vulnerable to remote code execution since they are running on Windows 8.1 Operating System.
I would call this policy a Laptop Security Policy which will include:

**Physically Securing Laptops:**
Allows the client to view documentation on how they want to secure all their laptops especially when they are not in use.

**Protect laptops from cyber criminals:**
Client may not be connected to their Wi-Fi router when they turn it on or a signal may have been lost so the client’s laptops may not receive important software updates, also updates that can detect viruses, malware and spyware. Since their windows laptops are vulnerable to remote code execution where an attacker can get to admin privileges and take control of the machine, this policy will enforce the client to keep updating their laptops twice a week or so or when their laptop prompts them to. 



**Continuous Protection of Data**
Client can take measures to ensure they can protect data and this policy includes points to create complicated passwords and make sure they don’t share them with members of the family because their children may not know the usage of passwords as a result, they can spill this information out to anyone in the public. 
This process will also encourage the client to look at encryption needs by enforcing the client to encrypt their files or even encrypt their hard drives. 

**Back up Data**
Lastly, in case the laptops are damaged or attacked they may have not been backed up. This policy will make the client to backup their data twice a week. It is not beneficial to back up the client’s data into a network storage drive that is on the network because their Wi-Fi router is not using proper encryption which can result in data loss. 
The client should be backing up to an external drive, but they will need to physically lock or secure their backup devices. 





• **Create a timeline and budget for the implementation of security policies (200 – 300)**
Timeline and budget for implementing the two security policies above would be:
 

These policies should be given at least two weeks’ time to ensure critical feedback is given and the solutions offered. 

Risk Assessment – Has been given a high priority since their network is already insecure it poses a variety of threats from intercepting the entire home network traffic to getting root access on the vulnerable router. It is necessary for the client to get a cyber security consultant whose job profile is of conducting risk assessments, so they get a clean, directional and a sharp level of feedback on their entire home network. The budget cost of undertaking this assessment depends on how severe their network is. I would allocate somewhere around $350-$500 but this is dependent upon the consultant too.
- Cost: $350 - $500
- Time: 2-3 Hours

Confidentiality – is the next policy that should be followed, and I would consider changing the router modem to be Asus RT-AC66U B1 Dual-Band which ranges from $200 - $300 if bought from websites other than the official website. It offers fast streaming and allows the client to control the strength and implement parental settings for their kids. It also uses the AES encryption which is safer to rely on. 
Cost: $200 - $300
Time: 1 – 2 Hours

Protecting Laptops from Cyber criminals – After looking into the above policies during the first or second week, protecting laptops from cyber criminals should be looked at during the first week. The client should look at buying antivirus for four of his laptops, the recommended antivirus solution is Trend Micro which costs $79.95 for protecting two devices but it is recommended that they install this on the 4 laptops they have, so allocated cost is $99.95. 

- Cost: $99.95
- Time: 30 Minutes

Network Segregation – After getting feedback from a consultant on how wireless and wired connections work differently the client will have to think about installing a firewall immediately. For their home network, expensive firewalls are not needed and are not recommended. It is suitable to purchase the CUJO AI Smart Internet Security Firewall which protects their network from viruses and hacking. The cost on Amazon is $83.00.

- Cost: $83.00
- Time: 1 Hour

Continuous Protection of Data – Implement strengthened passwords should be issued on all their new devices that they can purchase from the list mentioned above. In terms of encrypting their data, secured is preferable for Windows especially for their version which is 8.1, I would say to dedicate $300+ because it requires company contact. 

- Cost: $300 +
- Time: 5 Minutes

Backup Data - This can be delayed until the previous policies have been gone through and implemented. The Seagate 1TB Expansion Portable Hard Drive is recommended to back up at least two of their laptops. The hard drive costs $81.90, I would recommend buying two because the client works in a financial sector so they will be storing files that are sensitive on their laptop which maybe large. 

- Cost: $163.80
- Time: N/A Depends on how much data they have on their systems but max 45 min
Physical Security of Laptops – Last thing to do is buy a laptop lock which is compatible with Windows and MAC books in their household costing $28.05 from Amazon. 

- Cost: $28.05
- Time: 30 Minutes



•	**Write a plain-English explanation for the client relating to the timeline, costs and budget for the implementation of the risk management plan (150 – 200)**


Firstly, the overall budget that the client needs to establish if they want to go ahead with the products above is $1474.80. I have achieved this amount because I have taken the maximum costs of each product. If the client can have a budget of $2000 it would be suitable to implement the above for their home network. It is appropriate for the client to conduct a risk assessment of their network prior to doing anything else because it will assist them to identify the threats or vulnerabilities lurking in their network. They may no be security conscious resulting in not knowing if a threat has already been infected in their systems. 

Confidentiality would be the next step because it allows the client to secure their data or files in their devices. They will have important data lying in their laptops that can be easily targeted if they are to transmit them over the internet for communication with a colleague or so. 
Antivirus solution is a standard security solution that must be installed on all their devices because it does the basic security scans and protects the client from accessing malicious websites. This should be done in the first place but depending upon the results of the risk assessment they can install the specific solution mentioned above which will protect against viruses plus blocking ransomware attacks by providing folder shield. 


Firewall is there to inspect traffic going to and out the network.
Encryption is necessary to block data files from being viewed in plain English.
Basic external hard drives are necessary in case the devices suffer from an attack and lose all their files.






•	Create a process for continuous review in the form of a list of steps to be followed to maintain the security controls you have designed (100 to 200 words)

1.	Risk Assessment – Keep in touch with the consultant who has been hired to undertake a risk assessment of the client’s home network. The client will have to keep contacting the consultant once every month to do a complete check to verify that the household is safer than last time.

2.	Network Segregation – Client must make sure that the smart firewall is updated at least once a week to ensure that it improves filtering traffic from the Internet.

 
3.	Confidentiality – Ensure that the router is switched off when not in use especially if the devices have been left on and the household has gone out. 

4.	Cybercriminal protection – Ensure that the client runs scans on the anti-virus software on every second day to ensure that their devices are free of threats


5.	Continuous Protection of Data – change their passwords every second week and ensure it is randomly generated.

6.	Back up Data – Clean the hard drives by removing unwanted files and run scans from the anti-virus software to ensure it is not affected with any bugs.












•	Provide evidence you have received feedback from an industry expert on your risk management plan, and how you have modified your approach based on feedback 
 

 



I have received feedback From Mr Clark and Ms Power who are my instructors and for this question related to the attacker’s job profile I got told that I should not be using penetration tester as an example of an attacker because it will be illegal for them to be issuing these tests and if they conducting these tests without permission they would not be considered as an ethical hacker.

 The suggested feedback was to change the title to a vulnerability finder who doesn’t know about the professional and ethical obligations of an IT professional.

I have catered to this feedback by changing the attacker to be a teenager who wants to practise their hacking skills. I was able to clearly answer what the question was asking because penetration tester complicated my answer. I kept my answer simple and straight forward to understand and ensured that it didn’t get too complicated. I was able to outline the attacker’s motivations by stating that the attacker wants to test their skills out in the real world, I was able to easily elaborate on this answer. I was also clearly able to indicate the scenario the attacker could pose because I was imagining all the findings that the teenager could fine and maybe fine tune his skills to a more dangerous level. 





4.	**Design an auditing and incident response plan to handle a security incident affecting the network described in the Problem Scenario.**
Your incident response plan must include:
•	**A description of the incident it will address (150 – 200 words)**

The two laptops running on Windows 8.1 Operating System can be affected by a vulnerability which lets the attacker to remotely implement a code execution on their systems. The client has opened a malicious webpage on the network which has open type fonts read by their computer. Open type font is where the attacker can run code in the specific context of the malicious website. This vulnerability is labelled as critical for Windows 8.1 for x64 based systems. The attacker can install programs that are not meant to run on their laptops, they can read all the client’s sensitive files related to their organisation as they may not have encrypted them, and the attacker could create new accounts with admin privileges.  The attacker can also read all the client’s credentials which has been stored in clear text and can potentially transfer all their money to the attacker’s account. This can result in catastrophe as the client will have no control over their main devices which are laptops and will be financially affected.

•	**An outline which states how it provides appropriate coverage for the incident which must refer to an authoritative source on incident response (100 – 200)**

The remote code execution vulnerability on the Windows 8.1 machines provides the necessary coverage for its incident because other systems like Windows Vista, Windows Server, Windows 7, Windows 8 and 8.1 and Windows 10 have been reported critical to the remote code execution vulnerability. Since all windows operating system have the Adobe Systems installed on their computers it includes an Adobe Type Manager Library which does not hold control of intelligently designed Open Type fonts. So, an attacker who has the skills to exploit this can take full control of the affected laptops. Microsoft had the facts and evidence to recognise this vulnerability but did not know it had affected its customers. It will affect all its customers repeatedly because an attacker can keep exploiting the vulnerability.

According to the website https://cyber.gov.au/business/guides/developing-an-incident-response-plan/ based on the Australian Signals Directorate from the Australian Government which provides a guideline for responding to a cyber security situation. It states that the incident response plan outlines how the organisation, in this case the household, will respond to a breach. It also ensures that the correct people are involved in the process and this must be done prior to the incident occurring. 
Another crucial element of a strong response process is making sure that the plan is viewable by the members of the household. There should be set standards that can help in making this plan like ISO 27035-2. 

In summary, a strong incident response plan must
-	Observe the threat environment which includes the chance and severity of the accidental or purposeful incident. 
-	Identify important assets, data and critical components of a system
-	Plan for different hard-core incident types and various data that can be compromised
-	Arranging and gathering professionals to continuously review and practice the plan.
-	After the incident occurs it must be reviewed and reported.


•	Create an auditing checklist with FIVE items which includes:
-	Software and hardware configurations to be checked which support security controls and incident response procedures
-	Suggested penetration tests that should be conducted to verify security controls are in place to prevent the incident.
The checklist for the software and hardware configurations include:
1.	Antivirus – Make sure that the antivirus is enabled on browser sessions to stop the user from clicking on malicious links.
2.	Firewall – need to filter what traffic can be accepted to and from the Internet
3.	Encryption – Encryption software to encrypt all files and data in case of attack
4.	NMAP SCAN – immediate Nmap scan is required to view any ports that maybe open on a system especially SSH access, this should be patched up. 
5.	Password cracking tools – run brute force attacks against own system to see if common passwords are being used that can be in any of the password cracking tools like John. 



•	Create a process, a list of steps, that should be followed should the incident occur, the process must include (200 – 300):
-	a preamble which has an allocation of responsibilities to relevant persons
-	specific details relating to the management, monitoring and auditing of software and hardware in the context of the incident. 

1.	Immediately try to get out of the network that the client is on. Turn all devices into airplane mode or even shutting the devices down is an excellent idea. 
2.	Go to the router and turn the modem off to try and mitigate against the attack and exposing the Wi-Fi signals outside the park and near the front street. 
3.	Responsible persons are Microsoft’s employees and the client should immediately call the Global Customer Service number because this attack can be rippled throughout the world. Number to call is 13 20 58. They will contact their security team and will guide the client with clear instructions. 
4.	The client should monitor the incident by taking a video stream of what happens with their devices and record every movement as evidence in case it may come handy for later use, they can also use it to show the Police if the incident was to elevate to a serious level. 
5.	Antivirus scans should be running every minute to detect what has been breached and if it was blocked by the anti-virus software. 
6.	Manage by viewing the log file of the laptops to see if any credentials were exposed to the attacker. If this is the case, then they should immediately contact the Australian Cybercrime Online Reporting Network. 


