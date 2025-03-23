# Operation Endgame

## Overview
- **Coming Soon**



Output from [solve.py](./solve.py):

```bash
Endgame/solution » python solve.py docker      
[+] Opening connection to 172.17.0.4 on port 7777: Done


------------------------------------------------------------------------
 ██████╗ ██████╗ ███████╗██████╗  █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
██╔═══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
██║   ██║██████╔╝█████╗  ██████╔╝███████║   ██║   ██║██║   ██║██╔██╗ ██║
██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
╚██████╔╝██║     ███████╗██║  ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
                                                                        
███████╗███╗   ██╗██████╗  ██████╗  █████╗ ███╗   ███╗███████╗          
██╔════╝████╗  ██║██╔══██╗██╔════╝ ██╔══██╗████╗ ████║██╔════╝          
█████╗  ██╔██╗ ██║██║  ██║██║  ███╗███████║██╔████╔██║█████╗            
██╔══╝  ██║╚██╗██║██║  ██║██║   ██║██╔══██║██║╚██╔╝██║██╔══╝            
███████╗██║ ╚████║██████╔╝╚██████╔╝██║  ██║██║ ╚═╝ ██║███████╗          
╚══════╝╚═╝  ╚═══╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝          
------------------------------------------------------------------------

[+]███████████████████████████████████████████████████████████████████████████████████████████████████████████████[+]
[+]                                                                                                               [+]
[+]                             Operation End this mans Whole Career - Top Secret                                 [+]
[+]                                                                                                               [+]
[+]---------------------------------------------------------------------------------------------------------------[+]
[+]                                                                                                               [+]
[+]     It is the year 2006, and you are an elite intelligence operative working with the FBI to track down an    [+]
[+] Advanced Persistent Threat (APT) individual who was previously believed to be operating abroad. Recent        [+]
[+] intelligence indicates that this individual is temporarily residing in the United States. This active APT     [+]
[+] member is a world renowned world-expert and is well-funded and clever, making him difficult to pin down.      [+]
[+] To locate him, a Stingray (IMSI Catcher) device has been deployed near his known residence in Miami. Over the [+]
[+] past three days, he has been on the move, carrying out clandestine cash pickups and dropoff at various        [+]
[+] inconsipicous locations across the country. Each time he makes a transaction, he activates his mobile device. [+]
[+] Fortunately for us, due to a fundamental design flaw in the device, even if the setting is turned off, it will[+]
[+] still ping the nearest base-station during it's boot sequence.                                                [+]
[+]                                                                                                               [+]
[+]---------------------------------------------------------------------------------------------------------------[+]
[+]                                   |*******CONFIDENTIAL*******|                                                [+]
[+]                                   |--------------------------|                                                [+]
[+] Your task is to solve five triangulation problems to pinpoint his exact locations based on these bearings.    [+]
[+]   - You will be provided the 2 nearest base stations, bearing angle, and the Stingray device location.        [+]
[+]   - Provide the exact (latitude, longitude) coordinates for each location to receive the flag.                [+]
[+]   - Don't F*ck this up.                                                                                       [+]
[+]---------------------------------------------------------------------------------------------------------------[+]
[+]                                                                                                               [+]
[+] Good luck, Operator!
                                                                                          [+]
[+]                                                                                                               [+]
[+]███████████████████████████████████████████████████████████████████████████████████████████████████████████████[+]

Problem 1:
Three base stations have detected a mobile device. Here are the base station details:
  StingrayMiami: Location = (25.733414, -80.241092), Bearing = 351.47°
  BaseStationHO: Location = (29.760430, -95.369800), Bearing = 61.46°
  BaseStationNY: Location = (40.714270, -74.005970), Bearing = 230.41°
These bearings are measured from North, increasing clockwise.
Find the (latitude, longitude) of the mobile device's location.
Format: lat,lon (e.g., 12.34,-56.78)

Enter your answer for Problem 1: 
Sending Answer for Problem 1: 35.055189,-81.943634
Correct!

Problem 2:
Three base stations have detected a mobile device. Here are the base station details:
  StingrayMiami: Location = (25.733414, -80.241092), Bearing = 328.53°
  BaseStationD: Location = (32.776270, -96.797000), Bearing = 31.89°
  BaseStationPE: Location = (33.448380, -112.074040), Bearing = 64.25°
These bearings are measured from North, increasing clockwise.
Find the (latitude, longitude) of the mobile device's location.
Format: lat,lon (e.g., 12.34,-56.78)

Enter your answer for Problem 2: 
Sending Answer for Problem 2: 39.434139,-91.350234
Correct!

Problem 3:
Three base stations have detected a mobile device. Here are the base station details:
  StingrayMiami: Location = (25.733414, -80.241092), Bearing = 11.20°
  BaseStationCH: Location = (41.878110, -87.629800), Bearing = 144.94°
  BaseStationHO: Location = (29.760430, -95.369800), Bearing = 80.95°
These bearings are measured from North, increasing clockwise.
Find the (latitude, longitude) of the mobile device's location.
Format: lat,lon (e.g., 12.34,-56.78)

Enter your answer for Problem 3: 
Sending Answer for Problem 3: 30.977038,-79.030582
Correct!

Problem 4:
Three base stations have detected a mobile device. Here are the base station details:
  StingrayMiami: Location = (25.733414, -80.241092), Bearing = 23.10°
  BaseStationD: Location = (32.776270, -96.797000), Bearing = 58.55°
  BaseStationHO: Location = (29.760430, -95.369800), Bearing = 51.71°
These bearings are measured from North, increasing clockwise.
Find the (latitude, longitude) of the mobile device's location.
Format: lat,lon (e.g., 12.34,-56.78)

Enter your answer for Problem 4: 
Sending Answer for Problem 4: 41.884633,-70.929262
Correct!

Problem 5:
Three base stations have detected a mobile device. Here are the base station details:
  StingrayMiami: Location = (25.733414, -80.241092), Bearing = 280.27°
  BaseStationCH: Location = (41.878110, -87.629800), Bearing = 222.68°
  BaseStationHO: Location = (29.760430, -95.369800), Bearing = 249.22°
These bearings are measured from North, increasing clockwise.
Find the (latitude, longitude) of the mobile device's location.
Format: lat,lon (e.g., 12.34,-56.78)

Enter your answer for Problem 5: 
Sending Answer for Problem 5: 27.569061,-101.470143
Correct!
[+] Receiving all data: Done (60B)
[*] Closed connection to 172.17.0.4 port 7777

Congratulations! Here is your flag: GrizzCTF{g0t_3m_c04ch}
```

