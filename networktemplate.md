# Network Forensic Analysis Report

## Setup

For this part of the Project, live traffic within the intranet was captured through wireshark.
- For the purpose of this project,command `systemctl start sniff` was ran which uses `tcpreplay` to replay PCAPs in `/opt/pcaps` onto Kali's `eth0` interface.
- This was then captured for about 15min through wireshark as live traffic.
- Once the live traffic was all captured, command `systemctl stop sniff` was ran to stop the `tcpreply`.
- Then, this capture was saved to a file.

<br>
<br>

## Time Thieves 

You must inspect your traffic capture to answer the following questions:

1. What is the domain name of the users' custom site?
    - frank-n-ted.com
    ![net1](https://user-images.githubusercontent.com/101371476/169899710-58adbd4b-899e-4c5a-bdbc-c29b9ed76e5e.png)

    - You can also find their name within DHCP packet
    - ![net2](https://user-images.githubusercontent.com/101371476/169899799-b5bc8d8c-ea3e-41f8-824d-68d992184deb.png)
    

2. What is the IP address of the Domain Controller (DC) of the AD network?
    - 10.6.12.157
3. What is the name of the malware downloaded to the 10.6.12.203 machine?
    - june11.dll
    ![net3](https://user-images.githubusercontent.com/101371476/169899914-b1e0aaa8-765b-48c7-a960-f52bae93400e.png)

   - Once you have found the file, export it to your Kali machine's desktop.
   - You can download the actual malware file by going to `File > Export Objects > HTTP`
    ![net4](https://user-images.githubusercontent.com/101371476/169899970-bababfc8-8352-444b-b82e-3fe55b331c91.png)

4. Upload the file to [VirusTotal.com](https://www.virustotal.com/gui/). 
    ![net5](https://user-images.githubusercontent.com/101371476/169900039-45c6c69b-7353-4400-871b-6388758ba006.png)

5. What kind of malware is this classified as?
    - Trojan Horse

<br>
<br>

---

## Vulnerable Windows Machine

1. Find the following information about the infected Windows machine:
    - Host name: ROTTERDAM-PC
    ![net6](https://user-images.githubusercontent.com/101371476/169900247-6df114a9-7978-45d9-9eed-a5461c687aa9.png)

    - IP address: 172.16.4.205
    ![net7](https://user-images.githubusercontent.com/101371476/169900289-ebfdb333-4ca3-4891-a808-3b1887e64276.png)

    - MAC address: 00:59:07:b0:63:a4
    ![net8](https://user-images.githubusercontent.com/101371476/169900458-d9720fff-1460-46cb-aefb-9f9f752805a8.png)

    
2. What is the username of the Windows user whose computer is infected?
    - matthijs.devries
    - Note that for CNameString values for hostnames always end with a $ (dollar sign), while user account names do not.
    ![net9](https://user-images.githubusercontent.com/101371476/169900589-5382f2d7-ebc1-4088-815c-d990aea86424.png)

3. What are the IP addresses used in the actual infection traffic?
    - 182.243.115.84
    - For this, you can use `Statistics > Conversation` then, look at the TCP tab.
    - You would look at the most amount of Bytes that the infected windows was communicating to.
    ![net10](https://user-images.githubusercontent.com/101371476/169900695-61ccf118-0d8b-4ba6-8282-c9d53653dd7f.png)

    - You can also confirm this by looking at the TCP stream. The body of this TCP stream is not clear indicating that it could be infected.
    ![net11](https://user-images.githubusercontent.com/101371476/169900734-0d566abb-3840-4446-b1a5-9f8a5e41b7c3.png)

4. As a bonus, retrieve the desktop background of the Windows host.
    - For this, you would go to `File > Export Objects > HTTP`
    - The Size of the img is quite large compared to the other image files.
    - In this case, the size of the file can indicate that it's a desktop image, as Desktop Background images are usually high in resolution.
    ![net12](https://user-images.githubusercontent.com/101371476/169900945-4e209513-931e-4421-96bc-c50c47a65166.png)

    - Once downloaded, you can also look at the property of the file to confirm. 
    - You can see that Image size is 1920x1080 pixels, which is the size that is likely used for desktop images.
    ![net13](https://user-images.githubusercontent.com/101371476/169901006-1d8c76b8-694f-4aca-84d0-c04c4a17ab71.png)

    - Here is the downloaded Deskbop background image:
    ![net14](https://user-images.githubusercontent.com/101371476/169901055-98a844fa-5120-4264-a193-008eca0a6084.png)


<br>
<br>

---

## Illegal Downloads

1. Find the following information about the machine with IP address `10.0.0.201`:
    - MAC address: 00:16:17:18:66:c8
    - Windows username: elmer.blanco
    ![net15](https://user-images.githubusercontent.com/101371476/169901112-3e7eef68-90ac-4e39-aa11-08f7d8c90edc.png)

    ![net16](https://user-images.githubusercontent.com/101371476/169901161-aa17a3a6-d1ab-456a-9890-bbf255a30e71.png)

    - OS version: Windows NT 10.0; Win64; x64 (Windows 10)
    - For OS version, I've searched for TCP stream in HTTP
    ![net17](https://user-images.githubusercontent.com/101371476/169901228-3e831490-89a0-4b51-b6fd-4080e5998d3b.png)


2. Which torrent file did the user download?
    - Betty_Boop_Rhythm_on_the_Reservation.avi.torrent
    ![net18](https://user-images.githubusercontent.com/101371476/169901280-e8c2722f-695f-40c7-bf4d-2ee78a16022c.png)






