#!/usr/bin/python2

import scapy.all as scapy
import smtplib, ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send_mail(msg):
        mail_content = msg
        #The mail addresses and password
        sender_address = 'shivraj07052002@gmail.com'
        sender_pass = '9322456063'
        receiver_address = 'shivraj07052002@gmail.com'
        #Setup the MIME
        message = MIMEMultipart()
        message['From'] = sender_address
        message['To'] = receiver_address
        message['Subject'] = 'You are Under Attack..!'   #The subject line
        #The body and the attachments for the mail
        message.attach(MIMEText(mail_content, 'plain'))
        #Create SMTP session for sending the mail
        session = smtplib.SMTP('smtp.gmail.com', 587) #use gmail with port
        session.starttls() #enable security
        session.login(sender_address, sender_pass) #login with mail_id and password
        text = message.as_string()
        session.sendmail(sender_address, receiver_address, text)
        session.quit()
        print('Mail Sent')


def getmac(ip):

        arp_request_header = scapy.ARP(pdst = ip)
        ether_header = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_packet = ether_header/arp_request_header
        answered_list = scapy.srp(arp_request_packet,timeout=1,verbose=False)[0]
        return  answered_list[0][1].hwsrc

def sniff(interface):

        scapy.sniff(iface=interface,store=False,prn=process_sniffed_packet)

def process_sniffed_packet(packet):

        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op==2:
                try:
                        real_mac = getmac(packet[scapy.ARP].psrc)
                        response_mac = packet[scapy.ARP].hwsrc

                        if real_mac != response_mac:
                                print ("[+] You are under attack !!")
                                msg= "Routers mac has been chnge from " + real_mac+ "  TO  " + response_mac
                                send_mail(msg)
                except IndexError:
                        pass

sniff("eth0")