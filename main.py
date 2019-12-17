'''
Este script consulta a una db para obtener una lista de tiendas y sus ip's, para posterior hacer el intento
de apagado de todas las maquinas encendidas que usen windows(así se requería). Tomando la autenticacion de un
archivo de configuración. para al final enviar el reporte por mail.
Por: Rigoberto M. rigohvz14@gmail.com
'''
import socket
import sys
import msvcrt
import win32api
import win32con
import win32netcon
import win32security
import win32wnet
from datetime import datetime
import pymysql.cursors
from collections import OrderedDict
from pymysql.cursors import DictCursorMixin, Cursor
import schedule
import smtplib, email
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import warnings
from time import gmtime, strftime
import configparser
import threading
import time
import queue
import os
import shutil

def shutdown(host=None, user=None, passwrd=None, msg=None, timeout=0, force=1,
			 reboot=0):
	""" Shuts down a remote computer, requires NT-BASED OS. """
	
	# Create an initial connection if a username & password is given.
	connected = 0
	if user and passwrd:
		try:
			win32wnet.WNetAddConnection2(win32netcon.RESOURCETYPE_ANY, None,
										 ''.join([r'\\', host]), None, user,
										 passwrd)
		# Don't fail on error, it might just work without the connection.
		except:
			pass
		else:
			connected = 1
	# We need the remote shutdown or shutdown privileges.
	try:
		p1 = win32security.LookupPrivilegeValue(host, win32con.SE_SHUTDOWN_NAME)
		p2 = win32security.LookupPrivilegeValue(host,
												win32con.SE_REMOTE_SHUTDOWN_NAME)
		newstate = [(p1, win32con.SE_PRIVILEGE_ENABLED),
					(p2, win32con.SE_PRIVILEGE_ENABLED)]
		# Grab the token and adjust its privileges.
		htoken = win32security.OpenProcessToken(win32api.GetCurrentProcess(),
											   win32con.TOKEN_ALL_ACCESS)
		win32security.AdjustTokenPrivileges(htoken, False, newstate)
		win32api.InitiateSystemShutdown(host, msg, timeout, force, reboot)
		# Release the previous connection.
		if connected:
			win32wnet.WNetCancelConnection2(''.join([r'\\', host]), 0, 0)
		return 1
	except:
		return 0

class OrderedDictCursor(DictCursorMixin, Cursor):
	dict_type = OrderedDict

def getTime(fmat=0):
	now = datetime.now()
	current_time = now.strftime("%Y-%m-%d %H:%M:%S")
	if fmat != 0:
		current_time = now.strftime("%Y-%m-%d")
	
	return str(current_time)

def scan(addr, p):
	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	socket.setdefaulttimeout(0.25)
	result = s.connect_ex((addr,p))
	if result == 0:
	  return 1
	else :
	  return 0

def send_mail(filename):
	file = open('log_mail.txt', "a+")
	try:
		body = "Adjuntando monitoreo de equipos %s" % getTime()
		sender_email = "guardia.sistemas"
		# Lista de correos a donde enviar archivo
		receiver_email = ["my_mail.mail.com"]

		server = smtplib.SMTP('mail.host.com', 587)
		server.starttls()
		server.login("user", "pass")
		  
		message = MIMEMultipart()
		message["From"] = sender_email
		message["To"] = ", ".join(receiver_email)
		message["Subject"] = "Monitoreo equipos %s" % getTime()
		# Add body to email
		message.attach(MIMEText(body, "plain"))
		
		# Open file in binary mode
		with open(filename, "rb") as attachment:
			# Add file as application/octet-stream
			# Email client can usually download this automatically as attachment
			part = MIMEBase("application", "octet-stream")
			part.set_payload(attachment.read())
		# Encode file in ASCII characters to send by email    
		encoders.encode_base64(part)

		# Add header as key/value pair to attachment part
		part.add_header(
			"Content-Disposition",
			"attachment; filename= {}".format(filename),
		)

		# Add attachment to message and convert message to string
		message.attach(part)
		text = message.as_string()
		server.sendmail(sender_email, receiver_email, text)
		server.quit()
		file.write("%s Correo enviado " % getTime())
		os.remove(filename)
	except:
		file.write("%s Error al enviar el correo,  moviendo archivo a logs" % getTime())
		shutil.move(filename, 'logs\\'+filename)

	finally:
		file.write("\n")
		file.close()


def info_tiendas():
	try:
		# Connect to the database
		connection = pymysql.connect(host='127.0.0.1',
									 user='user',
									 password='pass',
									 db='DB',
									 charset='utf8mb4',
									 connect_timeout=30,
									 cursorclass=pymysql.cursors.DictCursor)
		with connection.cursor(OrderedDictCursor) as cursor:
			# Se obtienen los datos de una tabla
			sql = "SELECT lans_ips FROM table WHERE 1 = 1"
			
			cursor.execute(sql)
			connection.close()
			return cursor.fetchall()
	except:
		return False
def parse_network(nw):
	a = '.'
	net = nw.split('.')
	return net[0] + a + net[1] + a + net[2] + a

def setAuth():
	config = configparser.ConfigParser()
	config.read('config.ini')
	global user
	user = config['autenticacion']['user']

	global passw
	passw = config['autenticacion']['pass']
	global passw_2
	passw_2 = config['autenticacion']['pass_dos']
	global msg
	msg = config['autenticacion']['msg']

def threader():
	global file_log
	global user
	global passw
	global passw_2
	global msg

	setAuth()

	while True:
		worker = q.get()
		name = 'N/A'
		if (scan(worker, 135)):
			try:
				name = socket.gethostbyaddr(worker)[0].split('.')[0]
			except socket.herror:
				name = 'N/A'

			if shutdown(worker, user, passw, msg, 5) or shutdown(worker, user, passw_2, msg, 5):
				line = ("%s - %s\t: OFF Se envio orden de apagado" % (worker,name))
			else:
				line = ("%s - %s\t: ON  Ocurrio un error al apagar" % (worker,name))
			print(line)
			file_log.write(line)
			file_log.write("\n")
		q.task_done()


def mainThread():
	startTime = time.time()
	result = info_tiendas()

	if not result:
		print("No se obtuvo la información de las tiendas")
		sys.exit()

	global file_log

	file_txt = 'Maquinas_apagadas'+getTime(1)+'.txt'
	file_log = open(file_txt, "w")
	t1 = datetime.now()
	file_log.write("Comenzando escaneo: %s" % t1)
	file_log.write("\n")
	for row in result:
		ip = row['direccion_ip']
		if ip != None:
			file_log.write("\n")
      # en este script se apagan maquinas de sucursales de muebleria CRE...
      # pero se puede adaptar para usar un archivo con las lans a apagar
			print("Tienda: %s" % row['muebleria'])
			file_log.write("%s - %s" % (row['clave_muebleria'], row['muebleria']))
			file_log.write("\n")

			a = '.'
			net = ip.split('.')
			net = net[0] + a + net[1] + a + net[2] + a
		
			for x in range(20):
				t = threading.Thread(target = threader)
				t.daemon = True
				t.start()
			
			for last_oct in range(1, 256):
				q.put(net+str(last_oct))
			file_log.write("\n")
		q.join()

	print('Time taken:', time.time() - startTime)
	t2 = datetime.now()
	file_log.write("Escaneo finalizado: %s" % t2)
	file_log.close()
	send_mail(file_txt)
print("\
\
   _____ _____ _____ __  __ \n\
  / ____|_   _|_   _|  \\/  | Script: ver equipos encendidos\n\
 | (___   | |   | | | \\  / | ver: 0.0.1\n\
  \\___ \\  | |   | | | |\\/| | Fecha: 20-11-19\n\
  ____) |_| |_ _| |_| |  | | Por: Rigoberto M.\n\
 |_____/|_____|_____|_|  |_| Horario: * días 10:30 p.m\n\
")
warnings.simplefilter('ignore')
global file_log
global user
global passw
global passw_2
global msg
q = queue.LifoQueue()
mainThread()
