import time
import os
import datetime
import pathlib
from pathlib import Path
import signal
import threading
import sys
import configparser
import socket
import sys

#   ________________________________________________________________________________
#   MODULI
import os, time, sys, signal, threading, configparser, socket #crypt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from hmac import compare_digest as compare_hash


def pwd():
    '''
    #Funkcija pwd ima zadaću vraćanja podatka o tome u kojem se direktoriju korisnik trenutno nalazi.
    To čini pomoću naredbe os.getcwd (get current working directory). Naredba ne prima parametre ni argumente
    te će se u slučaju njihova upisivanja ispisati poruka da naredba ne prima parametre ni argumente.
    '''
    print(os.getcwd())
    return


def ps():
    '''
    #Funkcija ne prima parametre vec samo vraca PID trenutnog proces preko
    naredbe os.getpid() koja takoder ne prima nikakve argumente
    '''
    print(os.getpid())
    return


def echo(a):
    '''
    #Funkcija prima unos od krosinika te mice "echo" sa pocetka i vraca ostatak
    nepromijenjenog unosa koji se ispisuje na ekran
    '''
    b = a.lstrip('echo ')
    print(b)
    return


def echo_navodnik(a):
    '''
    #Funkcija prima unos od korisnika te mice "echo" sa pocetka, zatim zamjenjuje "
    sa razmakom te to cini isto sa ' i na kraju vraca promijenjeni unos koji se ispisuje na ekran
    '''
    b = a.lstrip('echo ')
    if (b.startswith("\"")):
        c = b.lstrip('"')
        d = c.replace('"', ' ')
        f = d.replace("'", ' ')
        print(f)
    elif (b.startswith("\'")):
        c = b.lstrip("'")
        d = c.replace("'", ' ')
        f = d.replace("'", ' ')
        print(f)
    return


def kill(sig):
    '''
    #Funkcija kill(sig) omogućava korisniku slanje signala trenutnome procesu. Naredba prima minimalno
    jedan argument te je pomoću if petlje osigurano da se ovaj uvijet ispuni. Korisnik kao argument može navesti broj
    signala (npr. 2), ime signala (npr. SIGQUIT) ili skraćeno ime signala (npr. QUIT). Ukoliko korisnik kao argument unese
    signal broj dva, ispisuje se odgovarajuća poruka te se program zatvara pomoću sys.quit().
    Ukoliko korisnik kao argument navede signal pod brojem 3, program će ga ignorirati.
    Ukoliko se kao argument navede signal 15, program ga izvršava pomoću naredbe kill(15).
    Prilikom identificiranja primljenog signala njegova se vrijednost zabilježava kao dva = 2, tri = 3 ili petnaest = 15
    kako bi mi se pridružila int vrijednost umijesto string vrijednosti koju unosi korisnik.
    Naredba os.kill uzima tu int vrijednost te potom izvršava signal koji joj pripada.
    Ukoliko korisnik pokuša naredbi pridružiti neki pid ispisati će se poruka da naredba ne prima argumente.
    '''
    a = os.getpid()
    os.kill(a, sig)
    return

def kill_pid(pid, sig):
    os.kill(pid, sig)
    return

def provjeri_pid(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True


def cd_arg(a):
    '''
       #Funkcija "cd_arg(a") čija je zadaća omogućiti korisniku nesmetano kretanje
       po svim dostupnim postojećim direktorijima. Navedena funkcija prima jedan
       argument koji može biti adresa u relativnom ili apsolutnom obliku, "." te ".."
       kao navigatore. Prijenego što se funkcija pozove, program provjerava putem ugrađene
       naredbeos.path.exists(), koja također prima adresu kao argument, postoji li unesena
       adresa. Analogno, ako adresa postoji, izvodi se funkcija koja uz pomoć naredbe
       os.chdir() mijenja poziciju korisnika u stablu direktorija.
       '''
    os.chdir(a)
    return


def cd_no_args(a):
    '''
       #Funkcija "cd_no_args(a)" također mijenja korisnikov položaj u stablu direktorija,
       ali ona se poziva samo u slučaju da je unesena naredba "ls" bez parametara. Njezina
       je zadaća ista kao ona prethodne funkcije, ali sam odlučio napraviti još jednu istu
       funkciju radi preglednosti i lakšeg snalaženja u programskom kodu te lakšeg održavanja.
       Prije poziva same funkcije, program provjerava duljinu liste koja sadržava svaku
       riječ iz unosa korisnika. Ukoliko je duljina te liste 1, to znači da je unesena samo
       jedna riječ koja mora biti "ls" (postignuto korištenjem if-elif-else petljom) te se u
       funkciju kao argument prosljeđuje varijabla "home" čija je vrijednost ime kućnog
       direktorija korisnika koji koristi program. Funkcija zatim mijenja korisnikovu poziciju
       u stablu direktorija u vlastiti kućni direktorij.
       '''
    os.chdir("{}".format(a))
    return


def date_kod_pozdrava():
    '''
    #Funkcija date_kod_pozdrava() ispisuje datum i vrijeme u trenutku kada korisnik pokrene program
    te ih ispisuje na samome početku.
    '''
    now = datetime.datetime.now()
    print(now.strftime("%d.%m.%Y ; %H'%M'%S"))
    return

def date_no_args():
    '''
    #Funkcija date_no_args poziva se ukoliko uz unos naredbe date nije priložen nikakav parametar ni argument.
    If petlja prvo provjerava je li unesena samo naredba date te ukoliko jest poziva se ova naredba.
    Pomoću naredbe now.strftime dobavlja trenutno vrijeme te ga ispisuje korisniku. Vrijeme se ispisuje u 24-satnom obliku
    ukoliko korisnik ne odredi drugačije.
    '''
    now = datetime.datetime.now()
    print(now.strftime("%H'%M'%S %A %d.%m.%Y"))
    return

def date_arg():
    now = datetime.datetime.now()
    print(now.strftime("%I'%M %p %A %d.%m.%Y"))
    return


def ls_l(adr):
    '''
       #Funkcija "ls_l(adr)" služi korisniku kako bi njenim pozivom ispisao sadržaj
       trenutnog direktorija ili nekog specifičnog direktorija čiju adresu korisnik može
       svojevoljno unijeti u apsolutnom ili relativnom obliku. Bez obzira na duljinu
       unesene naredbe tj. sadrži li ona adresu, parametar "-l", ili ništa, funkcija uvijek
       prima jedan argument. Ako je unesena samo naredba "ls", funkcija se ne poziva nego se
       u glavnom dijelu programa poziva naredba "os.system()" koja kao argument prima naredbu
       "ls" te ju obrađuje na način kao što bi ju obradio i sam terminal. Ako je duljina liste
       unosa korisnika jednaka 2 tj. da se naredba sastoji od dvije riječi, druga se riječ testira
       je li ona adresa ili parametar "-l". Ako se ispostavi da je ona adresa onda se provjerava
       postoji li ta adresa. Ako ta adresa postoji onda se ona prosljeđuje u istu naredbu ("os.system()")
       koja izlistava sadržaj direktorija na zadanoj adresi. Ako naredba sadrži parametar "-l" onda
       se poziva funkcija "ls_l(adr)". Funkcija prima jedan argument a to može biti adresa direktorija
       u apsolutnom ili relativnom obliku. Zatim se koristi naredba "os.listdir()" koja vraća listu sa
       svim sadržajem određenog direktorija. Implementirao sam for petlju koja iterira kroz svaki element
       novonastale liste "a" te provjerava počinje li taj element znakom "."(točke).Ako poćinje točkom
       njega se ignorira te for petlja nastavlja dalje dok ne pronađe element koji ne počinje točkom.
       Kada se dogodi podudaranje sa uvjetom, ispisuju se podaci traženi u zadatku. Uz pomoć naredbe
       "os.stat()" koja kao argument prima adresu dobio sam listu sa traženim podacima(bilo je tu još
       dodatnih informacija koje nam u ovom slučaju nisu trebale). Adresu sam dobio na način da sam
       uz pomoć naredbe ".format()" i metode konkatenacije stringova spojio adresu koju je unio korisnik
       sa imenom datoteke koja se nalazi u tom direktoriju te sam tu novonastalu adresu proslijedio
       u naredbu "os.stat()". Ispisao sam samo tražene podatke koristeći indekse za odabir elemenata
       liste koju je izbacila ta naredba. Isti princip vrijedi i za dugi i detaljan ispis direktorija
       na nekoj određenoj adresi.
       '''
    a = os.listdir(adr)
    print("{}\t{}\t{}\t{}\t{}\t{}\t".format('Mode ', 'HL ', 'UID ', 'GID ', 'Size ', 'Name '))
    for i in range(len(a)):
        if (a[i].startswith('.') == False):
            print("{} \t{} \t{} \t{} \t{} \t{} \t".format(os.stat(adr + '/' + a[i])[0],
                                                  os.stat(adr + '/' + a[i])[3],
                                                  os.stat(adr + '/' + a[i])[4],
                                                  os.stat(adr + '/' + a[i])[5],
                                                  os.stat(adr + '/' + a[i])[6],
                                                  a[i]))
    return


def touch(a):
    '''
    #Funkcija touch koja prima apsolutnu adresu potrebnu za stvaranje datoteke
    U funkciji se prvotno provjerava da li datoteka vec postoji na unesenoj adresi, ako da
    ispise se prikladna poruka
    Ako datoteka ne postoji na unesenoj adresi onda se poziva funkcija Path().touch koja
    je importana iz pathlib-a koja na unesenoj adresi stvara datoteku
    '''
    if (os.path.exists(a)):
        print('Datoteka već postoji.')
    else:
        Path(a).touch()
    return


def rm(comm):
    '''
    #Funkcija"rm(a)" služi kako bi korisnik mogao ukloniti proizvoljnu datoteku
    sa neke određene adrese ili sa trenutnog radnog direktorija. Unos je namješten
    tako da se funkcija neće pozvati dok korisnik ne unese naziv naredbe (rm) i ime
    datoteke koju želi ukloniti ili adresu na kojoj se nalazi ta datoteka.
    U funkciju se prosljeđuje adresa koja se prvo testira je li postojeća. Ako je
    uvjet zadovoljen adresa se prosljeđuje u naredbu "os.remove()" koja prima adresu
    u apsolutnom ili relativnom obliku kao argument, te briše datoteku koja se nalazi
    na kraju putanje. U suprotnom, ako adresa tj. datoteka ne postoji korisniku se
    prikazuje odgovarajuća poruka.
    '''
    path = pathlib.Path(comm[1])
    if(len(comm) == 1):
        print('Naredba prima točno jedan argument.')
    elif(len(comm) == 2):
        if(os.path.exists(comm[1])):
            os.remove(comm[1])
            print('Datoteka uspješno uklonjena.')
        elif(os.path.exists(path.parent) == False):
            print('Nepostojeća adresa.')
        else:
            print('Datoteka ne postoji.')
    else:
        print('Naredba prima točno jedan argument')


def kub(n,m,z):
    lock.acquire()
    global broj
    #x = 33330330330320320320
    for i in range(n,m):
        y = pow(i,3)
        broj = broj - y
    var2=str(broj)
    if (z == 1):
        with open("{}/result.txt".format(home), "a") as datoteka:
            datoteka.write('\n\nRezultat {}. dretve: \n'.format(z))
            datoteka.write(var2)
    else:
        with open("{}/result.txt".format(home), "a") as datoteka:
            datoteka.write('\nRezultat {}. dretve: \n'.format(z))
            datoteka.write(var2)
    print ('Sa radom je završila {}. dretva.'.format(z))
    lock.release()
    return

def spavanje(n,m,z,q):
    lock.acquire()
    global broj
    time.sleep(z)
    # x = 33330330330320320320
    for i in range(n, m):
        y = pow(i, 3)
        broj = broj - y
    var2 = str(broj)
    with open("{}/result.txt".format(home), "a") as datoteka:
        datoteka.write('\nRezultat {}. dretve: \n'.format(q))
        datoteka.write(var2)
    print('Sa radom je završila {}. dretva.'.format(q))
    lock.release()
    return


def remoteshd():
    remoteConfig = configparser.ConfigParser()
    remoteConfig.read('remoteshd.conf')

    host = 'localhost'
    port = int(remoteConfig['DEFAULT']['port'])
    address = (host, port)

    print('Veza otvorena na {}:{}\n'.format(host, port))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(address)
    sock.listen(1)
    clisock, addr = sock.accept()

    # CITANJE DATOTEKE USERS-PASSWORD.CONF
    usersConfig = configparser.ConfigParser()
    usersConfig.read('users-passwords.conf')

    users = []

    for username in usersConfig['users-passwords']:
        password = usersConfig['users-passwords'][username]
        users.append((username, password))

    print('Registrirani korisnici:')
    print('{:<15}{}'.format('usr', 'pwd'))
    print('{:<15}{}'.format('---', '---'))
    for user in users:
        print('{:<15}{}'.format(user[0], user[1]))
    print('\n')

    # primanje korisnickog imena
    podaci = clisock.recv(1024)
    username_client = podaci.decode()
    print('Uneseni korisnik: ' + username_client)

    # primanje zaporke
    podaci = clisock.recv(1024)
    password_client = podaci.decode()
    print('Unesena zaporka: ' + password_client)

    # LOGIN PROVJERA
    login_success = False
    for user in users:
        hashed_password = crypt.crypt(password_client, user[1])
        userdata_client = (username_client, hashed_password)
        if user == userdata_client:
            login_success = True

    print('Uspješna prijava.' if login_success else 'Nepostojeći korisnik.', end='\n\n')

    if login_success == True:

        # slanje odgovora
        poslani_podaci = str(login_success).encode()
        clisock.send(poslani_podaci)

        # primanje simetricnog kljuca
        podaci = clisock.recv(1024)
        ciphertext = podaci

        print(podaci)

        # citanje privatnog kljuca
        config = configparser.ConfigParser()
        config.read('remoteshd.conf')
        private_key = bytes(config['DEFAULT']['key_prv'], encoding='utf-8')

        private_key = serialization.load_pem_private_key(
            private_key,
            password=b'1234'
        )

        symmetric_key_decrypted = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(symmetric_key_decrypted, end='\n\n')

        f = Fernet(symmetric_key_decrypted)

        is_running = True
        while (is_running):

            odziv = '(sh):' + ispisi_odziv()
            podaci = f.encrypt(odziv.encode())
            clisock.send(podaci)

            podaci = clisock.recv(1024)
            podaci_decrypted = f.decrypt(podaci)
            podaci_decoded = podaci_decrypted.decode()

            print(time.ctime())
            print('Primljena naredba: ' + podaci_decoded)
            print('Statusni kod: 0')

            naredba_primljena = podaci_decoded.split()
            rezultat = izvrsi(naredba_primljena)
            rezultat_str = str(rezultat)

            print('Izlaz naredbe:\n' + rezultat_str, end='\n')

            podaci = f.encrypt(rezultat_str.encode())
            clisock.send(podaci)

            if rezultat == False:
                is_running = False

    clisock.close()
    sock.close()
    return ''


# klijentska strana
def remotesh():
    host = 'localhost'
    port = 5000
    address = (host, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(address)

    print('Povezan na {}:{}\n'.format(host, port))

    # slanje korisnickog imena
    print('Korisnicko ime: ', end='')
    poruka = input()
    podaci = poruka.encode()
    sock.send(podaci)

    # slanje zaporke
    print('Zaporka: ', end='')
    poruka = input()
    podaci = poruka.encode()
    sock.send(podaci)

    # primanje zahvale
    primljeni_podaci = sock.recv(1024)
    login_success = bool(primljeni_podaci.decode())
    print('Uspješna prijava.' if login_success else 'Nepostojeći korisnik.', end='\n\n')

    if login_success == True:
        # generiranje simetricnog kljuca
        symmetric_key_client = Fernet.generate_key()
        f = Fernet(symmetric_key_client)
        print(symmetric_key_client)

        # citanje javnog kljuca
        config = configparser.ConfigParser()
        config.read('remoteshd.conf')
        public_key = bytes(config['DEFAULT']['key_pub'], encoding='utf-8')

        public_key = serialization.load_pem_public_key(
            public_key
            )
        print(public_key)

        # enkripcija javnim kljucem
        ciphertext = public_key.encrypt(
            symmetric_key_client,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(ciphertext, end='\n\n')

        # slanje simetricnog kljuca
        podaci = ciphertext
        sock.send(podaci)

        print('Pozdrav! ({})'.format(time.ctime()))

        is_running = True
        while (is_running):

            odziv_encrypted = sock.recv(1024)
            odziv = f.decrypt(odziv_encrypted)
            print(odziv.decode(), end='')

            naredba = input()
            podaci = f.encrypt(naredba.encode())
            sock.send(podaci)

            rezultat_encrypted = sock.recv(1024)
            rezultat_enkodiran = f.decrypt(rezultat_encrypted)
            rezultat = rezultat_enkodiran.decode()

            if rezultat == 'False':
                is_running = False
                rezultat = ''

            print(rezultat, end = '\n')

    # ssock.shutdown()
    sock.close()
    return ''



# zad 1
'''
#Isječak koda koji prikazuje pozdravnu poruku te trenutni datum i vrijeme 
uz pomoć modula time i naredbe "time.ctime()"
'''
print('Pozdrav korisniku!')
print('({})'.format(time.ctime()))

a = 0

home = str(Path.home())

# stvaranje datoteke povijest.txt
'''
#Isječak koda ispod ovog komentara prikazuje postupak stvaranja datoteke 
.povijest u kućnom direktoriju korisnika te njezino otvaranje i upisivanje
naslova i trenutnog datuma i vremena početka sesije.
'''
Path("{}/.povijest".format(home)).touch()
with open("{}/.povijest".format(home), "a") as datoteka:
    datoteka.write('Povijest unesenih naredbi  ({})\n\n'.format(time.ctime()))




#While petlja koja koja ce ispisivati prompt dok je unos razlicit od izlaz ili odjava
while (a != 'izlaz' or 'odjava'):
    #Odzivni znak
    print()
    #Linija koja ispisuje prompt na ekran
    #Naredba os.getlogin() pronalazi ime ulogiranog korisnika koji pokrece program
    #Naredba os.uname() ispisuje sve podatke o OS-u dok agrumnet [1] uzima samo
    #ime i ignorira sve druge informacije
    #Naredba os.getcwd() vraca trenutni direktorij u kojemu korisnik radi
    print('[{}@{}]{} $ '.format(os.getlogin(), """os.uname()[1]""", os.getcwd()), end='')

    a = input()
    #Petlja koja ispisuje prompt cak i nakon unosa, identicno svo kao i kod prvog
    #definiranja prompta
    while not a:
        print('[{}@{}]{} $ '.format(os.getlogin(), os.uname()[1], os.getcwd()), end='')
        a = input()

    # upisivanje korištenih naredbi u datoteku
    '''
       #Svaka naredba koja nije prazan unos tj. Enter se automatski dodaje u datoteku
       .povijest te umeće prekid retka "\n" kako bi sljedeća naredba bila u zasebnom retku
       '''
    with open("{}/.povijest".format(home), "a") as datoteka:
        datoteka.write(a)
        datoteka.write('\n')


    #if petlja koja provjerava je li korisnik unio izlaz ili odjava, ako je
    #program ce zavrsiti sa radom
    if (a == 'izlaz' or a == 'odjava'):
        break

    comm = a.split()

    # Naredba remoteshd
    if (comm[0] == "remoteshd"):
        remoteshd()

        # Naredba remotesh
        if (comm[0] == "remotesh"):
            remoteshd()

    #Naredba pwd
    if (comm[0] == "pwd"):
        if (len(comm) == 1):
            pwd()
        elif (len(comm) > 1):
            print('Naredba ne prima parametre ni argumente.')


    #Naredba ps
    #if petlja koja provjerava je li unos jednak ps
    elif (comm[0] == 'ps'):
        #Ako je duljina unos veca od 1, ako je to znaci da je korisnik unio parametar
        #ili argument sto ps ne prima te se ispisuje prikladna poruka
        if (len(comm) > 1):
            print('Nepostojeći parametar ili argument.')
        #Ako je duljina unosa jednaka 1 onda se poziva funkcija ps koja vraca PID
        #trenutnog proces
        elif (len(comm) == 1):
            #funkcija ps ne prima nikakve argumente
            ps()


    #Naredba echo
    #elif petlja provjerava da li je unesen echo
    elif (comm[0] == 'echo'):
        #varijabla b koja od duljine unosa oduzima 1, pomocu cega se moze dohvatiti
        #kraj unosa i provjeriti da li je unos omeden sa " ili '
        b = len(comm) - 1
        #Ako je duljina naredbe jednaka 1 to znaci je korisnik unio samo echo bez
        #argumenata te se ispisuje odgovarajuca poruka
        if (len(comm) == 1):
            print('Naredba prima barem jedan argument.')
        #elif petlja provjerava da li je unos omeden sa " znakovima te ako je
        #salje unos u funkciju echo_navodnik koja mice navodnike iz unosa te ispisuje
        #unos bez echo na pocetku
        elif comm[1].startswith("\"") and comm[b].endswith("\""):
            echo_navodnik(a)
        #elif petlja provjerava da li je unos omeden sa ' znakovima te ako je
        #salje unos u funkciju echo_navodnik koja mice navodnike iz unosa te ispisuje
        #unos bez echo na pocetku
        elif comm[1].startswith("\'") and comm[b].endswith("\'"):
            echo_navodnik(a)
        #Ako unos ne sadrzi bilo kakve navodnike poziva se funkcija koja ispisuje unos
        #od korisnika bez "echo" na pocetku
        else:
            echo(a)


    #Naredba KILL
    elif (comm[0] == 'kill'):
        if (len(comm) == 1):
            print('Naredba prima bar jedan argument.')
        elif (len(comm) == 2):
            if (comm[1] == '-2' or comm[1] == '-SIGINT' or comm[1] == '-INT'):
                dva = 2
                print('Pristigao je signal broj 2. Program se završava.')
                # kill(dva)
                sys.exit()
            elif (comm[1] == '-3' or comm[1] == '-SIGQUIT' or comm[1] == '-QUIT'):
                tri = 3
                signal.signal(signal.SIGQUIT, signal.SIG_IGN)
                print('Pristigao je signal broj 3. Signal je ignoriran.')
            elif (comm[1] == '-15' or comm[1] == '-SIGTERM' or comm[1] == '-TERM'):
                petnaest = 15
                print('Pristigao je signal broj 15. Program se završava.')
                kill(petnaest)
            else:
                print('Pogrešan parametar.')
        elif (len(comm) == 3):
            if (provjeri_pid(int(comm[2])) == False):
                print('Nepostojeći PID.')
            elif (comm[2] == '-2' or '-SIGINT'):
                dva = 2
                kill_pid(int(comm[2]), dva)
            elif (comm[2] == '-3' or '-SIGQUIT'):
                tri = 3
                kill_pid(int(comm[2]), tri)
            elif (comm[2] == '-15' or '-SIGTERM'):
                petnaest = 15
                kill_pid(int(comm[2]), petnaest)


    #Naredba cd
    elif (comm[0] == "cd"):
        if (len(comm) > 1):
            if (os.path.exists(comm[1]) == False):
                print('Nepostojeća adresa.')
            else:
                cd_arg(comm[1])
        else:
            cd_no_args(home)


    #Naredba date
    elif (comm[0] == "date"):
        if (len(comm) == 1):
            date_no_args()
        elif (len(comm) > 1):
            if (comm[1] != '-s'):
                print('Pogrešan parametar.')
            else:
                date_arg()


    #Naredba ls
    elif(comm[0] == 'ls'):
        if(len(comm) == 1):
            os.system(a)
        elif(len(comm) == 2):
            if(comm[1] == '-l'):
                ls_l(os.getcwd())
            elif(comm[1].startswith(('/', '.'))):
                if(os.path.exists(comm[1])):
                    os.system(a)
                else:
                    print('Nepostojeća adresa.')
            else:
                print('Unesen je krivi parametar.')
        elif(len(comm) == 3):
            if(comm[1] == '-l'):
                if(os.path.exists(comm[2])):
                    ls_l(comm[2])
                else:
                    print('Adresa ne postoji.')
            else:
                print('Unesen je krivi parametar')


    #Naredba touch
    #elif petlja prvo provjerava je li unos jednak touch
    #Zatim se provjerava duljina unosa
    #Ako je duljina unosa manja od 2 znaci da je korisnik unio samo touch bez argumenta
    #te se ispisuje prikladna poruka
    elif (comm[0] == 'touch'):
        if (len(comm) < 2):
            print('Naredba prima najmanje jedan argument.')
        #Ako je duljina unosa jednaka 2 poziva se funkcija touch koja prima samo drugi
        #element unosa odnosno samo adresu potrebnu za stvaranje datoteke te funkcija
        #stvori navedenu datoteku
        elif (len(comm) == 2):
            touch(comm[1])
        #Ako je duljina unosa jednaka 3 to znaci da je korisnik unio prvo ime
        #datoteke te zatim posebno adresu stvaranja te ih program razdvaja i formatira na
        #potreban nacin i salje u funkciju touch koja stvara datoteku
        elif (len(comm) == 3):
            #if petlja provjerava da li adresa vec postoji, ako da salje prikladnu poruku,
            #ako ne datoteka se stvori pomocu funkcije touch
            if (os.path.exists(comm[2])):
                touch('{}/{}'.format(comm[2], comm[1]))
            else:
                print('Nepostojeća adresa.')


    #Naredba rm
    elif (comm[0] == 'rm'):
        rm(comm)


    #Naredba kub
    elif (comm[0] == 'kub'):
        if (len(comm) > 1):
            print('Naredba ne prima argumente niti parametre.')
        elif (len(comm) == 1):
            broj = 33330330330320320320
            lock = threading.Lock()
            t1 = threading.Thread(target = kub, args = (1,33000,1))
            t2 = threading.Thread(target = spavanje, args = (33000,66000,3,2))
            t3 = threading.Thread(target = kub, args = (66000,99000,3))

            t1.start()
            t2.start()
            t3.start()

            t1.join()
            t2.join()
            t3.join()

            print ('Konačan iznos broja je: {}'.format(broj))


    # Pogrešan unos naredbe
    #else petlja izbacuje poruku kao ni jedna od prije navedenih naredbi
    #nije unesena
    else:
        print('Pogrešno unesena naredba.')