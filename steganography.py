import numpy as np
import cv2
from tkinter import *
from PIL import Image, ImageTk
from tkinter import filedialog
from tkinter import messagebox
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
import base64


root = Tk()
root.title("Steganography - Hide a Secret Message in an Image")
root.geometry("700x500+150+180")
root.resizable(False, False)
root.configure(bg="#2f4155")


def showimage():
    global filename
    filename = filedialog.askopenfilename(initialdir=os.getcwd(),
                                          title="Select Image File",
                                          filetype=(("Images", "*.png *.jpg *.jpeg *.jfif"),
                                                    ("All file", ".txt")))
    img = Image.open(filename)
    img = img.resize((330, 350))  # Resize the image
    img = ImageTk.PhotoImage(img)

    lbl.configure(image=img, width=330, height=350, relief=SUNKEN)
    lbl.image = img


# Derive_key function from password
def derive_key(key_seed: str) -> bytes:
    kdf = Scrypt(
        salt=b'',
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    key = kdf.derive(key_seed.encode())
    return key


# Pretvaranje podataka u binarni string
# Za svaku vrstu podataka "data" (string, byte, niz, integer) funkcijom format() vrši se pretvorba svakog znaka u 8-bitni binarni oblik te se on povezuje s funkcijom join().
def to_binary(data):
    if isinstance(data, str):
        return ''.join([format(ord(i), "08b") for i in data])
    elif isinstance(data, bytes) or isinstance(data, np.ndarray):
        return [format(i, "08b") for i in data]
    elif isinstance(data, int) or isinstance(data, np.uint8):
        return format(data, "08b")
    else:
        raise TypeError(" This type of data is not supported!\n")


def save_encoded_image():
    encoded_image = encode_text()
    
    name = os.path.splitext(os.path.basename(filename))[0]

    cv2.imwrite("hidden_" + name + ".png", encoded_image)

    text1.delete("1.0", END)
    passw.delete("1.0", END)
    lbl.configure(image=None, relief="flat")
    lbl.image = None


def encode_text():
    # funkcija imread() sprema sliku u obliku matrice piksela u varijablu "image"
    image = cv2.imread(filename)

    # maksimalan broj bajtova koji se mogu enkodirati u sliku
    # broj bajtova se računa kao umnožak visine, širine, broja 3 (zbog RGB) te se dijeli s 8 (1 bajt = 8 bitova)
    max_bytes = image.shape[0] * image.shape[1] * 3 // 8
    print(" Max bytes to encode : ", max_bytes)

    # uzme poruku koju treba sakriti
    global secret
    secret = text1.get(1.0,END).encode()

    # provjerava je li duljina tajnih podataka veća od max broja bajtova.
    if len(secret) > max_bytes:
        raise ValueError(
            " Too much data for this image;\nUse BIGGER IMAGE or LESS DATA!\n")

    print(" Encoding data...")
    
    # uzme password koji sluzi za enkripciju/dekripciju te poruke
    global pas
    pas = passw.get(1.0,END)
    # print("password ", pas)

    # iz tog passworda dobije se ključ koji će služiti za enkripciju
    key = base64.b64encode(derive_key(pas))
    # print("key ", key)

    # Kreira instancu klase Fernet koristeci taj ključ (FERNET je simetrični kriptografski algoritam)
    fernet = Fernet(key)

    # inicijalizacija indeksa za tajne podatke
    data_index = 0
    
    encrypted_secret_data = fernet.encrypt(secret).decode()    #decode vraća u string
    encrypted_secret_data += "====="    # da zna gdje je kraj stringa (inace ce ispisat cilu matricu slike)

    # print("ENcrypted secret data: ", encrypted_secret_data)
    
    binary_secret = to_binary(encrypted_secret_data)   # pretvorba tajnih podataka u binarni oblik
    data_length = len(binary_secret)    # računanje duljine tajnih podataka koje ćemo sakriti


    for row in image:
        for pixel in row:
            # funkcija to_binary() pretvara vrijednosti r, g, b u binarni oblik
            r, g, b = to_binary(pixel)

            # zamjena LSB sve dok još ima tajnih podataka
            if data_index < data_length:
                # red piksel
                # zamjena LSB crvenog dijela piksela sa trenutnim bitom tajne
                # pretvorba u integer funkcijom int()
                pixel[0] = int(r[:-1] + binary_secret[data_index], 2)
                data_index += 1

            if data_index < data_length:
                # green piksel
                pixel[1] = int(g[:-1] + binary_secret[data_index], 2)
                data_index += 1

            if data_index < data_length:
                # blue piksel
                pixel[2] = int(b[:-1] + binary_secret[data_index], 2)
                data_index += 1

            # izlazak iz petlje ako je cijela tajna enkodirana
            if data_index >= data_length:
                break

    return image



def get_secret_message():
    pas = passw.get(1.0,END)
    # print("password ", pas)
    
    # iz tog passworda dobije se ključ koji će sluziti za dekripciju u ovom slučaju
    key = base64.b64encode(derive_key(pas))
    # print("key ",key)

    # Kreira instancu klase Fernet koristeci taj kljuc
    fernet = Fernet(key)

    decoded_data = decode_input()
    decoded_data += "=="    #dodajemo jer se kod decode() izgubi

    # print("decoded data: ", decoded_data)

    decrypted_data = fernet.decrypt(decoded_data.encode()).decode()
    text1.insert(END, decrypted_data)


# GET DECODED DATA
def decode_input():
    print(" Decoding secret data from image...")

    image = cv2.imread(filename)

    binary_result = ""
    decoded_data = ""

    for row in image:
        for pixel in row:
            r, g, b = to_binary(pixel)

            # dodajemo zadnji bit (znak) svakog od komponenti piksela
            binary_result += r[-1]
            binary_result += g[-1]
            binary_result += b[-1]

    # pretvaramo rezultat u bajtove
    # range(start, stop, step)
    bytes_result = [binary_result[i:i+8]
                    for i in range(0, len(binary_result), 8)]

    # izdvajamo znak iz svakog bajta koji smo dobili
    for byte in bytes_result:
        decoded_data += chr(int(byte, 2))

        # provjerava se je li zadnjih 5 znakova stringa jednako =====, ako je prekida se dekodiranje jer smo procitali sve tajne podatke
        if decoded_data[-5:] == "=====":
            break
    # vraćamo dekodirani podatak (bez zadnjih 5 znakova)
    return decoded_data[:-5]


# ADD FILE
def add_file():
    global textfile
    textfile = filedialog.askopenfilename(initialdir=os.getcwd(),
                                          title="Select text file",
                                          filetype=(("TXT file", ".txt"),
                                                    ("All file", ".txt")))

    with open(textfile, "rb") as text:
        secret = text.read()

    text1.insert(END, secret)



#########      GUI     ###############
######################################


# ikona u kantunu (ovo nije toliko bitno)
image_icon = PhotoImage(file="icon.png")
root.iconphoto(False, image_icon)

# logo
# subsample označava smanjenje slike na zeljenu velicinu
logo = PhotoImage(file="icon.png").subsample(1, 1)
Label(root, image=logo, bg="#2f4155").place(x=15, y=10)

Label(root, text="CYBER SCIENCE", bg="#2d4155",
      fg="white", font="arial 25 bold").place(x=100, y=20)


# First frame
f = Frame(root, bg="#2f4155", width=340, height=400, relief=GROOVE)
f.place(x=10, y=80)

f_ = Frame(f, bg="black", bd=1, width=330, height=350, relief=GROOVE)
f_.place(x=0, y=45)

lbl = Label(f_, bg="black")
lbl.place(x=0, y=0)
Button(f, text="Add Photo", width=8, height=1,
       font="arial 12 bold", command=showimage).place(x=3, y=5)


# Second frame
frame2 = Frame(root, width=340, height=290, bg="#2f4155", relief=GROOVE)
frame2.place(x=350, y=80)
Label(frame2, text="Add Plaintext or a File",
      bg="#2f4155", fg="yellow").place(x=3, y=5)

text1 = Text(frame2, font="Roboto 20", bg="white",
             fg="black", relief=GROOVE, wrap=WORD)
text1.place(x=0, y=30, width=325, height=150)

Button(frame2, text="Add File", width=7, height=1,
       font="airal 12 bold", command=add_file).place(x=3, y=190)

passw = Text(frame2, font="Roboto 12", bg="white",
             fg="black", relief=GROOVE, wrap=WORD)
passw.place(x=3, y=250, width=325, height=30)
Label(frame2, text="Password", bg="#2f4155", fg="yellow").place(x=3, y=230)

# Third Frame
frame3 = Frame(root, bg="#2f4155", width=330, height=100,relief=GROOVE)
frame3.place(x=360, y=370)

Button(frame3, text="Encode", width=10, height=2,
       font="airal 14 bold", command=save_encoded_image).place(x=20, y=30)
Button(frame3, text="Decode", width=10, height=2,
       font="airal 14 bold", command=get_secret_message).place(x=180, y=30)
Label(frame3, text="Picture, Image, Photo File",
      bg="#2f4155", fg="yellow").place(x=20, y=5)



root.mainloop()
