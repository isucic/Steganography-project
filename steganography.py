import numpy as np
import cv2
from tkinter import *
from PIL import Image, ImageTk
from tkinter import filedialog
from tkinter import messagebox
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Pretvaranje podataka u binarni string
# Za svaku vrstu podataka "data" (string, byte, niz, integer) funkcijom format() vrši se pretvorba svakog znaka u 8-bitni binarni oblik te se on povezuje s funkcijom join().


root = Tk()
root.title("Steganography - Hide a Secret Message in an Image")
root.geometry("700x500+150+180")
root.resizable(False, False)
root.configure(bg="#2f4155")


def showimage():
    global filename
    filename = filedialog.askopenfilename(initialdir=os.getcwd(),
                                          title="Select Image File",
                                          filetype=(("PNG file", "*.png"),
                                                    ("JPG file", "*.jpg"),
                                                    ("All file", ".txt")))
    img = Image.open(filename)
    img = ImageTk.PhotoImage(img)
    lbl.configure(image=img, width=250, height=250)
    lbl.image = img


def to_binary(data):
    if isinstance(data, str):
        return ''.join([format(ord(i), "08b") for i in data])
    elif isinstance(data, bytes) or isinstance(data, np.ndarray):
        return [format(i, "08b") for i in data]
    elif isinstance(data, int) or isinstance(data, np.uint8):
        return format(data, "08b")
    else:
        raise TypeError(" This type of data is not supported!\n")

# SAVE IMAGE


def save_image():
    encoded_image = encode_input()
    print(secret)
    name = os.path.splitext(os.path.basename(filename))[0]

    cv2.imwrite("hidden_" + name + ".png", encoded_image)

# HIDE DATA


def encode_input():
    global secret
    secret = text1.get(1.0, END)
    name = filename
    # funkcija imread() sprema sliku u obliku matrice piksela u varijablu "image"
    image = cv2.imread(name)

    # maksimalan broj bajtova koji se mogu enkodirati u sliku
    # broj bajtova se računa kao umnožak visine, širine, broja 3 (zbog RGB) te se dijeli s 8 (1 bajt = 8 bitova)
    max_bytes = image.shape[0] * image.shape[1] * 3 // 8
    print(" Max bytes to encode : ", max_bytes)

    # provjerava je li duljina tajnih podataka veća od max broja bajtova.
    if len(secret) > max_bytes:
        raise ValueError(
            " Too much data for this image;\nUse BIGGER IMAGE or LESS DATA!\n")

    print(" Encoding data...")

    # dodaje oznaku kraja podataka na "secret"
    secret += "====="

    # inicijalizacija indeksa za tajne podatke
    data_index = 0

    # pretvorba tajnih podataka u binarni oblik
    binary_secret = to_binary(secret)
    # računanje duljine tajnih podataka koje ćemo sakriti
    data_length = len(binary_secret)

    # prolazi se kroz sve piksele slike
    for row in image:
        for pixel in row:
            # funkcija to_binary() pretvara vrijednosti r, g, b u binarni oblik
            r, g, b = to_binary(pixel)

            # zamjena LSB ako još ima tajnih podataka
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


def get_f_key():
    messagebox.showinfo("pop-up", "hello world")

# SHOW DATA


def show_decoded():
    # get_f_key()
    decoded_data = decode_input()
    # print("Decoded data: ", decoded_data)
    text1.insert(END, decoded_data)

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

        # provjera jel od 5og elementa odzada do kraja ovaj string
        # i ako je, prestajemo s dekodiranjem
        if decoded_data[-5:] == "=====":
            break
    # vraćamo sve od početka do 5og elementa odzada
    return decoded_data[:-5]


# ikona u kantunu (ovo nije toliko bitno)
image_icon = PhotoImage(file="icon.png")
root.iconphoto(False, image_icon)


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


# logo
# subsample označava smanjenje slike na zeljenu velicinu
logo = PhotoImage(file="icon.png").subsample(1, 1)
Label(root, image=logo, bg="#2f4155").place(x=15, y=10)

Label(root, text="CYBER SCIENCE", bg="#2d4155",
      fg="white", font="arial 25 bold").place(x=100, y=20)


# First frame
f = Frame(root, bd=3, bg="black", width=340, height=280, relief=GROOVE)
f.place(x=10, y=80)

lbl = Label(f, bg="black")
lbl.place(x=40, y=10)


# Second frame
frame2 = Frame(root, bd=3, width=340, height=280, bg="white", relief=GROOVE)
frame2.place(x=350, y=80)

Label(frame2, text="Add text").place(x=350, y=80)
text1 = Text(frame2, font="Roboto 20", bg="white",
             fg="black", relief=GROOVE, wrap=WORD)
text1.place(x=0, y=0, width=320, height=295)


scrollbar1 = Scrollbar(frame2)
scrollbar1.place(x=320, y=0, height=300)

scrollbar1.configure(command=text1.yview)
text1.configure(yscrollcommand=scrollbar1.set)


# Third frame
frame3 = Frame(root, bd=3, bg="#2f4155", width=330, height=100, relief=GROOVE)
frame3.place(x=10, y=370)

Button(frame3, text="Open Image", width=10, height=2,
       font="airal 14 bold", command=showimage).place(x=20, y=30)
Button(frame3, text="Encode Image", width=10, height=2,
       font="airal 14 bold", command=save_image).place(x=180, y=30)
Label(frame3, text="Picture, Image, Photo File",
      bg="#2f4155", fg="yellow").place(x=20, y=5)


# Fourth frame
frame4 = Frame(root, bd=3, bg="#2f4155", width=330, height=100, relief=GROOVE)
frame4.place(x=360, y=370)

Button(frame4, text="Add File", width=10, height=2,
       font="airal 14 bold", command=add_file).place(x=20, y=30)
Button(frame4, text="Decode", width=10, height=2,
       font="airal 14 bold", command=show_decoded).place(x=180, y=30)
Label(frame4, text="Picture, Image, Photo File",
      bg="#2f4155", fg="yellow").place(x=20, y=5)


root.mainloop()
