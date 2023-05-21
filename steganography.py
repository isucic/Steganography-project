import numpy as np
import cv2

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


def encode(name, secret):

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