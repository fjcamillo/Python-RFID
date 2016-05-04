__author__ = 'Francisc'
import serial

ar = serial.Serial('COM1', 9600, timeout=.1)
while True:
    print(ar.readline())