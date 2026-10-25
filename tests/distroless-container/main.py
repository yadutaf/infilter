#!/bin/python

import time

print("Ready")

try:
    while True:
        time.sleep(1000)
except KeyboardInterrupt:
    print("Exiting...")

print("Bye!")
