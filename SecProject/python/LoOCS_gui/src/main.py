import tkinter as tk
from subprocess import call

root = tk.Tk()


def myClick():
    myLabel = tk.Label(root, text="I clicked the fucking button")
    myLabel.grid(row=1, column=1)


myButton = tk.Button(root, text="Click Me!", command=myClick)

# Creating a Label Widget
myLabel1 = tk.Label(root, text="Hello World!")
myLabel2 = tk.Label(root, text="My name is AAAA")
# Shoving it onto the screen
myLabel1.grid(row=0, column=1)
myLabel2.grid(row=1, column=0)
myButton.grid(row=0, column=0)

root.mainloop()
